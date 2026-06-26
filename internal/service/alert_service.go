package service

import (
	"errors"
	"fmt"
	"security-platform/internal/model"
	"security-platform/internal/repository"
	"time"
)

var (
	ErrAlertNotFound    = errors.New("告警不存在")
	ErrInvalidTransition = errors.New("告警状态流转不合法")
	ErrAlreadyClosed    = errors.New("告警已关闭，不允许修改")
)

// 合法的状态流转表，key为当前状态，value为允许转入的目标状态集合
var validTransitions = map[int][]int{
	model.AlertStatusNew:        {model.AlertStatusAssigned, model.AlertStatusClosed},
	model.AlertStatusAssigned:   {model.AlertStatusProcessing, model.AlertStatusClosed},
	model.AlertStatusProcessing: {model.AlertStatusResolved, model.AlertStatusEscalated, model.AlertStatusClosed},
	model.AlertStatusResolved:   {model.AlertStatusClosed, model.AlertStatusProcessing},
	model.AlertStatusEscalated:  {model.AlertStatusAssigned, model.AlertStatusClosed},
	model.AlertStatusClosed:     {},
}

type AlertService struct {
	alertRepo *repository.AlertRepository
	userRepo  *repository.UserRepository
	auditSvc  *AuditService
}

func NewAlertService(
	alertRepo *repository.AlertRepository,
	userRepo *repository.UserRepository,
	auditSvc *AuditService,
) *AlertService {
	return &AlertService{alertRepo: alertRepo, userRepo: userRepo, auditSvc: auditSvc}
}

// Create 创建新告警，自动计算SLA截止时间
func (s *AlertService) Create(req *model.CreateAlertRequest, creatorID int64) (*model.SecurityAlert, error) {
	slaDuration, ok := model.SLADuration[req.Severity]
	if !ok {
		slaDuration = 72
	}
	alert := &model.SecurityAlert{
		Title:       req.Title,
		Description: req.Description,
		Source:      req.Source,
		Severity:    req.Severity,
		Status:      model.AlertStatusNew,
		CreatorID:   creatorID,
		SLADeadline: time.Now().Add(time.Duration(slaDuration) * time.Hour),
		Tags:        req.Tags,
	}
	if err := s.alertRepo.Create(alert); err != nil {
		return nil, err
	}
	return alert, nil
}

// GetByID 获取告警详情
func (s *AlertService) GetByID(id int64) (*model.SecurityAlert, error) {
	return s.alertRepo.FindByID(id)
}

// List 查询告警列表
func (s *AlertService) List(q *model.AlertQueryParams) ([]*model.SecurityAlert, int, error) {
	return s.alertRepo.List(q)
}

// Update 更新告警信息，包含状态流转合法性校验
func (s *AlertService) Update(id int64, req *model.UpdateAlertRequest, operatorID int64) error {
	alert, err := s.alertRepo.FindByID(id)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrAlertNotFound
	}
	if err != nil {
		return err
	}
	if alert.Status == model.AlertStatusClosed {
		return ErrAlreadyClosed
	}

	// 校验目标状态是否在合法流转范围内
	if req.Status > 0 && req.Status != alert.Status {
		allowed := validTransitions[alert.Status]
		valid := false
		for _, s := range allowed {
			if s == req.Status {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("%w: 从 %d 到 %d", ErrInvalidTransition, alert.Status, req.Status)
		}
	}

	// 应用字段更新
	if req.Title != "" {
		alert.Title = req.Title
	}
	if req.Description != "" {
		alert.Description = req.Description
	}
	if req.Severity > 0 && req.Severity != alert.Severity {
		// 严重等级升高时重新计算SLA截止时间
		if req.Severity > alert.Severity {
			slaDuration := model.SLADuration[req.Severity]
			alert.SLADeadline = time.Now().Add(time.Duration(slaDuration) * time.Hour)
			alert.SLABreached = false
		}
		alert.Severity = req.Severity
	}
	if req.AssigneeID != nil {
		if err := s.validateAssignee(*req.AssigneeID); err != nil {
			return err
		}
		alert.AssigneeID = req.AssigneeID
		if alert.Status == model.AlertStatusNew {
			alert.Status = model.AlertStatusAssigned
		}
	}
	if req.Status > 0 {
		alert.Status = req.Status
		now := time.Now()
		if req.Status == model.AlertStatusResolved {
			alert.ResolvedAt = &now
		}
		if req.Status == model.AlertStatusClosed {
			alert.ClosedAt = &now
		}
	}

	return s.alertRepo.Update(id, alert)
}

// Assign 将告警分配给指定分析师
func (s *AlertService) Assign(alertID, assigneeID, operatorID int64) error {
	alert, err := s.alertRepo.FindByID(alertID)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrAlertNotFound
	}
	if err != nil {
		return err
	}
	if alert.Status == model.AlertStatusClosed {
		return ErrAlreadyClosed
	}
	if err := s.validateAssignee(assigneeID); err != nil {
		return err
	}
	alert.AssigneeID = &assigneeID
	alert.Status = model.AlertStatusAssigned
	return s.alertRepo.Update(alertID, alert)
}

// AddComment 为告警添加处置记录
func (s *AlertService) AddComment(alertID, authorID int64, req *model.AddCommentRequest) (*model.AlertComment, error) {
	if _, err := s.alertRepo.FindByID(alertID); err != nil {
		return nil, ErrAlertNotFound
	}
	comment := &model.AlertComment{
		AlertID:  alertID,
		AuthorID: authorID,
		Content:  req.Content,
	}
	if err := s.alertRepo.AddComment(comment); err != nil {
		return nil, err
	}
	return comment, nil
}

// ListComments 获取告警的全部处置记录
func (s *AlertService) ListComments(alertID int64) ([]*model.AlertComment, error) {
	return s.alertRepo.ListComments(alertID)
}

// RunSLACheck 检查所有超时告警并执行自动上报升级流程
// 此方法应由定时任务周期性调用
func (s *AlertService) RunSLACheck() error {
	breached, err := s.alertRepo.CheckAndMarkSLABreaches()
	if err != nil {
		return fmt.Errorf("SLA违规标记失败: %w", err)
	}

	if breached == 0 {
		return nil
	}

	// 查询需要执行上报操作的告警
	targets, err := s.alertRepo.FindSLABreachedUnnotified()
	if err != nil {
		return fmt.Errorf("查询待上报告警失败: %w", err)
	}

	for _, alert := range targets {
		s.escalate(alert)
	}
	return nil
}

// escalate 对SLA违规的告警执行上报处理：提升严重等级并记录升级次数
func (s *AlertService) escalate(alert *model.SecurityAlert) {
	alert.EscalationCount++

	// 严重等级未到顶时自动上调一级
	if alert.Severity < model.SeverityCritical {
		alert.Severity++
		// 按新等级重新计算SLA截止时间
		slaDuration := model.SLADuration[alert.Severity]
		alert.SLADeadline = time.Now().Add(time.Duration(slaDuration) * time.Hour)
		alert.SLABreached = false
	}

	// 连续上报超过3次且仍无人处理时，将状态切换为已上报
	if alert.EscalationCount >= 3 && alert.AssigneeID == nil {
		alert.Status = model.AlertStatusEscalated
	}

	_ = s.alertRepo.Update(alert.ID, alert)

	// 向审计服务提交上报操作记录
	s.auditSvc.Log(&model.AuditLogEntry{
		UserID:     0,
		Username:   "system",
		Action:     "escalate_alert",
		Resource:   "alert",
		ResourceID: fmt.Sprintf("%d", alert.ID),
		Detail:     fmt.Sprintf("SLA违规，第%d次上报，严重等级调整为%d", alert.EscalationCount, alert.Severity),
		Result:     model.AuditResultSuccess,
	})
}

// validateAssignee 验证被指派人是否为有效的活跃用户
func (s *AlertService) validateAssignee(userID int64) error {
	user, err := s.userRepo.FindByID(userID)
	if errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("被指派用户不存在: %d", userID)
	}
	if err != nil {
		return err
	}
	if user.Status != model.UserStatusEnabled {
		return fmt.Errorf("被指派用户已被禁用: %s", user.Username)
	}
	return nil
}
