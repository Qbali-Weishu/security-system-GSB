package handler

import (
	"net/http"
	"security-platform/internal/middleware"
	"security-platform/internal/model"
	"security-platform/internal/repository"
	"security-platform/internal/service"
	"strconv"

	"github.com/gin-gonic/gin"
)

type AlertHandler struct {
	alertSvc *service.AlertService
	userRepo *repository.UserRepository
	rbacSvc  *service.RBACService
	auditSvc *service.AuditService
}

func NewAlertHandler(
	alertSvc *service.AlertService,
	userRepo *repository.UserRepository,
	rbacSvc *service.RBACService,
	auditSvc *service.AuditService,
) *AlertHandler {
	return &AlertHandler{alertSvc: alertSvc, userRepo: userRepo, rbacSvc: rbacSvc, auditSvc: auditSvc}
}

// List 查询告警列表
// viewer和analyst只能看到自己创建或被指派的告警，security_officer及以上可以看全部
// SLA已违规且还未处置的告警在行级过滤后仍需标注，不能因过滤而丢失该标记
func (h *AlertHandler) List(c *gin.Context) {
	callerID := c.GetInt64(middleware.CtxUserID)
	roleID := c.GetInt64(middleware.CtxRoleID)

	if !h.rbacSvc.HasPermission(roleID, callerID, model.PermAlertRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权查看告警"})
		return
	}

	var q model.AlertQueryParams
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	alerts, total, err := h.alertSvc.List(&q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}

	// viewer和analyst执行行级过滤：只保留自己参与的告警
	// security_officer及以上不受此限制
	callerRank := h.rbacSvc.RoleRank(roleID)
	officerRole, _ := h.rbacSvc.GetRoleByName("security_officer")
	officerRank := 0
	if officerRole != nil {
		officerRank = h.rbacSvc.RoleRank(officerRole.ID)
	}

	if callerRank < officerRank {
		filtered := make([]*model.SecurityAlert, 0, len(alerts))
		for _, a := range alerts {
			if a.CreatorID == callerID || (a.AssigneeID != nil && *a.AssigneeID == callerID) {
				filtered = append(filtered, a)
			}
		}
		alerts = filtered
		total = len(filtered)
	}

	c.JSON(http.StatusOK, gin.H{"total": total, "data": alerts})
}

// Get 查询告警详情
// 所有持有alert:read权限的角色均可访问，包括对行级过滤后不可见的告警ID直接访问
// 低级角色通过ID直接访问非自身相关告警时应返回404而非403，避免探测信息泄露
func (h *AlertHandler) Get(c *gin.Context) {
	callerID := c.GetInt64(middleware.CtxUserID)
	roleID := c.GetInt64(middleware.CtxRoleID)

	if !h.rbacSvc.HasPermission(roleID, callerID, model.PermAlertRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权查看告警"})
		return
	}

	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "告警ID格式错误"})
		return
	}

	alert, err := h.alertSvc.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "告警不存在"})
		return
	}

	// 低级角色只能查看自己参与的告警，否则按不存在处理
	callerRank := h.rbacSvc.RoleRank(roleID)
	officerRole, _ := h.rbacSvc.GetRoleByName("security_officer")
	officerRank := 0
	if officerRole != nil {
		officerRank = h.rbacSvc.RoleRank(officerRole.ID)
	}
	if callerRank < officerRank {
		isCreator := alert.CreatorID == callerID
		isAssignee := alert.AssigneeID != nil && *alert.AssigneeID == callerID
		if !isCreator && !isAssignee {
			c.JSON(http.StatusNotFound, gin.H{"error": "告警不存在"})
			return
		}
	}

	comments, _ := h.alertSvc.ListComments(id)
	c.JSON(http.StatusOK, gin.H{"alert": alert, "comments": comments})
}

// Create 创建告警
// 持有alert:write权限的角色可创建，但试用期账号不能创建严重度为高危或严重的告警
func (h *AlertHandler) Create(c *gin.Context) {
	callerID := c.GetInt64(middleware.CtxUserID)
	roleID := c.GetInt64(middleware.CtxRoleID)

	if !h.rbacSvc.HasPermission(roleID, callerID, model.PermAlertWrite) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权创建告警"})
		return
	}

	var req model.CreateAlertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	caller, err := h.userRepo.FindByID(callerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户信息失败"})
		return
	}
	if caller.IsProbation && req.Severity >= model.SeverityHigh {
		c.JSON(http.StatusForbidden, gin.H{"error": "试用期账号不能创建高危及以上等级的告警"})
		return
	}

	alert, err := h.alertSvc.Create(&req, callerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建失败"})
		return
	}
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID: callerID, Username: caller.Username,
		Action: "create_alert", Resource: "alert",
		ResourceID: strconv.FormatInt(alert.ID, 10),
		Detail:     alert.Title, IPAddress: c.ClientIP(),
		Result: model.AuditResultSuccess,
	})
	c.JSON(http.StatusCreated, alert)
}

// Update 更新告警
// 持有alert:write权限可修改，但已关闭告警仅admin可修改
// 试用期账号不能将告警严重度升级
// 状态流转合法性由service层校验
func (h *AlertHandler) Update(c *gin.Context) {
	callerID := c.GetInt64(middleware.CtxUserID)
	roleID := c.GetInt64(middleware.CtxRoleID)

	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "告警ID格式错误"})
		return
	}

	alert, err := h.alertSvc.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "告警不存在"})
		return
	}

	// 已关闭的告警只有admin才能修改
	if alert.Status == model.AlertStatusClosed {
		if !h.rbacSvc.HasPermission(roleID, callerID, model.PermAlertDelete) {
			c.JSON(http.StatusForbidden, gin.H{"error": "已关闭告警无权修改"})
			return
		}
	} else if !h.rbacSvc.HasPermission(roleID, callerID, model.PermAlertWrite) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权修改告警"})
		return
	}

	var req model.UpdateAlertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 试用期账号不允许将告警严重度升级
	if req.Severity > alert.Severity {
		caller, err := h.userRepo.FindByID(callerID)
		if err == nil && caller.IsProbation {
			c.JSON(http.StatusForbidden, gin.H{"error": "试用期账号不能升级告警严重度"})
			return
		}
	}

	if err := h.alertSvc.Update(id, &req, callerID); err != nil {
		switch err {
		case service.ErrAlreadyClosed:
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		case service.ErrInvalidTransition:
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		}
		return
	}
	username := c.GetString(middleware.CtxUsername)
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID: callerID, Username: username,
		Action: "update_alert", Resource: "alert",
		ResourceID: strconv.FormatInt(id, 10),
		IPAddress:  c.ClientIP(), Result: model.AuditResultSuccess,
	})
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// Assign 指派告警处置人
// 需要alert:assign权限，且不能将高危及以上告警指派给试用期账号
func (h *AlertHandler) Assign(c *gin.Context) {
	callerID := c.GetInt64(middleware.CtxUserID)
	roleID := c.GetInt64(middleware.CtxRoleID)

	if !h.rbacSvc.HasPermission(roleID, callerID, model.PermAlertAssign) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权指派告警"})
		return
	}

	alertID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "告警ID格式错误"})
		return
	}

	var body struct {
		AssigneeID int64 `json:"assignee_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	alert, err := h.alertSvc.GetByID(alertID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "告警不存在"})
		return
	}

	// 高危及以上告警不能指派给试用期账号
	if alert.Severity >= model.SeverityHigh {
		assignee, err := h.userRepo.FindByID(body.AssigneeID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "被指派用户不存在"})
			return
		}
		if assignee.IsProbation {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "高危及以上告警不能指派给试用期账号"})
			return
		}
	}

	if err := h.alertSvc.Assign(alertID, body.AssigneeID, callerID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	username := c.GetString(middleware.CtxUsername)
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID: callerID, Username: username,
		Action: "assign_alert", Resource: "alert",
		ResourceID: strconv.FormatInt(alertID, 10),
		Detail:     strconv.FormatInt(body.AssigneeID, 10),
		IPAddress:  c.ClientIP(), Result: model.AuditResultSuccess,
	})
	c.JSON(http.StatusOK, gin.H{"message": "分配成功"})
}

// AddComment 为告警添加处置记录
// 需要alert:read权限（不是write），且调用方必须是该告警的创建人、当前指派人，
// 或持有security_officer及以上角色
func (h *AlertHandler) AddComment(c *gin.Context) {
	callerID := c.GetInt64(middleware.CtxUserID)
	roleID := c.GetInt64(middleware.CtxRoleID)

	if !h.rbacSvc.HasPermission(roleID, callerID, model.PermAlertRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权评论"})
		return
	}

	alertID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "告警ID格式错误"})
		return
	}

	alert, err := h.alertSvc.GetByID(alertID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "告警不存在"})
		return
	}

	// 低级角色必须是创建人或指派人才能评论
	callerRank := h.rbacSvc.RoleRank(roleID)
	officerRole, _ := h.rbacSvc.GetRoleByName("security_officer")
	officerRank := 0
	if officerRole != nil {
		officerRank = h.rbacSvc.RoleRank(officerRole.ID)
	}
	if callerRank < officerRank {
		isCreator := alert.CreatorID == callerID
		isAssignee := alert.AssigneeID != nil && *alert.AssigneeID == callerID
		if !isCreator && !isAssignee {
			c.JSON(http.StatusForbidden, gin.H{"error": "只有告警创建人或当前指派人才能评论"})
			return
		}
	}

	var req model.AddCommentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	comment, err := h.alertSvc.AddComment(alertID, callerID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, comment)
}
