package model

import "time"

// 告警严重等级常量
const (
	SeverityInfo     = 1
	SeverityLow      = 2
	SeverityMedium   = 3
	SeverityHigh     = 4
	SeverityCritical = 5
)

// 告警生命周期状态常量
const (
	AlertStatusNew        = 1
	AlertStatusAssigned   = 2
	AlertStatusProcessing = 3
	AlertStatusResolved   = 4
	AlertStatusClosed     = 5
	AlertStatusEscalated  = 6
)

// SLADuration 各严重等级对应的处置时限，单位小时
var SLADuration = map[int]int{
	SeverityInfo:     168,
	SeverityLow:      72,
	SeverityMedium:   24,
	SeverityHigh:     8,
	SeverityCritical: 2,
}

// SecurityAlert 安全告警实体，包含完整的生命周期跟踪字段
type SecurityAlert struct {
	ID              int64      `json:"id"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Source          string     `json:"source"`
	Severity        int        `json:"severity"`
	Status          int        `json:"status"`
	AssigneeID      *int64     `json:"assignee_id"`
	CreatorID       int64      `json:"creator_id"`
	SLADeadline     time.Time  `json:"sla_deadline"`
	SLABreached     bool       `json:"sla_breached"`
	EscalationCount int        `json:"escalation_count"`
	ResolvedAt      *time.Time `json:"resolved_at"`
	ClosedAt        *time.Time `json:"closed_at"`
	Tags            []string   `json:"tags"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// AlertComment 告警处置记录
type AlertComment struct {
	ID        int64     `json:"id"`
	AlertID   int64     `json:"alert_id"`
	AuthorID  int64     `json:"author_id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateAlertRequest 创建告警请求体
type CreateAlertRequest struct {
	Title       string   `json:"title" binding:"required,max=256"`
	Description string   `json:"description" binding:"required"`
	Source      string   `json:"source" binding:"required,max=128"`
	Severity    int      `json:"severity" binding:"required,min=1,max=5"`
	Tags        []string `json:"tags"`
}

// UpdateAlertRequest 更新告警请求体，所有字段均为可选
type UpdateAlertRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    int      `json:"severity" binding:"omitempty,min=1,max=5"`
	Status      int      `json:"status" binding:"omitempty,min=1,max=6"`
	AssigneeID  *int64   `json:"assignee_id"`
	Tags        []string `json:"tags"`
}

// AddCommentRequest 添加处置记录请求体
type AddCommentRequest struct {
	Content string `json:"content" binding:"required,min=10"`
}

// AlertQueryParams 告警列表查询参数
type AlertQueryParams struct {
	Severity   int    `form:"severity"`
	Status     int    `form:"status"`
	AssigneeID int64  `form:"assignee_id"`
	Source     string `form:"source"`
	SLABreached *bool `form:"sla_breached"`
	Page       int    `form:"page"`
	PageSize   int    `form:"page_size"`
}
