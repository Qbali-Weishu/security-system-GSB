package model

import "time"

// AuditLog 审计日志实体，使用哈希链保证记录完整性
// 每条记录包含前一条记录的哈希值，任何篡改都会导致链条断裂
type AuditLog struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	ResourceID string   `json:"resource_id"`
	Detail    string    `json:"detail"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Result    string    `json:"result"`
	PrevHash  string    `json:"-"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
}

// 审计结果常量
const (
	AuditResultSuccess = "success"
	AuditResultFailure = "failure"
	AuditResultDenied  = "denied"
)

// AuditLogEntry 用于向审计服务提交日志的轻量入参
type AuditLogEntry struct {
	UserID     int64
	Username   string
	Action     string
	Resource   string
	ResourceID string
	Detail     string
	IPAddress  string
	UserAgent  string
	Result     string
}

// AuditQueryParams 审计日志查询参数
type AuditQueryParams struct {
	UserID   int64  `form:"user_id"`
	Action   string `form:"action"`
	Resource string `form:"resource"`
	Result   string `form:"result"`
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
}
