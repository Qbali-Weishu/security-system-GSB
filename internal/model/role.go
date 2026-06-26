package model

import "time"

// Role 角色实体，支持通过父角色ID实现继承关系
type Role struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	ParentID    *int64    `json:"parent_id"`
	CreatedAt   time.Time `json:"created_at"`
}

// Permission 权限实体，采用资源加动作的二段式命名
type Permission struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// RolePermission 角色与权限的关联关系
type RolePermission struct {
	RoleID       int64 `json:"role_id"`
	PermissionID int64 `json:"permission_id"`
}

// CreateRoleRequest 创建角色请求体
type CreateRoleRequest struct {
	Name        string `json:"name" binding:"required,min=2,max=64"`
	DisplayName string `json:"display_name" binding:"required"`
	ParentID    *int64 `json:"parent_id"`
}

// UpdateRolePermissionsRequest 更新角色权限请求体
type UpdateRolePermissionsRequest struct {
	PermissionIDs []int64 `json:"permission_ids" binding:"required"`
}

// 系统内置权限常量，以资源名称加动作命名
const (
	PermAlertRead    = "alert:read"
	PermAlertWrite   = "alert:write"
	PermAlertDelete  = "alert:delete"
	PermAlertAssign  = "alert:assign"
	PermUserRead     = "user:read"
	PermUserWrite    = "user:write"
	PermUserDelete   = "user:delete"
	PermRoleRead     = "role:read"
	PermRoleWrite    = "role:write"
	PermConfigRead   = "config:read"
	PermConfigWrite  = "config:write"
	PermAuditRead    = "audit:read"
	PermApikeyManage = "apikey:manage"
	PermReportRead   = "report:read"
	PermReportWrite  = "report:write"
)
