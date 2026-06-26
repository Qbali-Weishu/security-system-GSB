package model

import "time"

// 用户账号状态
const (
	UserStatusEnabled  = 1
	UserStatusDisabled = 0
	UserStatusLocked   = 2
)

// User 用户实体，包含账号锁定和登录尝试次数的完整状态
type User struct {
	ID               int64      `json:"id"`
	Username         string     `json:"username"`
	PasswordHash     string     `json:"-"`
	Email            string     `json:"email"`
	RoleID           int64      `json:"role_id"`
	Status           int        `json:"status"`
	IsProbation      bool       `json:"is_probation"`
	FailedLoginCount int        `json:"-"`
	LockedUntil      *time.Time `json:"-"`
	LastLoginAt      *time.Time `json:"last_login_at"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// IsLocked 判断账号当前是否处于锁定状态
func (u *User) IsLocked() bool {
	if u.Status == UserStatusLocked && u.LockedUntil != nil {
		return time.Now().Before(*u.LockedUntil)
	}
	return false
}

// LoginRequest 登录请求体
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// ChangePasswordRequest 修改密码请求体
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=10"`
}

// CreateUserRequest 创建用户请求体
type CreateUserRequest struct {
	Username string `json:"username" binding:"required,min=3,max=64,alphanum"`
	Password string `json:"password" binding:"required,min=10"`
	Email    string `json:"email" binding:"required,email"`
	RoleID   int64  `json:"role_id" binding:"required"`
}

// UpdateUserRequest 更新用户信息请求体
type UpdateUserRequest struct {
	Email  string `json:"email" binding:"omitempty,email"`
	RoleID int64  `json:"role_id"`
	Status int    `json:"status" binding:"omitempty,min=0,max=2"`
}
