package model

import "time"

// Session 用户会话，存储刷新令牌及其关联的设备信息
type Session struct {
	ID           int64      `json:"id"`
	UserID       int64      `json:"user_id"`
	RefreshToken string     `json:"-"`
	UserAgent    string     `json:"user_agent"`
	IPAddress    string     `json:"ip_address"`
	IsRevoked    bool       `json:"is_revoked"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

// IsExpired 判断会话是否已超过有效期
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsValid 判断会话是否同时满足未吊销且未过期两个条件
func (s *Session) IsValid() bool {
	return !s.IsRevoked && !s.IsExpired()
}

// TokenPair 包含访问令牌和刷新令牌的响应结构
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// RefreshRequest 刷新令牌请求体
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}
