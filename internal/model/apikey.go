package model

import "time"

// APIKey 机器账号接入凭证，用于系统集成场景
type APIKey struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	KeyHash     string     `json:"-"`
	KeyPrefix   string     `json:"key_prefix"`
	OwnerID     int64      `json:"owner_id"`
	Scopes      []string   `json:"scopes"`
	IsActive    bool       `json:"is_active"`
	ExpiresAt   *time.Time `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// IsExpired 判断密钥是否已过期，无过期时间的密钥永久有效
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// CreateAPIKeyRequest 创建密钥请求体
type CreateAPIKeyRequest struct {
	Name      string    `json:"name" binding:"required,max=128"`
	Scopes    []string  `json:"scopes" binding:"required,min=1"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// CreateAPIKeyResponse 创建密钥响应，原始密钥仅在创建时返回一次
type CreateAPIKeyResponse struct {
	APIKey   *APIKey `json:"api_key"`
	RawKey   string  `json:"raw_key"`
}
