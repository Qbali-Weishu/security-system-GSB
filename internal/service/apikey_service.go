package service

import (
	"errors"
	"security-platform/internal/model"
	"security-platform/internal/repository"
	"security-platform/pkg/crypto"
)

var ErrAPIKeyNotFound = errors.New("密钥不存在或无权操作")

// 系统支持的密钥访问范围
var validScopes = map[string]bool{
	"alert:read":  true,
	"alert:write": true,
	"report:read": true,
	"audit:read":  true,
}

type APIKeyService struct {
	repo *repository.APIKeyRepository
}

func NewAPIKeyService(repo *repository.APIKeyRepository) *APIKeyService {
	return &APIKeyService{repo: repo}
}

// Create 生成新的API密钥，原始密钥仅在创建响应中返回一次
func (s *APIKeyService) Create(ownerID int64, req *model.CreateAPIKeyRequest) (*model.CreateAPIKeyResponse, error) {
	for _, scope := range req.Scopes {
		if !validScopes[scope] {
			return nil, errors.New("包含不支持的访问范围: " + scope)
		}
	}

	rawKey, prefix, err := crypto.GenerateAPIKey()
	if err != nil {
		return nil, err
	}

	key := &model.APIKey{
		Name:      req.Name,
		KeyHash:   crypto.HashAPIKey(rawKey),
		KeyPrefix: prefix,
		OwnerID:   ownerID,
		Scopes:    req.Scopes,
		IsActive:  true,
		ExpiresAt: req.ExpiresAt,
	}
	if err := s.repo.Create(key); err != nil {
		return nil, err
	}
	return &model.CreateAPIKeyResponse{APIKey: key, RawKey: rawKey}, nil
}

// Authenticate 验证API密钥并返回密钥实体，同时更新最后使用时间
func (s *APIKeyService) Authenticate(rawKey string) (*model.APIKey, error) {
	hash := crypto.HashAPIKey(rawKey)
	key, err := s.repo.FindByKeyHash(hash)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrAPIKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if !key.IsActive || key.IsExpired() {
		return nil, ErrAPIKeyNotFound
	}
	go s.repo.UpdateLastUsed(key.ID)
	return key, nil
}

// HasScope 检查密钥是否包含指定的访问范围
func (s *APIKeyService) HasScope(key *model.APIKey, scope string) bool {
	for _, s := range key.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// ListByOwner 查询用户名下的所有密钥
func (s *APIKeyService) ListByOwner(ownerID int64) ([]*model.APIKey, error) {
	return s.repo.ListByOwner(ownerID)
}

// Revoke 吊销指定密钥
func (s *APIKeyService) Revoke(keyID, ownerID int64) error {
	return s.repo.Revoke(keyID, ownerID)
}
