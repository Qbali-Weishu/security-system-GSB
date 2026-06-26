package service

import (
	"errors"
	"security-platform/internal/model"
	"security-platform/internal/repository"
	"security-platform/pkg/crypto"
)

var ErrUserExists = errors.New("用户名或邮箱已存在")

type UserService struct {
	userRepo *repository.UserRepository
	rbacSvc  *RBACService
}

func NewUserService(userRepo *repository.UserRepository, rbacSvc *RBACService) *UserService {
	return &UserService{userRepo: userRepo, rbacSvc: rbacSvc}
}

func (s *UserService) Create(req *model.CreateUserRequest) (*model.User, error) {
	// 验证角色存在性
	if _, err := s.rbacSvc.roleRepo.FindByID(req.RoleID); errors.Is(err, repository.ErrNotFound) {
		return nil, errors.New("指定的角色不存在")
	}
	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}
	user := &model.User{
		Username:     req.Username,
		PasswordHash: hash,
		Email:        req.Email,
		RoleID:       req.RoleID,
		Status:       model.UserStatusEnabled,
	}
	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) GetByID(id int64) (*model.User, error) {
	return s.userRepo.FindByID(id)
}

func (s *UserService) List(page, pageSize int) ([]*model.User, int, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	return s.userRepo.List((page-1)*pageSize, pageSize)
}

// Update 更新用户信息，若角色发生变更则同时清除权限缓存
func (s *UserService) Update(id int64, req *model.UpdateUserRequest) error {
	if err := s.userRepo.Update(id, req); err != nil {
		return err
	}
	// 角色变更时清除该用户的权限缓存，确保下次请求使用新角色的权限
	if req.RoleID > 0 {
		s.rbacSvc.InvalidateUserCache(id)
	}
	return nil
}
