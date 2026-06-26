package service

import (
	"errors"
	"security-platform/internal/model"
	"security-platform/internal/repository"
	"security-platform/pkg/crypto"
	"security-platform/pkg/jwt"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("用户名或密码错误")
	ErrAccountLocked      = errors.New("账号已被锁定，请稍后再试")
	ErrAccountDisabled    = errors.New("账号已被禁用")
	ErrInvalidToken       = errors.New("令牌无效或已过期")
)

const maxLoginAttempts = 5

type AuthService struct {
	userRepo    *repository.UserRepository
	sessionRepo *repository.SessionRepository
	jwtAccess   string
	jwtRefresh  string
	accessExp   int
	refreshExp  int
}

func NewAuthService(
	userRepo *repository.UserRepository,
	sessionRepo *repository.SessionRepository,
	accessSecret, refreshSecret string,
	accessExpMin, refreshExpDay int,
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		jwtAccess:   accessSecret,
		jwtRefresh:  refreshSecret,
		accessExp:   accessExpMin,
		refreshExp:  refreshExpDay,
	}
}

// Login 验证用户凭据，登录成功后签发令牌对并创建会话
func (s *AuthService) Login(req *model.LoginRequest, ip, ua string) (*model.TokenPair, *model.User, error) {
	user, err := s.userRepo.FindByUsername(req.Username)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, nil, err
	}
	if user.Status == model.UserStatusDisabled {
		return nil, nil, ErrAccountDisabled
	}
	if user.IsLocked() {
		return nil, nil, ErrAccountLocked
	}
	if !crypto.CheckPassword(user.PasswordHash, req.Password) {
		_ = s.userRepo.RecordLoginFailure(req.Username, maxLoginAttempts)
		return nil, nil, ErrInvalidCredentials
	}
	_ = s.userRepo.RecordLoginSuccess(user.ID)

	// 先以占位令牌创建会话取得会话ID，再用ID生成正式刷新令牌并回填
	session := &model.Session{
		UserID:       user.ID,
		RefreshToken: "pending",
		UserAgent:    ua,
		IPAddress:    ip,
		ExpiresAt:    time.Now().Add(time.Duration(s.refreshExp) * 24 * time.Hour),
	}
	if err := s.sessionRepo.Create(session); err != nil {
		return nil, nil, err
	}
	refreshToken, err := jwt.GenerateRefresh(session.ID, s.jwtRefresh, s.refreshExp)
	if err != nil {
		return nil, nil, err
	}
	if err := s.sessionRepo.UpdateRefreshToken(session.ID, refreshToken); err != nil {
		return nil, nil, err
	}
	accessToken, err := jwt.GenerateAccess(user.ID, user.RoleID, user.Username, s.jwtAccess, s.accessExp)
	if err != nil {
		return nil, nil, err
	}
	return &model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(s.accessExp) * time.Minute),
	}, user, nil
}

// Refresh 通过刷新令牌签发新的令牌对，旧会话立即吊销
func (s *AuthService) Refresh(req *model.RefreshRequest, ip, ua string) (*model.TokenPair, error) {
	claims, err := jwt.ParseRefresh(req.RefreshToken, s.jwtRefresh)
	if err != nil {
		return nil, ErrInvalidToken
	}
	oldSession, err := s.sessionRepo.FindByRefreshToken(req.RefreshToken)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	if !oldSession.IsValid() {
		return nil, ErrInvalidToken
	}
	_ = claims

	user, err := s.userRepo.FindByID(oldSession.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status != model.UserStatusEnabled {
		return nil, ErrAccountDisabled
	}

	// 先吊销旧会话，再创建新会话，保证令牌轮换的单调性
	if err := s.sessionRepo.Revoke(oldSession.ID); err != nil {
		return nil, err
	}
	newSession := &model.Session{
		UserID:       user.ID,
		RefreshToken: "pending",
		UserAgent:    ua,
		IPAddress:    ip,
		ExpiresAt:    time.Now().Add(time.Duration(s.refreshExp) * 24 * time.Hour),
	}
	if err := s.sessionRepo.Create(newSession); err != nil {
		return nil, err
	}
	newRefreshToken, err := jwt.GenerateRefresh(newSession.ID, s.jwtRefresh, s.refreshExp)
	if err != nil {
		return nil, err
	}
	if err := s.sessionRepo.UpdateRefreshToken(newSession.ID, newRefreshToken); err != nil {
		return nil, err
	}
	accessToken, err := jwt.GenerateAccess(user.ID, user.RoleID, user.Username, s.jwtAccess, s.accessExp)
	if err != nil {
		return nil, err
	}
	return &model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(s.accessExp) * time.Minute),
	}, nil
}

// Logout 吊销当前会话
func (s *AuthService) Logout(sessionID int64) error {
	return s.sessionRepo.Revoke(sessionID)
}

// LogoutAll 吊销用户的所有活跃会话
func (s *AuthService) LogoutAll(userID int64) error {
	return s.sessionRepo.RevokeAllByUser(userID)
}

// ChangePassword 修改密码并吊销全部已有会话，强制重新登录
func (s *AuthService) ChangePassword(userID int64, req *model.ChangePasswordRequest) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}
	if !crypto.CheckPassword(user.PasswordHash, req.OldPassword) {
		return ErrInvalidCredentials
	}
	hash, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		return err
	}
	if err := s.userRepo.UpdatePassword(userID, hash); err != nil {
		return err
	}
	return s.sessionRepo.RevokeAllByUser(userID)
}
