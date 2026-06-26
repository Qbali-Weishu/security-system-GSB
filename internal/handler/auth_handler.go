package handler

import (
	"net/http"
	"security-platform/internal/middleware"
	"security-platform/internal/model"
	"security-platform/internal/service"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authSvc  *service.AuthService
	auditSvc *service.AuditService
}

func NewAuthHandler(authSvc *service.AuthService, auditSvc *service.AuditService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc, auditSvc: auditSvc}
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req model.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	pair, user, err := h.authSvc.Login(&req, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		h.auditSvc.Log(&model.AuditLogEntry{
			Username:  req.Username,
			Action:    "login",
			Resource:  "auth",
			Detail:    err.Error(),
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Result:    model.AuditResultFailure,
		})
		status := http.StatusUnauthorized
		if err == service.ErrAccountLocked || err == service.ErrAccountDisabled {
			status = http.StatusForbidden
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID:    user.ID,
		Username:  user.Username,
		Action:    "login",
		Resource:  "auth",
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Result:    model.AuditResultSuccess,
	})
	c.JSON(http.StatusOK, pair)
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req model.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	pair, err := h.authSvc.Refresh(&req, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pair)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	sessionID, _ := c.Get(middleware.CtxSessionID)
	userID := c.GetInt64(middleware.CtxUserID)
	username := c.GetString(middleware.CtxUsername)
	if id, ok := sessionID.(int64); ok {
		_ = h.authSvc.Logout(id)
	}
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID:    userID,
		Username:  username,
		Action:    "logout",
		Resource:  "auth",
		IPAddress: c.ClientIP(),
		Result:    model.AuditResultSuccess,
	})
	c.JSON(http.StatusOK, gin.H{"message": "已退出登录"})
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req model.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userID := c.GetInt64(middleware.CtxUserID)
	username := c.GetString(middleware.CtxUsername)

	if err := h.authSvc.ChangePassword(userID, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID:    userID,
		Username:  username,
		Action:    "change_password",
		Resource:  "auth",
		IPAddress: c.ClientIP(),
		Result:    model.AuditResultSuccess,
	})
	c.JSON(http.StatusOK, gin.H{"message": "密码已修改，所有会话已注销"})
}

func (h *AuthHandler) LogoutAll(c *gin.Context) {
	userID := c.GetInt64(middleware.CtxUserID)
	username := c.GetString(middleware.CtxUsername)
	_ = h.authSvc.LogoutAll(userID)
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID:    userID,
		Username:  username,
		Action:    "logout_all",
		Resource:  "auth",
		IPAddress: c.ClientIP(),
		Result:    model.AuditResultSuccess,
	})
	c.JSON(http.StatusOK, gin.H{"message": "已注销全部会话"})
}
