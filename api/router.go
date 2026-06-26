package api

import (
	"security-platform/internal/config"
	"security-platform/internal/handler"
	"security-platform/internal/middleware"
	"security-platform/internal/model"
	"security-platform/internal/service"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(
	r *gin.Engine,
	cfg *config.JWTConfig,
	authH *handler.AuthHandler,
	alertH *handler.AlertHandler,
	userH *handler.UserHandler,
	adminH *handler.AdminHandler,
	apikeyH *handler.APIKeyHandler,
	rbacSvc *service.RBACService,
) {
	pub := r.Group("/api/v1")
	pub.POST("/auth/login", authH.Login)
	pub.POST("/auth/refresh", authH.Refresh)

	auth := r.Group("/api/v1", middleware.JWTAuth(cfg))
	auth.POST("/auth/logout", authH.Logout)
	auth.POST("/auth/logout-all", authH.LogoutAll)
	auth.PUT("/auth/password", authH.ChangePassword)

	// 告警接口，授权逻辑在各handler内部处理
	auth.GET("/alerts", alertH.List)
	auth.GET("/alerts/:id", alertH.Get)
	auth.POST("/alerts", alertH.Create)
	auth.PUT("/alerts/:id", alertH.Update)
	auth.POST("/alerts/:id/assign", alertH.Assign)
	auth.POST("/alerts/:id/comments", alertH.AddComment)

	// 用户接口，授权逻辑在各handler内部处理
	auth.GET("/users", userH.List)
	auth.GET("/users/:id", userH.Get)
	auth.POST("/users", userH.Create)
	auth.PUT("/users/:id", userH.Update)

	// API密钥接口
	auth.GET("/apikeys", apikeyH.List)
	auth.POST("/apikeys", middleware.RequirePermission(rbacSvc, model.PermApikeyManage), apikeyH.Create)
	auth.DELETE("/apikeys/:id", middleware.RequirePermission(rbacSvc, model.PermApikeyManage), apikeyH.Revoke)

	// 系统管理接口
	admin := auth.Group("/admin")
	admin.GET("/roles", middleware.RequirePermission(rbacSvc, model.PermRoleRead), adminH.ListRoles)
	admin.POST("/roles", middleware.RequirePermission(rbacSvc, model.PermRoleWrite), adminH.CreateRole)
	admin.GET("/roles/:id/permissions", middleware.RequirePermission(rbacSvc, model.PermRoleRead), adminH.GetRolePermissions)
	admin.PUT("/roles/:id/permissions", middleware.RequirePermission(rbacSvc, model.PermRoleWrite), adminH.UpdateRolePermissions)
	admin.GET("/permissions", middleware.RequirePermission(rbacSvc, model.PermRoleRead), adminH.ListPermissions)
	admin.GET("/audit-logs", middleware.RequirePermission(rbacSvc, model.PermAuditRead), adminH.ListAuditLogs)
	admin.GET("/audit-logs/verify", middleware.RequirePermission(rbacSvc, model.PermAuditRead), adminH.VerifyAuditChain)
}
