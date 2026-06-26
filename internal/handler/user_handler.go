package handler

import (
	"net/http"
	"security-platform/internal/middleware"
	"security-platform/internal/model"
	"security-platform/internal/repository"
	"security-platform/internal/service"
	"strconv"

	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	userSvc  *service.UserService
	userRepo *repository.UserRepository
	rbacSvc  *service.RBACService
	auditSvc *service.AuditService
}

func NewUserHandler(
	userSvc *service.UserService,
	userRepo *repository.UserRepository,
	rbacSvc *service.RBACService,
	auditSvc *service.AuditService,
) *UserHandler {
	return &UserHandler{userSvc: userSvc, userRepo: userRepo, rbacSvc: rbacSvc, auditSvc: auditSvc}
}

// List 查询用户列表，需要user:read权限
func (h *UserHandler) List(c *gin.Context) {
	callerID := c.GetInt64(middleware.CtxUserID)
	roleID := c.GetInt64(middleware.CtxRoleID)

	if !h.rbacSvc.HasPermission(roleID, callerID, model.PermUserRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权查看用户列表"})
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	users, total, err := h.userSvc.List(page, size)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "data": users})
}

// Get 查询用户详情
// 任何已登录用户可查看自身信息，查看他人需要user:read权限
func (h *UserHandler) Get(c *gin.Context) {
	callerID := c.GetInt64(middleware.CtxUserID)
	roleID := c.GetInt64(middleware.CtxRoleID)

	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户ID格式错误"})
		return
	}

	// 查看自身不需要额外权限，查看他人需要user:read
	if id != callerID && !h.rbacSvc.HasPermission(roleID, callerID, model.PermUserRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权查看其他用户信息"})
		return
	}

	user, err := h.userSvc.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	c.JSON(http.StatusOK, user)
}

// Create 创建用户，需要user:write权限
// 不能为新用户授予高于或等于操作者自身等级的角色，防止权限提升
func (h *UserHandler) Create(c *gin.Context) {
	callerID := c.GetInt64(middleware.CtxUserID)
	roleID := c.GetInt64(middleware.CtxRoleID)

	if !h.rbacSvc.HasPermission(roleID, callerID, model.PermUserWrite) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权创建用户"})
		return
	}

	var req model.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 防止越权：新用户角色等级不能高于或等于操作者自身
	callerRank := h.rbacSvc.RoleRank(roleID)
	targetRank := h.rbacSvc.RoleRank(req.RoleID)
	if targetRank >= callerRank {
		c.JSON(http.StatusForbidden, gin.H{"error": "不能为新用户分配不低于自身等级的角色"})
		return
	}

	user, err := h.userSvc.Create(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	username := c.GetString(middleware.CtxUsername)
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID: callerID, Username: username,
		Action: "create_user", Resource: "user",
		ResourceID: strconv.FormatInt(user.ID, 10),
		Detail:     user.Username, IPAddress: c.ClientIP(),
		Result: model.AuditResultSuccess,
	})
	c.JSON(http.StatusCreated, user)
}

// Update 更新用户信息，需要user:write权限
// 不能修改自身的角色（防止自行提权）
// 不能将他人的角色设置为高于或等于操作者自身等级的角色
func (h *UserHandler) Update(c *gin.Context) {
	callerID := c.GetInt64(middleware.CtxUserID)
	roleID := c.GetInt64(middleware.CtxRoleID)

	if !h.rbacSvc.HasPermission(roleID, callerID, model.PermUserWrite) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权修改用户信息"})
		return
	}

	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户ID格式错误"})
		return
	}

	var req model.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 不允许修改自身角色
	if id == callerID && req.RoleID > 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "不能修改自身的角色"})
		return
	}

	// 变更角色时检查等级限制
	if req.RoleID > 0 {
		callerRank := h.rbacSvc.RoleRank(roleID)
		targetRank := h.rbacSvc.RoleRank(req.RoleID)
		if targetRank >= callerRank {
			c.JSON(http.StatusForbidden, gin.H{"error": "不能将用户角色设置为不低于自身等级的角色"})
			return
		}
	}

	if err := h.userSvc.Update(id, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	username := c.GetString(middleware.CtxUsername)
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID: callerID, Username: username,
		Action: "update_user", Resource: "user",
		ResourceID: strconv.FormatInt(id, 10),
		IPAddress:  c.ClientIP(), Result: model.AuditResultSuccess,
	})
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}
