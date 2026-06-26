package handler

import (
	"net/http"
	"security-platform/internal/middleware"
	"security-platform/internal/model"
	"security-platform/internal/service"
	"strconv"

	"github.com/gin-gonic/gin"
)

type AdminHandler struct {
	rbacSvc  *service.RBACService
	auditSvc *service.AuditService
}

func NewAdminHandler(rbacSvc *service.RBACService, auditSvc *service.AuditService) *AdminHandler {
	return &AdminHandler{rbacSvc: rbacSvc, auditSvc: auditSvc}
}

func (h *AdminHandler) ListRoles(c *gin.Context) {
	roles, err := h.rbacSvc.ListRoles()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": roles})
}

func (h *AdminHandler) CreateRole(c *gin.Context) {
	var req model.CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	operatorID := c.GetInt64(middleware.CtxUserID)
	username := c.GetString(middleware.CtxUsername)

	role, err := h.rbacSvc.CreateRole(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID:     operatorID,
		Username:   username,
		Action:     "create_role",
		Resource:   "role",
		ResourceID: strconv.FormatInt(role.ID, 10),
		Detail:     role.Name,
		IPAddress:  c.ClientIP(),
		Result:     model.AuditResultSuccess,
	})
	c.JSON(http.StatusCreated, role)
}

func (h *AdminHandler) ListPermissions(c *gin.Context) {
	perms, err := h.rbacSvc.ListPermissions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": perms})
}

func (h *AdminHandler) GetRolePermissions(c *gin.Context) {
	roleID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "角色ID格式错误"})
		return
	}
	perms, err := h.rbacSvc.GetRolePermissions(roleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": perms})
}

// UpdateRolePermissions 更新角色权限集合
// 注意：此接口调用 rbacSvc.UpdateRolePermissions，其中存在缓存失效逻辑缺陷，
// 权限变更后已登录用户的缓存不会被正确清除。
func (h *AdminHandler) UpdateRolePermissions(c *gin.Context) {
	roleID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "角色ID格式错误"})
		return
	}
	var req model.UpdateRolePermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	operatorID := c.GetInt64(middleware.CtxUserID)
	username := c.GetString(middleware.CtxUsername)

	if err := h.rbacSvc.UpdateRolePermissions(roleID, req.PermissionIDs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID:     operatorID,
		Username:   username,
		Action:     "update_role_permissions",
		Resource:   "role",
		ResourceID: strconv.FormatInt(roleID, 10),
		IPAddress:  c.ClientIP(),
		Result:     model.AuditResultSuccess,
	})
	c.JSON(http.StatusOK, gin.H{"message": "权限已更新"})
}

func (h *AdminHandler) ListAuditLogs(c *gin.Context) {
	var q model.AuditQueryParams
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logs, total, err := h.auditSvc.List(&q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "data": logs})
}

// VerifyAuditChain 校验审计日志哈希链完整性
func (h *AdminHandler) VerifyAuditChain(c *gin.Context) {
	n, _ := strconv.Atoi(c.DefaultQuery("last_n", "1000"))
	broken, err := h.auditSvc.VerifyChain(n)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "校验失败"})
		return
	}
	if broken > 0 {
		c.JSON(http.StatusOK, gin.H{"intact": false, "first_broken_id": broken})
		return
	}
	c.JSON(http.StatusOK, gin.H{"intact": true})
}
