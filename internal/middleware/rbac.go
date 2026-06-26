package middleware

import (
	"net/http"
	"security-platform/internal/service"

	"github.com/gin-gonic/gin"
)

// RequirePermission 返回权限检查中间件，验证当前用户是否拥有指定权限
func RequirePermission(rbacSvc *service.RBACService, perm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID, ok := c.Get(CtxRoleID)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "未经认证"})
			return
		}
		userID, _ := c.Get(CtxUserID)
		if !rbacSvc.HasPermission(roleID.(int64), userID.(int64), perm) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "权限不足: " + perm})
			return
		}
		c.Next()
	}
}
