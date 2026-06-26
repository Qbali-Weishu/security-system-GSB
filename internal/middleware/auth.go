package middleware

import (
	"net/http"
	"security-platform/internal/config"
	"security-platform/internal/service"
	jwtutil "security-platform/pkg/jwt"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	CtxUserID    = "userID"
	CtxUsername  = "username"
	CtxRoleID    = "roleID"
	CtxSessionID = "sessionID"
)

// JWTAuth 验证请求头中的 Bearer 令牌，将用户身份写入上下文
func JWTAuth(cfg *config.JWTConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "缺少认证令牌"})
			return
		}
		claims, err := jwtutil.ParseAccess(strings.TrimPrefix(header, "Bearer "), cfg.AccessSecret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "令牌无效或已过期"})
			return
		}
		c.Set(CtxUserID, claims.UserID)
		c.Set(CtxUsername, claims.Username)
		c.Set(CtxRoleID, claims.RoleID)
		c.Next()
	}
}

// APIKeyAuth 验证请求头中的 X-API-Key，将密钥拥有者写入上下文
func APIKeyAuth(apiKeySvc *service.APIKeyService) gin.HandlerFunc {
	return func(c *gin.Context) {
		rawKey := c.GetHeader("X-API-Key")
		if rawKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "缺少 API 密钥"})
			return
		}
		key, err := apiKeySvc.Authenticate(rawKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "API 密钥无效或已过期"})
			return
		}
		c.Set("apiKeyID", key.ID)
		c.Set("apiKeyOwnerID", key.OwnerID)
		c.Set("apiKeyScopes", key.Scopes)
		c.Next()
	}
}
