package handler

import (
	"net/http"
	"security-platform/internal/middleware"
	"security-platform/internal/model"
	"security-platform/internal/service"
	"strconv"

	"github.com/gin-gonic/gin"
)

type APIKeyHandler struct {
	apiKeySvc *service.APIKeyService
	auditSvc  *service.AuditService
}

func NewAPIKeyHandler(apiKeySvc *service.APIKeyService, auditSvc *service.AuditService) *APIKeyHandler {
	return &APIKeyHandler{apiKeySvc: apiKeySvc, auditSvc: auditSvc}
}

func (h *APIKeyHandler) List(c *gin.Context) {
	ownerID := c.GetInt64(middleware.CtxUserID)
	keys, err := h.apiKeySvc.ListByOwner(ownerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": keys})
}

func (h *APIKeyHandler) Create(c *gin.Context) {
	var req model.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ownerID := c.GetInt64(middleware.CtxUserID)
	username := c.GetString(middleware.CtxUsername)

	resp, err := h.apiKeySvc.Create(ownerID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID:     ownerID,
		Username:   username,
		Action:     "create_apikey",
		Resource:   "apikey",
		ResourceID: strconv.FormatInt(resp.APIKey.ID, 10),
		Detail:     req.Name,
		IPAddress:  c.ClientIP(),
		Result:     model.AuditResultSuccess,
	})
	c.JSON(http.StatusCreated, resp)
}

func (h *APIKeyHandler) Revoke(c *gin.Context) {
	keyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "密钥ID格式错误"})
		return
	}
	ownerID := c.GetInt64(middleware.CtxUserID)
	username := c.GetString(middleware.CtxUsername)

	if err := h.apiKeySvc.Revoke(keyID, ownerID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "密钥不存在"})
		return
	}
	h.auditSvc.Log(&model.AuditLogEntry{
		UserID:     ownerID,
		Username:   username,
		Action:     "revoke_apikey",
		Resource:   "apikey",
		ResourceID: strconv.FormatInt(keyID, 10),
		IPAddress:  c.ClientIP(),
		Result:     model.AuditResultSuccess,
	})
	c.JSON(http.StatusOK, gin.H{"message": "密钥已吊销"})
}
