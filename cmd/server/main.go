package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"security-platform/api"
	"security-platform/internal/config"
	"security-platform/internal/handler"
	"security-platform/internal/repository"
	"security-platform/internal/service"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	db, err := repository.NewDB(cfg.Database.DSN())
	if err != nil {
		log.Fatalf("数据库连接失败: %v", err)
	}
	defer db.Close()

	userRepo := repository.NewUserRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	roleRepo := repository.NewRoleRepository(db)
	alertRepo := repository.NewAlertRepository(db)
	auditRepo := repository.NewAuditRepository(db)
	apikeyRepo := repository.NewAPIKeyRepository(db)

	auditSvc := service.NewAuditService(auditRepo)
	defer auditSvc.Shutdown()

	rbacSvc := service.NewRBACService(roleRepo)
	authSvc := service.NewAuthService(userRepo, sessionRepo,
		cfg.JWT.AccessSecret, cfg.JWT.RefreshSecret,
		cfg.JWT.AccessExpMin, cfg.JWT.RefreshExpDay)
	userSvc := service.NewUserService(userRepo, rbacSvc)
	alertSvc := service.NewAlertService(alertRepo, userRepo, auditSvc)
	apiKeySvc := service.NewAPIKeyService(apikeyRepo)

	go runSLAChecker(alertSvc)

	authH := handler.NewAuthHandler(authSvc, auditSvc)
	alertH := handler.NewAlertHandler(alertSvc, userRepo, rbacSvc, auditSvc)
	userH := handler.NewUserHandler(userSvc, userRepo, rbacSvc, auditSvc)
	adminH := handler.NewAdminHandler(rbacSvc, auditSvc)
	apikeyH := handler.NewAPIKeyHandler(apiKeySvc, auditSvc)

	gin.SetMode(cfg.Server.Mode)
	r := gin.Default()
	api.RegisterRoutes(r, &cfg.JWT, authH, alertH, userH, adminH, apikeyH, rbacSvc)

	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		log.Printf("服务启动，监听端口 %s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务启动失败: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func runSLAChecker(alertSvc *service.AlertService) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if err := alertSvc.RunSLACheck(); err != nil {
			log.Printf("SLA检查失败: %v", err)
		}
	}
}
