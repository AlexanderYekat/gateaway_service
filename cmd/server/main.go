package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"gateaway_service/internal/auth"
	"gateaway_service/internal/config"
	"gateaway_service/internal/database"
	"gateaway_service/internal/handlers"
	"gateaway_service/internal/middleware"

	"github.com/gin-gonic/gin"
)

func main() {
	// Инициализация логгера
	logger := log.New(os.Stdout, "[GATEWAY] ", log.LstdFlags)

	// Загрузка конфигурации
	cfg := config.DefaultConfig()

	// Инициализация базы данных
	db, err := database.New(&cfg.Database)
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}

	// Инициализация сервиса аутентификации
	authService := auth.New(&cfg.Security)

	// Инициализация обработчиков
	handler := handlers.New(db, authService, cfg)

	// Создание роутера Gin
	router := gin.Default()

	// Загрузка HTML шаблонов
	router.LoadHTMLGlob("web/templates/*")
	router.Static("/static", "web/static")

	// Настройка middleware
	router.Use(gin.Recovery())
	router.Use(middleware.RateLimit(&cfg.RateLimit))

	// Настройка маршрутов
	setupRoutes(router, handler, db, cfg, authService)

	// Запуск сервера
	go func() {
		addr := cfg.Server.Port
		logger.Printf("Starting server on port %d", addr)
		if err := router.Run(":8443"); err != nil {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Println("Shutting down server...")
}

func setupRoutes(router *gin.Engine, h *handlers.Handler, db *database.DB, cfg *config.Config, auth *auth.Auth) {
	// Публичные маршруты
	router.GET("/login", h.LoginPage)
	router.POST("/login", h.Login)

	// Защищенные маршруты
	protected := router.Group("/")
	protected.Use(middleware.IPFilter(db, &cfg.Security))
	protected.Use(middleware.RequireAuth(db))
	{
		protected.GET("/status", h.Status)
		protected.POST("/register-fingerprint", h.RegisterFingerprint)
		protected.GET("/logout", h.Logout)
	}
}
