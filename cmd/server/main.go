package main

import (
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"gateaway_service/internal/auth"
	"gateaway_service/internal/config"
	"gateaway_service/internal/database"
	"gateaway_service/internal/handlers"
	"gateaway_service/internal/middleware"

	"github.com/gin-gonic/gin"
)

func main() {
	// Создаем директорию для логов если её нет
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}

	// Удаляем старый файл логов если он существует
	logPath := filepath.Join(logDir, "gateway.log")
	if err := os.Remove(logPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("Failed to remove old log file: %v", err)
	}

	// Открываем новый файл для логов
	logFile, err := os.OpenFile(
		logPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()

	// Настраиваем логгер для записи как в файл, так и в консоль
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger := log.New(multiWriter, "[GATEWAY] ", log.LstdFlags)

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

	// Добавляем глобальный middleware для логирования
	router.Use(func(c *gin.Context) {
		ip := c.ClientIP()
		userAgent := c.Request.UserAgent()
		fingerprint := c.GetHeader("X-Fingerprint")

		logger.Printf(`
=== Входящий запрос ===
Path: %s
Method: %s
IP: %s
User-Agent: %s
Fingerprint: %s
Cookies: %v
Headers: %v
===================`,
			c.Request.URL.Path,
			c.Request.Method,
			ip,
			userAgent,
			fingerprint,
			c.Request.Cookies(),
			c.Request.Header)

		c.Next()
	})

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
	// Все маршруты, включая /login, требуют проверки IP или fingerprint
	router.Use(middleware.IPFilter(db, &cfg.Security)) // Глобальная проверка доступа

	// Публичные маршруты (но всё ещё требуют проверки IP/fingerprint)
	router.GET("/login", h.LoginPage)
	router.POST("/login", h.Login)

	// Дополнительно защищенные маршруты (требуют аутентификации)
	protected := router.Group("/")
	protected.Use(middleware.RequireAuth(db)) // Дополнительная проверка аутентификации
	{
		protected.GET("/status", h.Status)
		protected.POST("/register-fingerprint", h.RegisterFingerprint)
		protected.GET("/logout", h.Logout)
	}
}
