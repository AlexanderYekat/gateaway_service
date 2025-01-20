package handlers

import (
	"net/http"
	"time"

	"gateaway_service/internal/auth"
	"gateaway_service/internal/config"
	"gateaway_service/internal/database"
	"gateaway_service/internal/models"

	"github.com/gin-gonic/gin"
)

// Handler содержит зависимости для обработчиков
type Handler struct {
	db     *database.DB
	auth   *auth.Auth
	config *config.Config
}

// New создает новый экземпляр Handler
func New(db *database.DB, auth *auth.Auth, cfg *config.Config) *Handler {
	return &Handler{
		db:     db,
		auth:   auth,
		config: cfg,
	}
}

// LoginPage отображает страницу входа
func (h *Handler) LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "Login - Gateway Service",
	})
}

// Login обрабатывает процесс входа
func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Login       string `json:"login" binding:"required"`
		TOTPCode    string `json:"totp_code" binding:"required"`
		Fingerprint string `json:"fingerprint" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Поиск пользователя
	var user models.User
	if err := h.db.Where("login = ?", req.Login).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Проверка TOTP кода
	if !h.auth.ValidateTOTPCode(user.TOTPSecret, req.TOTPCode) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid TOTP code"})
		return
	}

	// Проверка fingerprint
	isValidFingerprint, err := h.auth.ValidateFingerprint(&user, req.Fingerprint)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate fingerprint"})
		return
	}

	// Если fingerprint не валиден, добавляем его в список разрешенных
	if !isValidFingerprint {
		fingerprints, err := user.GetAllowedFingerprints()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get fingerprints"})
			return
		}
		fingerprints = append(fingerprints, req.Fingerprint)
		if err := user.SetAllowedFingerprints(fingerprints); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save fingerprint"})
			return
		}
		if err := h.db.Save(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
			return
		}
	}

	// Создание сессии
	token, err := h.auth.GenerateSessionToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate session"})
		return
	}

	session := models.Session{
		UserID:      user.ID,
		Token:       token,
		Fingerprint: req.Fingerprint,
		IP:          c.ClientIP(),
		ExpiresAt:   time.Now().Add(h.config.Security.SessionDuration),
	}

	if err := h.db.Create(&session).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// Добавление IP в белый список
	whitelistedIP := models.WhitelistedIP{
		IP:        c.ClientIP(),
		ExpiresAt: time.Now().Add(h.config.Security.SessionDuration),
	}

	if err := h.db.Create(&whitelistedIP).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to whitelist IP"})
		return
	}

	// Установка cookie
	h.auth.SetSessionCookie(c.Writer, token)

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"user_id": user.ID,
	})
}

// Status возвращает статус текущей сессии
func (h *Handler) Status(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	sessionID, _ := c.Get("session_id")
	var session models.Session
	if err := h.db.First(&session, sessionID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"ip":            session.IP,
		"expires_at":    session.ExpiresAt,
	})
}

// RegisterFingerprint регистрирует новый fingerprint для пользователя
func (h *Handler) RegisterFingerprint(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req struct {
		Fingerprint string `json:"fingerprint" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	fingerprints, err := user.GetAllowedFingerprints()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get fingerprints"})
		return
	}

	// Проверка на дубликаты
	for _, fp := range fingerprints {
		if fp == req.Fingerprint {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Fingerprint already registered"})
			return
		}
	}

	fingerprints = append(fingerprints, req.Fingerprint)
	if err := user.SetAllowedFingerprints(fingerprints); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save fingerprint"})
		return
	}

	if err := h.db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Fingerprint registered successfully"})
}

// Logout выполняет выход из системы
func (h *Handler) Logout(c *gin.Context) {
	sessionID, exists := c.Get("session_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Удаление сессии
	if err := h.db.Delete(&models.Session{}, sessionID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete session"})
		return
	}

	// Удаление IP из белого списка
	if err := h.db.Where("ip = ? AND is_permanent = ?", c.ClientIP(), false).
		Delete(&models.WhitelistedIP{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove IP from whitelist"})
		return
	}

	// Очистка cookie
	h.auth.ClearSessionCookie(c.Writer)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}
