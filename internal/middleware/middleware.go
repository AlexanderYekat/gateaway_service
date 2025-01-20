package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"gateaway_service/internal/config"
	"gateaway_service/internal/database"
	"gateaway_service/internal/models"

	"log"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimiter представляет ограничитель запросов для IP-адреса
type RateLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	rateLimiters    = make(map[string]*RateLimiter)
	mu              sync.Mutex
	cleanupInterval = 5 * time.Minute
)

// generateFingerprint создает отпечаток на основе заголовков
func generateFingerprint(c *gin.Context) string {
	// Собираем значимые заголовки
	components := []string{
		c.Request.UserAgent(),
		c.GetHeader("Accept-Language"),
		c.GetHeader("Sec-Ch-Ua"),
		c.GetHeader("Sec-Ch-Ua-Platform"),
		c.GetHeader("Sec-Ch-Ua-Mobile"),
	}

	// Создаем строку для хеширования
	fingerprint := fmt.Sprintf("%v", components)

	// Создаем SHA-256 хеш
	hasher := sha256.New()
	hasher.Write([]byte(fingerprint))
	return hex.EncodeToString(hasher.Sum(nil))
}

// IPFilter проверяет IP-адрес запроса
func IPFilter(db *database.DB, cfg *config.SecurityConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := getClientIP(c)
		userAgent := c.Request.UserAgent()
		browserFingerprint := generateFingerprint(c)

		log.Printf(`
=== Данные для добавления в базу ===
IP адрес: %s
User-Agent: %s
Сгенерированный fingerprint: %s
URL запроса: %s
===============================`,
			ip, userAgent, browserFingerprint, c.Request.URL.Path)

		// Проверка статического разрешенного IP
		if cfg.AllowedIP != "" && ip == cfg.AllowedIP {
			c.Next()
			return
		}

		// Проверка IP в белом списке
		var whitelistedIP models.WhitelistedIP
		result := db.Where("ip = ? AND expires_at > ?", ip, time.Now()).
			Or("ip = ? AND is_permanent = ?", ip, true).
			First(&whitelistedIP)

		if result.Error != nil {
			// Проверяем fingerprint если IP не разрешен
			var user models.User
			fingerprintResult := db.Where("allowed_fingerprints LIKE ?",
				fmt.Sprintf("%%%s%%", browserFingerprint)).First(&user)

			if fingerprintResult.Error != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// RateLimit ограничивает количество запросов с одного IP
func RateLimit(cfg *config.RateLimitConfig) gin.HandlerFunc {
	// Запуск очистки старых лимитеров
	go cleanupLimiters()

	return func(c *gin.Context) {
		ip := getClientIP(c)
		limiter := getRateLimiter(ip, cfg)

		if !limiter.limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAuth проверяет аутентификацию пользователя
func RequireAuth(db *database.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		sess := sessions.Default(c)
		userID := sess.Get("user_id")

		log.Printf("[DEBUG] Проверка сессии:\n"+
			"Session ID: %v\n"+
			"User ID: %v\n",
			sess.ID(), userID)

		// Получение cookie
		cookie, err := c.Cookie("gateway_session")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		// Поиск сессии
		var session models.Session
		if err := db.Where("token = ? AND expires_at > ?", cookie, time.Now()).
			First(&session).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired session"})
			c.Abort()
			return
		}

		// Проверка IP-адреса
		if session.IP != getClientIP(c) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "IP address mismatch"})
			c.Abort()
			return
		}

		// Добавление информации о пользователе в контекст
		c.Set("user_id", session.UserID)
		c.Set("session_id", session.ID)

		c.Next()
	}
}

// getRateLimiter возвращает или создает лимитер для IP-адреса
func getRateLimiter(ip string, cfg *config.RateLimitConfig) *RateLimiter {
	mu.Lock()
	defer mu.Unlock()

	if limiter, exists := rateLimiters[ip]; exists {
		limiter.lastSeen = time.Now()
		return limiter
	}

	limiter := &RateLimiter{
		limiter:  rate.NewLimiter(rate.Limit(cfg.RequestsPerSecond), cfg.BurstSize),
		lastSeen: time.Now(),
	}
	rateLimiters[ip] = limiter

	return limiter
}

// cleanupLimiters удаляет неиспользуемые лимитеры
func cleanupLimiters() {
	for {
		time.Sleep(cleanupInterval)

		mu.Lock()
		for ip, limiter := range rateLimiters {
			if time.Since(limiter.lastSeen) > cleanupInterval {
				delete(rateLimiters, ip)
			}
		}
		mu.Unlock()
	}
}

// getClientIP получает IP-адрес клиента
func getClientIP(c *gin.Context) string {
	// Проверка заголовка X-Forwarded-For
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Проверка заголовка X-Real-IP
	if xrip := c.GetHeader("X-Real-IP"); xrip != "" {
		return xrip
	}

	// Получение IP из RemoteAddr
	return c.ClientIP()
}
