package middleware

import (
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

// IPFilter проверяет IP-адрес запроса
func IPFilter(db *database.DB, cfg *config.SecurityConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := getClientIP(c)
		userAgent := c.Request.UserAgent()
		fingerprint := c.GetHeader("X-Fingerprint")

		log.Printf("[DEBUG] Входящий запрос:\n"+
			"Path: %s\n"+
			"Method: %s\n"+
			"IP: %s\n"+
			"User-Agent: %s\n"+
			"Fingerprint: %s\n"+
			"Headers: %v\n",
			c.Request.URL.Path,
			c.Request.Method,
			ip,
			userAgent,
			fingerprint,
			c.Request.Header)

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
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			c.Abort()
			return
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
