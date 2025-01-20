package config

import (
	"time"
)

// Config содержит все настройки приложения
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	Security  SecurityConfig
	RateLimit RateLimitConfig
}

// ServerConfig содержит настройки сервера
type ServerConfig struct {
	Port            int           `json:"port"`
	ReadTimeout     time.Duration `json:"read_timeout"`
	WriteTimeout    time.Duration `json:"write_timeout"`
	ShutdownTimeout time.Duration `json:"shutdown_timeout"`
}

// DatabaseConfig содержит настройки базы данных
type DatabaseConfig struct {
	Type     string `json:"type"`      // sqlite или postgres
	Path     string `json:"path"`      // путь к файлу SQLite или DSN для PostgreSQL
	LogLevel string `json:"log_level"` // уровень логирования SQL-запросов
}

// SecurityConfig содержит настройки безопасности
type SecurityConfig struct {
	AllowedIP       string        `json:"allowed_ip"`       // постоянно разрешенный IP
	SessionDuration time.Duration `json:"session_duration"` // длительность сессии
	CookieName      string        `json:"cookie_name"`      // имя cookie
	CookieSecure    bool          `json:"cookie_secure"`    // требовать HTTPS для cookie
	CookieHTTPOnly  bool          `json:"cookie_http_only"` // запретить доступ к cookie из JavaScript
	CookieSameSite  string        `json:"cookie_same_site"` // политика SameSite для cookie
	TOTPIssuer      string        `json:"totp_issuer"`      // издатель для Google Authenticator
}

// RateLimitConfig содержит настройки ограничения запросов
type RateLimitConfig struct {
	RequestsPerSecond int           `json:"requests_per_second"` // максимальное количество запросов в секунду
	BurstSize         int           `json:"burst_size"`          // размер всплеска запросов
	BlockDuration     time.Duration `json:"block_duration"`      // длительность блокировки при превышении лимита
}

// DefaultConfig возвращает конфигурацию по умолчанию
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:            8443,
			ReadTimeout:     10 * time.Second,
			WriteTimeout:    10 * time.Second,
			ShutdownTimeout: 30 * time.Second,
		},
		Database: DatabaseConfig{
			Type:     "sqlite",
			Path:     "gateway.db",
			LogLevel: "error",
		},
		Security: SecurityConfig{
			AllowedIP:       "", // должен быть установлен вручную
			SessionDuration: 3 * time.Hour,
			CookieName:      "gateway_session",
			CookieSecure:    true,
			CookieHTTPOnly:  true,
			CookieSameSite:  "strict",
			TOTPIssuer:      "Gateway Service",
		},
		RateLimit: RateLimitConfig{
			RequestsPerSecond: 10,
			BurstSize:         20,
			BlockDuration:     10 * time.Minute,
		},
	}
}
