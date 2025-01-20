package auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gateaway_service/internal/config"
	"gateaway_service/internal/models"

	"github.com/pquerna/otp/totp"
)

// Auth представляет сервис аутентификации
type Auth struct {
	config *config.SecurityConfig
}

// New создает новый экземпляр сервиса аутентификации
func New(cfg *config.SecurityConfig) *Auth {
	return &Auth{
		config: cfg,
	}
}

// GenerateTOTPSecret генерирует новый секретный ключ для Google Authenticator
func (a *Auth) GenerateTOTPSecret(username string) (string, string, error) {
	// Генерация случайного ключа
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", "", fmt.Errorf("failed to generate random secret: %w", err)
	}

	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	// Создание TOTP ключа
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      a.config.TOTPIssuer,
		AccountName: username,
		Secret:      secret,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	return secretBase32, key.URL(), nil
}

// ValidateTOTPCode проверяет код Google Authenticator
func (a *Auth) ValidateTOTPCode(secret string, code string) bool {
	return totp.Validate(code, secret)
}

// GenerateSessionToken генерирует новый токен сессии
func (a *Auth) GenerateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}
	return base32.StdEncoding.EncodeToString(b), nil
}

// SetSessionCookie устанавливает cookie сессии
func (a *Auth) SetSessionCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     a.config.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(a.config.SessionDuration),
		HttpOnly: a.config.CookieHTTPOnly,
		Secure:   a.config.CookieSecure,
		SameSite: parseSameSite(a.config.CookieSameSite),
	}
	http.SetCookie(w, cookie)
}

// ClearSessionCookie удаляет cookie сессии
func (a *Auth) ClearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     a.config.CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

// ValidateFingerprint проверяет fingerprint устройства
func (a *Auth) ValidateFingerprint(user *models.User, fingerprint string) (bool, error) {
	allowedFingerprints, err := user.GetAllowedFingerprints()
	if err != nil {
		return false, fmt.Errorf("failed to get allowed fingerprints: %w", err)
	}

	for _, allowed := range allowedFingerprints {
		if allowed == fingerprint {
			return true, nil
		}
	}
	return false, nil
}

// parseSameSite преобразует строковое значение в тип http.SameSite
func parseSameSite(value string) http.SameSite {
	switch strings.ToLower(value) {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}
