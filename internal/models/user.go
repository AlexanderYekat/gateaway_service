package models

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// User представляет модель пользователя в системе
type User struct {
	gorm.Model
	Login               string    `gorm:"uniqueIndex;not null"`
	TOTPSecret          string    `gorm:"not null"`  // Секретный ключ для Google Authenticator
	AllowedCookies      string    `gorm:"type:text"` // JSON-строка с разрешенными cookie
	AllowedFingerprints string    `gorm:"type:text"` // JSON-строка с разрешенными отпечатками
	LastIP              string    `gorm:"size:45"`   // Последний IP-адрес
	LastLogin           time.Time // Время последнего входа
}

// Session представляет сессию пользователя
type Session struct {
	gorm.Model
	UserID      uint      `gorm:"not null"`
	Token       string    `gorm:"uniqueIndex;not null"` // Cookie token
	Fingerprint string    `gorm:"not null"`             // Отпечаток устройства
	IP          string    `gorm:"size:45;not null"`     // IP-адрес
	ExpiresAt   time.Time `gorm:"not null"`             // Время истечения сессии
}

// WhitelistedIP представляет разрешенный IP-адрес
type WhitelistedIP struct {
	gorm.Model
	IP          string    `gorm:"size:45;uniqueIndex;not null"` // IP-адрес
	ExpiresAt   time.Time `gorm:"not null"`                     // Время истечения доступа
	IsPermanent bool      `gorm:"default:false"`                // Постоянный доступ
}

// SetAllowedCookies сохраняет список разрешенных cookie
func (u *User) SetAllowedCookies(cookies []string) error {
	data, err := json.Marshal(cookies)
	if err != nil {
		return err
	}
	u.AllowedCookies = string(data)
	return nil
}

// GetAllowedCookies возвращает список разрешенных cookie
func (u *User) GetAllowedCookies() ([]string, error) {
	var cookies []string
	if u.AllowedCookies == "" {
		return cookies, nil
	}
	err := json.Unmarshal([]byte(u.AllowedCookies), &cookies)
	return cookies, err
}

// SetAllowedFingerprints сохраняет список разрешенных отпечатков
func (u *User) SetAllowedFingerprints(fingerprints []string) error {
	data, err := json.Marshal(fingerprints)
	if err != nil {
		return err
	}
	u.AllowedFingerprints = string(data)
	return nil
}

// GetAllowedFingerprints возвращает список разрешенных отпечатков
func (u *User) GetAllowedFingerprints() ([]string, error) {
	var fingerprints []string
	if u.AllowedFingerprints == "" {
		return fingerprints, nil
	}
	err := json.Unmarshal([]byte(u.AllowedFingerprints), &fingerprints)
	return fingerprints, err
}
