package database

import (
	"fmt"
	"log"

	"gateaway_service/internal/config"
	"gateaway_service/internal/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB представляет соединение с базой данных
type DB struct {
	*gorm.DB
}

// New создает новое подключение к базе данных
func New(cfg *config.DatabaseConfig) (*DB, error) {
	var dialector gorm.Dialector

	// Настройка уровня логирования
	logLevel := logger.Error
	switch cfg.LogLevel {
	case "silent":
		logLevel = logger.Silent
	case "info":
		logLevel = logger.Info
	case "warn":
		logLevel = logger.Warn
	}

	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	}

	// Подключение к базе данных
	switch cfg.Type {
	case "sqlite":
		dialector = sqlite.Open(cfg.Path)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Type)
	}

	db, err := gorm.Open(dialector, gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Автоматическая миграция схемы
	if err := autoMigrate(db); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return &DB{db}, nil
}

// autoMigrate выполняет автоматическую миграцию схемы базы данных
func autoMigrate(db *gorm.DB) error {
	log.Println("Running database migrations...")

	// Список моделей для миграции
	models := []interface{}{
		&models.User{},
		&models.Session{},
		&models.WhitelistedIP{},
	}

	for _, model := range models {
		if err := db.AutoMigrate(model); err != nil {
			return fmt.Errorf("failed to migrate %T: %w", model, err)
		}
	}

	log.Println("Database migrations completed successfully")
	return nil
}

// Close закрывает соединение с базой данных
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
