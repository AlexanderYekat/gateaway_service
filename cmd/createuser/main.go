package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"gateaway_service/internal/auth"
	"gateaway_service/internal/config"
	"gateaway_service/internal/database"
	"gateaway_service/internal/models"

	"github.com/mdp/qrterminal/v3"
)

func main() {
	// Парсинг аргументов командной строки
	login := flag.String("login", "", "Логин пользователя")
	flag.Parse()

	if *login == "" {
		log.Fatal("Необходимо указать логин пользователя через флаг -login")
	}

	// Загрузка конфигурации
	cfg := config.DefaultConfig()

	// Инициализация базы данных
	db, err := database.New(&cfg.Database)
	if err != nil {
		log.Fatalf("Ошибка инициализации базы данных: %v", err)
	}

	// Инициализация сервиса аутентификации
	authService := auth.New(&cfg.Security)

	// Проверка существования пользователя
	var existingUser models.User
	if err := db.Where("login = ?", *login).First(&existingUser).Error; err == nil {
		log.Fatalf("Пользователь с логином %s уже существует", *login)
	}

	// Генерация TOTP секрета и URL для QR-кода
	secret, totpURL, err := authService.GenerateTOTPSecret(*login)
	if err != nil {
		log.Fatalf("Ошибка генерации TOTP секрета: %v", err)
	}

	// Создание пользователя
	user := models.User{
		Login:      *login,
		TOTPSecret: secret,
	}

	if err := db.Create(&user).Error; err != nil {
		log.Fatalf("Ошибка создания пользователя: %v", err)
	}

	// Вывод информации
	fmt.Printf("Пользователь %s успешно создан\n", *login)
	fmt.Printf("TOTP Secret: %s\n\n", secret)
	fmt.Println("Отсканируйте QR-код в Google Authenticator:")
	fmt.Println()

	// Генерация QR-кода в терминале
	qrterminal.GenerateWithConfig(totpURL, qrterminal.Config{
		Level:     qrterminal.L,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: 1,
	})

	fmt.Println("\nСохраните TOTP Secret в надежном месте!")
}
