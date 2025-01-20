# Gateway Service

Защищённый веб-сервис (Gateway) с многофакторной аутентификацией и контролем доступа.

## Особенности

- Многофакторная аутентификация:
  - Google Authenticator (TOTP)
  - Cookie
  - Fingerprint устройства
- Контроль доступа по IP:
  - Поддержка статического разрешенного IP
  - Временный доступ для авторизованных устройств
- Защита от DDoS:
  - Rate limiting
  - Автоматическая блокировка при превышении лимита
- Безопасные сессии:
  - Secure cookies
  - Проверка fingerprint
  - Автоматическое истечение сессий

## Требования

- Go 1.21 или выше
- SQLite3
- Docker (опционально)

## Установка

### Локальная установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/your-username/gateway-service.git
cd gateway-service
```

2. Установите зависимости:
```bash
go mod download
```

3. Создайте первого пользователя:
```bash
go run cmd/createuser/main.go -login admin
```
Сохраните QR-код для Google Authenticator.

4. Запустите сервис:
```bash
go run cmd/server/main.go
```

### Docker установка

1. Соберите образ:
```bash
docker build -t gateway-service .
```

2. Запустите контейнер:
```bash
docker run -d \
  -p 8443:8443 \
  -v $(pwd)/data:/app/data \
  --name gateway \
  gateway-service
```

## Конфигурация

Основные настройки находятся в `internal/config/config.go`:

- `Server`: настройки HTTP сервера
- `Database`: настройки базы данных
- `Security`: параметры безопасности
- `RateLimit`: ограничения запросов

## API Endpoints

### Публичные endpoints

- `GET /login` - страница входа
- `POST /login` - аутентификация пользователя

### Защищенные endpoints

- `GET /status` - статус текущей сессии
- `POST /register-fingerprint` - регистрация нового fingerprint
- `GET /logout` - выход из системы

## Безопасность

- Все соединения должны использовать HTTPS
- Cookie устанавливаются с флагами Secure и HttpOnly
- Поддерживается SameSite=Strict для cookie
- IP-адреса проверяются на каждый запрос
- Сессии имеют ограниченное время жизни
- Используется rate limiting для защиты от DDoS

## Разработка

### Структура проекта

```
.
├── cmd/
│   └── server/          # Точка входа приложения
├── internal/
│   ├── auth/           # Аутентификация
│   ├── config/         # Конфигурация
│   ├── database/       # Работа с БД
│   ├── handlers/       # HTTP обработчики
│   ├── middleware/     # Middleware
│   └── models/         # Модели данных
├── web/
│   ├── static/         # Статические файлы
│   └── templates/      # HTML шаблоны
├── Dockerfile
└── README.md
```

### Тестирование

```bash
go test ./...
```

## Лицензия

MIT
