FROM golang:1.21-alpine AS builder

# Установка необходимых зависимостей
RUN apk add --no-cache gcc musl-dev

# Установка рабочей директории
WORKDIR /app

# Копирование файлов проекта
COPY . .

# Сборка приложения
RUN go mod download
RUN CGO_ENABLED=1 GOOS=linux go build -a -o gateway ./cmd/server

FROM alpine:latest

# Установка необходимых пакетов
RUN apk add --no-cache ca-certificates tzdata

# Создание пользователя для запуска приложения
RUN adduser -D -g '' gateway

# Копирование бинарного файла из builder
COPY --from=builder /app/gateway /usr/local/bin/
COPY --from=builder /app/web /app/web

# Создание директории для базы данных и настройка прав
RUN mkdir -p /app/data && \
    chown -R gateway:gateway /app

# Переключение на непривилегированного пользователя
USER gateway

# Рабочая директория
WORKDIR /app

# Определение переменных окружения
ENV GIN_MODE=release

# Открытие порта
EXPOSE 8443

# Запуск приложения
CMD ["gateway"]
