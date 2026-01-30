// FILE: ./internal/config/config.go
package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// getEnv helper function
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvRequired helper function for required environment variables
func getEnvRequired(key, description string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("configuration error: %s - required environment variable %s is not set", description, key)
	}
	return value, nil
}

type Config struct {
	Server      ServerConfig
	DatabaseURL string // PostgreSQL connection URL
	RedisURL    string // Redis connection URL
	JWT         JWTConfig
	SMTP        SMTPConfig
	App         AppConfig
}

type ServerConfig struct {
	Port         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	Env          string
}

type JWTConfig struct {
	SecretKey     string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type AppConfig struct {
	Name        string
	Version     string
	BaseURL     string
	FrontendURL string
}

func LoadConfig() (*Config, error) {
	// Load .env file if exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Parse timeouts
	readTimeout, _ := strconv.Atoi(getEnv("READ_TIMEOUT", "10"))
	writeTimeout, _ := strconv.Atoi(getEnv("WRITE_TIMEOUT", "10"))

	// Parse JWT expiry
	accessExpiry, _ := strconv.Atoi(getEnv("JWT_ACCESS_EXPIRY", "3600"))
	refreshExpiry, _ := strconv.Atoi(getEnv("JWT_REFRESH_EXPIRY", "604800"))

	// Parse SMTP Port
	smtpPort, _ := strconv.Atoi(getEnv("SMTP_PORT", "587"))

	// Get required database URL - langsung dari env
	databaseURL, err := getEnvRequired("DATABASE_URL", "PostgreSQL database connection URL")
	if err != nil {
		return nil, err
	}

	// Get required Redis URL - langsung dari env
	redisURL, err := getEnvRequired("REDIS_URL", "Redis cache connection URL")
	if err != nil {
		return nil, err
	}

	// Get required JWT secret
	jwtSecret, err := getEnvRequired("JWT_SECRET", "JWT signing key")
	if err != nil {
		return nil, err
	}

	return &Config{
		Server: ServerConfig{
			Port:         getEnv("PORT", "8080"),
			ReadTimeout:  time.Duration(readTimeout) * time.Second,
			WriteTimeout: time.Duration(writeTimeout) * time.Second,
			Env:          getEnv("ENV", "development"),
		},
		DatabaseURL: databaseURL,
		RedisURL:    redisURL,
		JWT: JWTConfig{
			SecretKey:     jwtSecret,
			AccessExpiry:  time.Duration(accessExpiry) * time.Second,
			RefreshExpiry: time.Duration(refreshExpiry) * time.Second,
		},
		SMTP: SMTPConfig{
			Host:     getEnv("SMTP_HOST", ""),
			Port:     smtpPort,
			Username: getEnv("SMTP_USERNAME", ""),
			Password: getEnv("SMTP_PASSWORD", ""),
			From:     getEnv("SMTP_FROM", "noreply@example.com"),
		},
		App: AppConfig{
			Name:        getEnv("APP_NAME", "Auth Service"),
			Version:     getEnv("APP_VERSION", "1.0.0"),
			BaseURL:     getEnv("BASE_URL", "http://localhost:8080"),
			FrontendURL: getEnv("FRONTEND_URL", "http://localhost:3000"),
		},
	}, nil
}
