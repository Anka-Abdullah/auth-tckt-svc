// FILE: ./internal/config/container.go
package config

import (
	"auth-svc-ticketing/internal/application/services"
	"auth-svc-ticketing/internal/core/ports"
	"auth-svc-ticketing/internal/infrastructure/http/handlers"
	"auth-svc-ticketing/internal/infrastructure/http/middleware"
	"auth-svc-ticketing/internal/infrastructure/mailer"
	postgresRepo "auth-svc-ticketing/internal/infrastructure/persistence/postgres"
	"auth-svc-ticketing/internal/infrastructure/persistence/redisrepo"
	"auth-svc-ticketing/internal/infrastructure/security"
	customLogger "auth-svc-ticketing/pkg/logger"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

type Container struct {
	Config        *Config
	Logger        *customLogger.Logger
	DB            *gorm.DB
	RedisClient   *redis.Client
	UserRepo      ports.UserRepository
	TokenRepo     ports.TokenRepository
	JWTManager    ports.JWTManager
	PasswordMgr   ports.PasswordManager
	Mailer        ports.Mailer
	AuthService   ports.AuthService
	OTPService    ports.OTPService
	AuthHandler   *handlers.AuthHandler
	HealthHandler *handlers.HealthHandler
	Middleware    *middleware.MiddlewareManager

	closers []func()
}

func NewContainer(cfg *Config, logger *customLogger.Logger) (*Container, error) {
	container := &Container{
		Config: cfg,
		Logger: logger,
	}

	// 1. Initialize Database
	db, err := InitializeDatabase(cfg, logger)
	if err != nil {
		return nil, err
	}
	container.DB = db

	// 2. Initialize Redis
	redisClient, err := InitializeRedis(cfg, logger)
	if err != nil {
		return nil, err
	}
	container.RedisClient = redisClient

	// 3. Initialize Repositories
	container.UserRepo = postgresRepo.NewUserRepository(container.DB)
	container.TokenRepo = redisrepo.NewTokenRepository(redisClient)

	// 4. Initialize Mailer (gunakan fungsi yang benar)
	mailerConfig := &mailer.Config{
		Host:     cfg.SMTP.Host,
		Port:     cfg.SMTP.Port,
		Username: cfg.SMTP.Username,
		Password: cfg.SMTP.Password,
		From:     cfg.SMTP.From,
	}
	container.Mailer = mailer.NewMailer(mailerConfig, logger)

	// 5. Initialize Security Components
	container.JWTManager = security.NewJWTManager(
		cfg.JWT.SecretKey,
		cfg.JWT.AccessExpiry,
		cfg.JWT.RefreshExpiry,
	)
	container.PasswordMgr = security.NewPasswordManager()

	// 6. Create OTP service dengan mailer
	otpService := services.NewOTPService(container.TokenRepo, container.Mailer, logger)
	container.OTPService = otpService

	// 7. Create Auth service dengan OTP service
	container.AuthService = services.NewAuthService(
		container.UserRepo,
		container.TokenRepo,
		container.JWTManager,
		container.PasswordMgr,
		otpService,
		container.Mailer, // Tambahkan mailer ke auth service
		logger,
	)

	// 8. Initialize Handlers
	container.AuthHandler = handlers.NewAuthHandler(
		container.AuthService,
		otpService,
		logger,
	)

	// 9. Initialize Middleware
	container.Middleware = middleware.NewMiddlewareManager(
		container.JWTManager,
		logger,
	)

	// 10. Initialize Health Handler
	container.HealthHandler = handlers.NewHealthHandler(
		logger,
		container.DB,
		container.RedisClient,
	)

	// Add closers
	container.closers = append(container.closers, func() {
		sqlDB, err := container.DB.DB()
		if err == nil {
			sqlDB.Close()
			logger.Info("Database connection closed")
		}
	})

	container.closers = append(container.closers, func() {
		if err := redisClient.Close(); err != nil {
			logger.Error("Failed to close Redis connection", err)
		} else {
			logger.Info("Redis connection closed")
		}
	})

	logger.Info("Container initialized successfully")
	return container, nil
}

// Close method untuk cleanup
func (c *Container) Close() {
	for _, closer := range c.closers {
		closer()
	}
}
