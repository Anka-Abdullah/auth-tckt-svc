package config

import (
	"context"
	"fmt"
	"log"
	"time"

	"auth-svc-ticketing/internal/application/services"
	"auth-svc-ticketing/internal/core/domain"
	"auth-svc-ticketing/internal/core/ports"
	"auth-svc-ticketing/internal/infrastructure/http/handlers"
	"auth-svc-ticketing/internal/infrastructure/http/middleware"
	"auth-svc-ticketing/internal/infrastructure/persistence/postgres"
	"auth-svc-ticketing/internal/infrastructure/persistence/redisrepo"
	"auth-svc-ticketing/internal/infrastructure/security"
	"auth-svc-ticketing/pkg/logger"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

type Container struct {
	Config        *Config
	Logger        *logger.Logger
	DB            *gorm.DB
	RedisClient   *redis.Client
	UserRepo      ports.UserRepository
	TokenRepo     ports.TokenRepository
	JWTManager    ports.JWTManager
	PasswordMgr   ports.PasswordManager
	AuthService   ports.AuthService
	OTPService    ports.OTPService
	AuthHandler   *handlers.AuthHandler
	HealthHandler *handlers.HealthHandler
	Middleware    *middleware.MiddlewareManager

	closers []func()
}

func NewContainer(cfg *Config, logger *logger.Logger) (*Container, error) {
	container := &Container{
		Config: cfg,
		Logger: logger,
	}

	// 1. Initialize Database
	db, err := InitializeDatabase(cfg, logger)
	if err != nil {
		return nil, err
	}
	container.DB = db.DB

	// 2. Initialize Redis
	redisClient, err := InitializeRedis(cfg, logger)
	if err != nil {
		return nil, err
	}
	container.RedisClient = redisClient

	// 3. Initialize Repositories
	container.UserRepo = postgres.NewUserRepository(db.DB)
	container.TokenRepo = redisrepo.NewTokenRepository(redisClient)

	// 4. Initialize Security Components
	container.JWTManager = security.NewJWTManager(
		cfg.JWT.SecretKey,
		cfg.JWT.AccessExpiry,
		cfg.JWT.RefreshExpiry,
	)
	container.PasswordMgr = security.NewPasswordManager()

	// 5. Initialize Services
	dummyMailer := &DummyMailer{}

	// Create OTP service first
	otpService := services.NewOTPService(container.TokenRepo, dummyMailer, logger)
	container.OTPService = otpService

	// Create Auth service with OTP service
	container.AuthService = services.NewAuthService(
		container.UserRepo,
		container.TokenRepo,
		container.JWTManager,
		container.PasswordMgr,
		dummyMailer,
		otpService,
		logger,
	)

	// 6. Initialize Handlers
	container.AuthHandler = handlers.NewAuthHandler(
		container.AuthService,
		otpService,
		logger,
	)

	// 7. Initialize Middleware
	container.Middleware = middleware.NewMiddlewareManager(
		container.JWTManager,
		logger,
	)

	// 8. Initialize Health Handler
	container.HealthHandler = handlers.NewHealthHandler(
		logger,
		container.DB,
		container.RedisClient,
	)

	// Add closers
	container.closers = append(container.closers, func() {
		sqlDB, err := db.DB.DB()
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

func (c *Container) Close() {
	for _, closer := range c.closers {
		closer()
	}
	c.Logger.Info("Container closed successfully")
}

// InitializeRedis initializes Redis connection
func InitializeRedis(cfg *Config, logger *logger.Logger) (*redis.Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Host + ":" + cfg.Redis.Port,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info("Redis connection established")
	return rdb, nil
}

// Dummy mailer for development
type DummyMailer struct{}

func (d *DummyMailer) SendVerificationEmail(user *domain.User, token string) error {
	log.Printf("Verification email sent to %s with token: %s\n", user.Email, token)
	return nil
}

func (d *DummyMailer) SendPasswordResetEmail(email, token string) error {
	log.Printf("Password reset email sent to %s with token: %s\n", email, token)
	return nil
}

func (d *DummyMailer) SendWelcomeEmail(user *domain.User) error {
	log.Printf("Welcome email sent to %s\n", user.Email)
	return nil
}
