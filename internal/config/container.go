package config

import (
	"auth-svc-ticketing/internal/infrastructure/http/handlers"
	"auth-svc-ticketing/internal/infrastructure/http/middleware"
	"auth-svc-ticketing/pkg/logger"
)

type Container struct {
	Config        *Config
	Logger        *logger.Logger
	AuthHandler   *handlers.AuthHandler
	HealthHandler *handlers.HealthHandler
	Middleware    *middleware.MiddlewareManager
	// Add other dependencies (repositories, services, etc.)

	// Closers for graceful shutdown
	closers []func()
}

func NewContainer(cfg *Config, logger *logger.Logger) (*Container, error) {
	container := &Container{
		Config: cfg,
		Logger: logger,
	}

	// Initialize dependencies in correct order
	// 1. Infrastructure (DB, Redis, etc.)
	// 2. Repositories
	// 3. Services
	// 4. Handlers & Middleware

	// Example initialization (you'll need to implement actual constructors):
	/*
	   db := initDatabase(cfg)
	   redis := initRedis(cfg)

	   userRepo := persistence.NewUserRepository(db)
	   tokenRepo := persistence.NewTokenRepository(redis)

	   jwtManager := security.NewJWTManager(cfg.JWT.SecretKey, cfg.JWT.AccessExpiry)
	   passwordManager := security.NewPasswordManager()

	   authService := services.NewAuthService(userRepo, tokenRepo, jwtManager, passwordManager)

	   container.AuthHandler = handlers.NewAuthHandler(authService, logger)
	   container.Middleware = middleware.NewMiddlewareManager(jwtManager, logger)
	   container.HealthHandler = handlers.NewHealthHandler(logger, db, redis)

	   // Add closers
	   container.closers = append(container.closers, func() {
	       db.Close()
	       redis.Close()
	   })
	*/

	return container, nil
}

func (c *Container) Close() {
	for _, closer := range c.closers {
		closer()
	}
	c.Logger.Info("Container closed successfully")
}
