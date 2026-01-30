// FILE: ./cmd/api/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	echoMw "github.com/labstack/echo/v4/middleware"

	"auth-svc-ticketing/internal/config"
	"auth-svc-ticketing/internal/infrastructure/http/routes"
	customLogger "auth-svc-ticketing/pkg/logger" // Alias untuk logger custom
	// Import zap untuk middleware logging jika diperlukan
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Initialize logger
	appLogger := customLogger.NewLogger(cfg.Server.Env)
	defer func() {
		if err := appLogger.Sync(); err != nil {
			log.Printf("Failed to sync logger: %v", err)
		}
	}()

	appLogger.Info("Starting Auth Service",
		"env", cfg.Server.Env,
		"port", cfg.Server.Port,
		"version", "1.0.0",
	)

	// Setup dependencies
	container, err := setupDependencies(cfg, appLogger)
	if err != nil {
		appLogger.Fatal("Failed to setup dependencies", err)
	}
	defer container.Close()

	// Create Echo instance
	e := echo.New()
	e.HideBanner = true

	// ================================
	// MIDDLEWARE BAWAAN ECHO
	// ================================
	e.Use(echoMw.Recover())
	e.Use(echoMw.CORSWithConfig(echoMw.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowHeaders: []string{
			echo.HeaderOrigin,
			echo.HeaderContentType,
			echo.HeaderAccept,
			echo.HeaderAuthorization,
			"X-Request-ID",
		},
		ExposeHeaders: []string{
			"X-Request-ID",
		},
		AllowCredentials: true,
		MaxAge:           86400,
	}))
	e.Use(echoMw.RequestID())
	e.Use(echoMw.GzipWithConfig(echoMw.GzipConfig{
		Level: 5,
	}))

	// Gunakan EchoLogger dari logger custom
	e.Use(appLogger.EchoLogger())

	// Rate limiting dengan middleware Echo
	e.Use(echoMw.RateLimiterWithConfig(echoMw.RateLimiterConfig{
		Skipper: echoMw.DefaultSkipper,
		Store: echoMw.NewRateLimiterMemoryStoreWithConfig(
			echoMw.RateLimiterMemoryStoreConfig{
				Rate:      10,
				Burst:     30,
				ExpiresIn: 3 * time.Minute,
			},
		),
		IdentifierExtractor: func(ctx echo.Context) (string, error) {
			id := ctx.RealIP()
			return id, nil
		},
		ErrorHandler: func(context echo.Context, err error) error {
			return context.JSON(http.StatusTooManyRequests,
				map[string]interface{}{
					"success": false,
					"message": "Too many requests",
					"error":   "Rate limit exceeded",
				})
		},
		DenyHandler: func(context echo.Context, identifier string, err error) error {
			return context.JSON(http.StatusTooManyRequests,
				map[string]interface{}{
					"success": false,
					"message": "Too many requests",
					"error":   "Rate limit exceeded",
				})
		},
	}))

	// ================================
	// SETUP ROUTES
	// ================================
	setupRoutes(e, container, appLogger)

	// Graceful shutdown setup
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		appLogger.Info("Starting server", "port", cfg.Server.Port)
		serverAddr := ":" + cfg.Server.Port
		appLogger.Info("Server listening", "address", serverAddr)

		if err := e.Start(serverAddr); err != nil && err != http.ErrServerClosed {
			appLogger.Fatal("Failed to start server", err)
		}
	}()

	// Wait for interrupt signal
	<-quit
	appLogger.Info("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown Echo server
	if err := e.Shutdown(ctx); err != nil {
		appLogger.Error("Server shutdown failed", err)
	}

	appLogger.Info("Server exited gracefully")
}

// setupDependencies - Setup semua dependencies
func setupDependencies(cfg *config.Config, logger *customLogger.Logger) (*config.Container, error) {
	// Initialize container dengan database
	container, err := config.NewContainer(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to setup container: %w", err)
	}

	return container, nil
}

// setupRoutes - Setup semua routes
func setupRoutes(e *echo.Echo, container *config.Container, logger *customLogger.Logger) {
	// Setup route container
	routeContainer := &routes.Container{
		AuthHandler:   container.AuthHandler,
		HealthHandler: container.HealthHandler,
		Middleware:    container.Middleware,
		Logger:        logger,
	}

	routes.SetupRoutes(e, routeContainer)
	logger.Info("Routes setup completed")
}
