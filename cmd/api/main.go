package main

import (
	"context"
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
	"auth-svc-ticketing/pkg/logger"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Initialize logger
	appLogger := logger.NewLogger(cfg.Server.Env)
	defer appLogger.Sync()

	appLogger.Info("Starting Auth Service",
		"env", cfg.Server.Env,
		"port", cfg.Server.Port,
		"version", "1.0.0",
	)

	// Setup dependencies
	container, err := setupDependencies(cfg, appLogger)
	if err != nil {
		appLogger.Fatal("Failed to setup dependencies:", err)
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
			return context.JSON(http.StatusTooManyRequests, nil)
		},
		DenyHandler: func(context echo.Context, identifier string, err error) error {
			return context.JSON(http.StatusTooManyRequests, nil)
		},
	}))

	// ================================
	// SETUP ROUTES
	// ================================
	setupRoutes(e, container, appLogger)

	// Add readiness and liveness probes
	e.GET("/ready", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ready"})
	})

	e.GET("/live", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "alive"})
	})

	// Graceful shutdown setup
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		appLogger.Info("Starting server", "port", cfg.Server.Port)
		if err := e.Start(":" + cfg.Server.Port); err != nil && err != http.ErrServerClosed {
			appLogger.Fatal("Failed to start server:", err)
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
		appLogger.Error("Server shutdown failed:", err)
	}

	appLogger.Info("Server exited gracefully")
}

// setupDependencies - Setup semua dependencies
func setupDependencies(cfg *config.Config, logger *logger.Logger) (*config.Container, error) {
	// Ini adalah placeholder - implementasi nyata akan bergantung pada database, redis, dll.
	container := &config.Container{
		Config: cfg,
		Logger: logger,
		// Inisialisasi dependency lainnya di sini
	}

	return container, nil
}

// setupRoutes - Setup semua routes
func setupRoutes(e *echo.Echo, container *config.Container, logger *logger.Logger) {
	// Setup route container
	routeContainer := &routes.Container{
		// Handler dan middleware akan diinisialisasi di sini
		Logger: logger,
	}

	routes.SetupRoutes(e, routeContainer)
	logger.Info("Routes setup completed")
}

// Handler placeholder
func healthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "healthy"})
}

func readinessCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ready"})
}
