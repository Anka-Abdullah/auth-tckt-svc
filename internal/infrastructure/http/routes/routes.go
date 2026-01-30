package routes

import (
	"auth-svc-ticketing/internal/infrastructure/http/handlers"
	"auth-svc-ticketing/internal/infrastructure/http/middleware"
	"auth-svc-ticketing/pkg/logger"

	"github.com/labstack/echo/v4"
)

// Container struct
type Container struct {
	AuthHandler   *handlers.AuthHandler
	HealthHandler *handlers.HealthHandler
	Middleware    *middleware.MiddlewareManager
	Logger        *logger.Logger
}

// SetupRoutes - Setup semua routes
func SetupRoutes(e *echo.Echo, container *Container) {
	// Health check route
	if container.HealthHandler != nil {
		e.GET("/health", container.HealthHandler.HealthCheck)
	} else {
		e.GET("/health", func(c echo.Context) error {
			return c.JSON(200, map[string]string{"status": "healthy"})
		})
	}

	e.GET("/ready", func(c echo.Context) error {
		return c.JSON(200, map[string]string{"status": "ready"})
	})

	e.GET("/live", func(c echo.Context) error {
		return c.JSON(200, map[string]string{"status": "alive"})
	})

	// API v1 group
	api := e.Group("/api/v1")

	// Setup auth routes dengan routes manager
	if container.AuthHandler != nil && container.Middleware != nil {
		authRoutes := NewAuthRoutes(container.AuthHandler, container.Middleware)
		authRoutes.RegisterRoutes(api)
	}

	if container.Logger != nil {
		container.Logger.Info("Routes setup completed")
	}
}
