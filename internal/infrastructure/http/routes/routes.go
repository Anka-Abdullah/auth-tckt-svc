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
	Middleware    *middleware.AuthMiddleware // Perbaikan tipe
	Logger        *logger.Logger
}

// SetupRoutes - Setup semua routes
func SetupRoutes(e *echo.Echo, container *Container) {
	// Health check route
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(200, map[string]string{"status": "healthy"})
	})

	// API v1 group
	api := e.Group("/api/v1")

	// Auth routes
	setupAuthRoutes(api, container)

	if container.Logger != nil {
		container.Logger.Info("Routes setup completed")
	}
}

// setupAuthRoutes - Setup auth routes
func setupAuthRoutes(group *echo.Group, container *Container) {
	// Public routes
	group.POST("/auth/register", container.AuthHandler.Register)
	group.POST("/auth/login", container.AuthHandler.Logout) // Ganti dengan handler yang sesuai
	group.POST("/auth/refresh", container.AuthHandler.Logout)
	group.POST("/auth/forgot-password", container.AuthHandler.Logout)
	group.POST("/auth/reset-password", container.AuthHandler.Logout)
	group.POST("/auth/verify-email", container.AuthHandler.Logout)

	// Protected routes
	protected := group.Group("")
	if container.Middleware != nil {
		protected.Use(container.Middleware.JWTMiddleware())
	}

	protected.POST("/auth/logout", container.AuthHandler.Logout)
	protected.GET("/auth/profile", container.AuthHandler.Logout)
}
