package routes

import (
	"auth-svc-ticketing/internal/infrastructure/http/handlers"
	"auth-svc-ticketing/internal/infrastructure/http/middleware"

	"github.com/labstack/echo/v4"
)

type AuthRoutes struct {
	handler *handlers.AuthHandler
	mw      *middleware.MiddlewareManager
}

func NewAuthRoutes(
	handler *handlers.AuthHandler,
	mw *middleware.MiddlewareManager,
) *AuthRoutes {
	return &AuthRoutes{
		handler: handler,
		mw:      mw,
	}
}

func (r *AuthRoutes) RegisterRoutes(e *echo.Group) {
	authGroup := e.Group("/auth")

	// Public routes
	authGroup.POST("/register", r.handler.Register)
	authGroup.POST("/login", r.handler.Login)
	authGroup.POST("/refresh", r.handler.RefreshToken)
	authGroup.POST("/forgot-password", r.handler.ForgotPassword)
	authGroup.POST("/reset-password", r.handler.ResetPassword)
	authGroup.POST("/verify-email", r.handler.VerifyEmail)

	// Protected routes (require authentication)
	protectedGroup := authGroup.Group("")
	protectedGroup.Use(r.mw.JWTMiddleware())
	protectedGroup.POST("/logout", r.handler.Logout)
	protectedGroup.GET("/profile", r.handler.GetProfile)
}
