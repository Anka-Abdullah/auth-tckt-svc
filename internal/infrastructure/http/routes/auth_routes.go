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

	// OTP routes
	authGroup.POST("/register-with-otp", r.handler.RegisterWithOTP)
	authGroup.POST("/verify-otp", r.handler.VerifyOTP)
	authGroup.POST("/resend-otp", r.handler.ResendOTP)
	authGroup.POST("/login-with-otp", r.handler.LoginWithOTP)
	authGroup.POST("/verify-login-otp", r.handler.VerifyLoginOTP)

	// Protected routes (require authentication)
	protectedGroup := authGroup.Group("")
	protectedGroup.Use(r.mw.JWTMiddleware())
	protectedGroup.POST("/logout", r.handler.Logout)
	protectedGroup.GET("/profile", r.handler.GetProfile)
}
