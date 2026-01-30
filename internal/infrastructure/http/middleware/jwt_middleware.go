package middleware

import (
	"auth-svc-ticketing/internal/core/ports"
	"auth-svc-ticketing/pkg/logger"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

type MiddlewareManager struct {
	jwtManager ports.JWTManager
	logger     *logger.Logger
}

func NewMiddlewareManager(
	jwtManager ports.JWTManager,
	logger *logger.Logger,
) *MiddlewareManager {
	return &MiddlewareManager{
		jwtManager: jwtManager,
		logger:     logger,
	}
}

func (m *MiddlewareManager) JWTMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get token from header
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				m.logger.Warn("Missing authorization header")
				return echo.NewHTTPError(http.StatusUnauthorized, "Missing authorization header")
			}

			// Check Bearer prefix
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				m.logger.Warn("Invalid authorization header format")
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization header format")
			}

			token := parts[1]

			// Verify token
			claims, err := m.jwtManager.Verify(token)
			if err != nil {
				m.logger.Warn("Invalid token", "error", err)
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid or expired token")
			}

			// Set user info in context
			c.Set("user_id", claims.UserID)
			c.Set("user_email", claims.Email)
			c.Set("user_roles", claims.Roles)
			c.Set("access_token", token)

			m.logger.Debug("JWT validated",
				"user_id", claims.UserID,
				"email", claims.Email,
			)

			return next(c)
		}
	}
}

func (m *MiddlewareManager) AdminMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			roles, ok := c.Get("user_roles").([]string)
			if !ok {
				return echo.NewHTTPError(http.StatusForbidden, "Invalid user roles")
			}

			// Check if user has admin role
			hasAdminRole := false
			for _, role := range roles {
				if role == "admin" {
					hasAdminRole = true
					break
				}
			}

			if !hasAdminRole {
				m.logger.Warn("Admin access denied",
					"user_id", c.Get("user_id"),
					"roles", roles,
				)
				return echo.NewHTTPError(http.StatusForbidden, "Admin access required")
			}

			return next(c)
		}
	}
}
