package middleware

import (
	"net/http"
	"strings"

	"auth-svc-ticketing/internal/core/ports"
	"auth-svc-ticketing/pkg/logger"

	"github.com/labstack/echo/v4"
)

// AuthMiddleware - Middleware kustom untuk authentication
type AuthMiddleware struct {
	jwtManager ports.JWTManager
	logger     *logger.Logger
}

func NewAuthMiddleware(jwtManager ports.JWTManager, logger *logger.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager: jwtManager,
		logger:     logger,
	}
}

// JWTMiddleware - Memeriksa dan validasi JWT token
func (m *AuthMiddleware) JWTMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token, err := extractTokenFromHeader(c)
			if err != nil {
				m.logger.Warn("Failed to extract token", "error", err)
				return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
			}

			claims, err := m.jwtManager.Verify(token)
			if err != nil {
				m.logger.Warn("Invalid token", "error", err)
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid or expired token")
			}

			// Set user info in context
			c.Set("user_id", claims.UserID)
			c.Set("user_email", claims.Email)
			c.Set("user_roles", claims.Roles)

			m.logger.Debug("User authenticated",
				"user_id", claims.UserID,
				"path", c.Path(),
			)

			return next(c)
		}
	}
}

// RequireRole - Middleware untuk memeriksa role user
func (m *AuthMiddleware) RequireRole(requiredRole string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			roles, ok := c.Get("user_roles").([]string)
			if !ok {
				return echo.NewHTTPError(http.StatusForbidden, "Access denied")
			}

			hasRole := false
			for _, role := range roles {
				if role == requiredRole {
					hasRole = true
					break
				}
			}

			if !hasRole {
				m.logger.Warn("Role check failed",
					"user_id", c.Get("user_id"),
					"required_role", requiredRole,
					"user_roles", roles,
				)
				return echo.NewHTTPError(http.StatusForbidden, "Insufficient permissions")
			}

			return next(c)
		}
	}
}

// Helper function untuk extract token
func extractTokenFromHeader(c echo.Context) (string, error) {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization header format")
	}

	return parts[1], nil
}
