package middleware

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func (m *AuthMiddleware) AdminMiddleware() echo.MiddlewareFunc {
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
