package middleware

import (
	"time"

	"auth-svc-ticketing/pkg/logger"

	"github.com/labstack/echo/v4"
)

// RequestLogger - Middleware kustom untuk logging request
func RequestLogger(logger *logger.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()

			// Process request
			err := next(c)

			// Log after request is processed
			duration := time.Since(start)

			status := c.Response().Status
			method := c.Request().Method
			path := c.Request().URL.Path
			clientIP := c.RealIP()

			logFields := []interface{}{
				"method", method,
				"path", path,
				"status", status,
				"duration", duration.String(),
				"client_ip", clientIP,
				"user_agent", c.Request().UserAgent(),
			}

			// Add request ID if available
			if reqID := c.Response().Header().Get(echo.HeaderXRequestID); reqID != "" {
				logFields = append(logFields, "request_id", reqID)
			}

			// Log based on status code
			if status >= 500 {
				logger.Error("Server error", err, logFields...)
			} else if status >= 400 {
				logger.Warn("Client error", logFields...)
			} else {
				logger.Info("Request completed", logFields...)
			}

			return err
		}
	}
}
