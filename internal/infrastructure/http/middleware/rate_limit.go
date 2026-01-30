package middleware

import (
	"fmt"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
)

// RateLimiter - Middleware kustom untuk rate limiting
type RateLimiter struct {
	requests    map[string][]time.Time
	mu          sync.RWMutex
	maxRequests int
	window      time.Duration
}

func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests:    make(map[string][]time.Time),
		maxRequests: maxRequests,
		window:      window,
	}
}

func (rl *RateLimiter) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			clientIP := c.RealIP()

			rl.mu.Lock()
			defer rl.mu.Unlock()

			now := time.Now()

			// Clean old requests
			var validRequests []time.Time
			for _, reqTime := range rl.requests[clientIP] {
				if now.Sub(reqTime) <= rl.window {
					validRequests = append(validRequests, reqTime)
				}
			}

			// Check rate limit
			if len(validRequests) >= rl.maxRequests {
				// Set rate limit headers
				c.Response().Header().Set("X-RateLimit-Limit", fmt.Sprint(rl.maxRequests))
				c.Response().Header().Set("X-RateLimit-Remaining", "0")
				c.Response().Header().Set("X-RateLimit-Reset",
					time.Now().Add(rl.window).Format(time.RFC3339))

				return echo.NewHTTPError(429, "Too many requests")
			}

			// Add current request
			validRequests = append(validRequests, now)
			rl.requests[clientIP] = validRequests

			// Set rate limit headers
			remaining := rl.maxRequests - len(validRequests)
			c.Response().Header().Set("X-RateLimit-Limit", fmt.Sprint(rl.maxRequests))
			c.Response().Header().Set("X-RateLimit-Remaining", fmt.Sprint(remaining))
			c.Response().Header().Set("X-RateLimit-Reset",
				time.Now().Add(rl.window).Format(time.RFC3339))

			return next(c)
		}
	}
}
