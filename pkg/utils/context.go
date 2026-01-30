package utils

import (
	"context"
	"time"

	"github.com/labstack/echo/v4"
)

// Context keys
type contextKey string

const (
	UserIDKey    contextKey = "user_id"
	UserEmailKey contextKey = "user_email"
	UserRolesKey contextKey = "user_roles"
	RequestIDKey contextKey = "request_id"
	TraceIDKey   contextKey = "trace_id"
)

// SetContextValue sets a value in context
func SetContextValue(c echo.Context, key contextKey, value interface{}) {
	c.Set(string(key), value)
}

// GetContextValue gets a value from context
func GetContextValue(c echo.Context, key contextKey) interface{} {
	return c.Get(string(key))
}

// GetUserIDFromContext gets user ID from context
func GetUserIDFromContext(c echo.Context) string {
	if userID, ok := GetContextValue(c, UserIDKey).(string); ok {
		return userID
	}
	return ""
}

// GetUserEmailFromContext gets user email from context
func GetUserEmailFromContext(c echo.Context) string {
	if email, ok := GetContextValue(c, UserEmailKey).(string); ok {
		return email
	}
	return ""
}

// GetUserRolesFromContext gets user roles from context
func GetUserRolesFromContext(c echo.Context) []string {
	if roles, ok := GetContextValue(c, UserRolesKey).([]string); ok {
		return roles
	}
	return []string{}
}

// GetRequestIDFromContext gets request ID from context
func GetRequestIDFromContext(c echo.Context) string {
	if requestID, ok := GetContextValue(c, RequestIDKey).(string); ok {
		return requestID
	}
	return ""
}

// HasRole checks if user has specific role
func HasRole(c echo.Context, role string) bool {
	roles := GetUserRolesFromContext(c)
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if user has any of the specified roles
func HasAnyRole(c echo.Context, requiredRoles ...string) bool {
	userRoles := GetUserRolesFromContext(c)
	for _, userRole := range userRoles {
		for _, requiredRole := range requiredRoles {
			if userRole == requiredRole {
				return true
			}
		}
	}
	return false
}

// HasAllRoles checks if user has all specified roles
func HasAllRoles(c echo.Context, requiredRoles ...string) bool {
	userRoles := GetUserRolesFromContext(c)
	rolesMap := make(map[string]bool)

	for _, role := range userRoles {
		rolesMap[role] = true
	}

	for _, requiredRole := range requiredRoles {
		if !rolesMap[requiredRole] {
			return false
		}
	}

	return true
}

// WithTimeout creates context with timeout
func WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

// WithValues copies context with new values
func WithValues(parent context.Context, values map[interface{}]interface{}) context.Context {
	for key, value := range values {
		parent = context.WithValue(parent, key, value)
	}
	return parent
}
