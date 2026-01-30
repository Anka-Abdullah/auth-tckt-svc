package utils

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/labstack/echo/v4"
)

// Custom error types
var (
	ErrNotFound           = NewAppError("not found", http.StatusNotFound)
	ErrUnauthorized       = NewAppError("unauthorized", http.StatusUnauthorized)
	ErrForbidden          = NewAppError("forbidden", http.StatusForbidden)
	ErrBadRequest         = NewAppError("bad request", http.StatusBadRequest)
	ErrValidation         = NewAppError("validation error", http.StatusBadRequest)
	ErrConflict           = NewAppError("conflict", http.StatusConflict)
	ErrInternal           = NewAppError("internal server error", http.StatusInternalServerError)
	ErrTooManyRequests    = NewAppError("too many requests", http.StatusTooManyRequests)
	ErrServiceUnavailable = NewAppError("service unavailable", http.StatusServiceUnavailable)
)

// AppError represents application error
type AppError struct {
	Code     int                    `json:"code"`
	Message  string                 `json:"message"`
	Err      error                  `json:"-"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Stack    []string               `json:"stack,omitempty"`
}

// NewAppError creates a new AppError
func NewAppError(message string, code int) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
	}
}

// Error implements error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// WithError adds underlying error
func (e *AppError) WithError(err error) *AppError {
	e.Err = err
	return e
}

// WithMetadata adds metadata
func (e *AppError) WithMetadata(metadata map[string]interface{}) *AppError {
	e.Metadata = metadata
	return e
}

// WithStack adds stack trace
func (e *AppError) WithStack() *AppError {
	e.Stack = getStackTrace()
	return e
}

// IsAppError checks if error is AppError
func IsAppError(err error) bool {
	var appErr *AppError
	return errors.As(err, &appErr)
}

// GetAppError extracts AppError from error
func GetAppError(err error) *AppError {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}
	return nil
}

// WrapError wraps an error with message
func WrapError(err error, message string) error {
	if err == nil {
		return nil
	}

	if appErr := GetAppError(err); appErr != nil {
		appErr.Message = fmt.Sprintf("%s: %s", message, appErr.Message)
		return appErr
	}

	return fmt.Errorf("%s: %w", message, err)
}

// HandleError handles error for HTTP response
func HandleError(c echo.Context, err error) error {
	if err == nil {
		return nil
	}

	// Check if it's already an AppError
	if appErr := GetAppError(err); appErr != nil {
		// Log the error if it's a server error
		if appErr.Code >= http.StatusInternalServerError {
			// Get logger from context if available
			if logger, ok := c.Get("logger").(interface {
				Error(string, error, ...interface{})
			}); ok {
				logger.Error("Server error", err,
					"path", c.Path(),
					"method", c.Request().Method,
					"status", appErr.Code,
				)
			}
		}

		return c.JSON(appErr.Code, Response{
			Success: false,
			Message: appErr.Message,
			Error:   appErr.Error(),
		})
	}

	// Handle validation errors
	if strings.Contains(err.Error(), "validation") {
		return BadRequest(c, err.Error())
	}

	// Default to internal server error
	return InternalServerError(c, "Something went wrong")
}

// Get stack trace
func getStackTrace() []string {
	var stack []string
	for i := 1; ; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}

		// Skip runtime and testing files
		if strings.Contains(file, "runtime/") ||
			strings.Contains(file, "testing/") ||
			strings.Contains(file, "vendor/") {
			continue
		}

		funcName := runtime.FuncForPC(pc).Name()
		stack = append(stack, fmt.Sprintf("%s:%d %s", file, line, funcName))
	}

	return stack
}

// PanicRecovery recovers from panic and logs
func PanicRecovery() {
	if r := recover(); r != nil {
		stack := getStackTrace()
		// Log the panic with stack trace
		fmt.Printf("PANIC RECOVERED: %v\nSTACK TRACE:\n%s\n",
			r, strings.Join(stack, "\n"))
	}
}
