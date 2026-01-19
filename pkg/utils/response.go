package utils

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// Response standard format
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Meta    interface{} `json:"meta,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Meta information for pagination
type Meta struct {
	Page       int  `json:"page"`
	Limit      int  `json:"limit"`
	TotalItems int  `json:"total_items"`
	TotalPages int  `json:"total_pages"`
	HasNext    bool `json:"has_next"`
	HasPrev    bool `json:"has_prev"`
}

// SuccessResponse creates a successful response
func SuccessResponse(message string, data interface{}) Response {
	return Response{
		Success: true,
		Message: message,
		Data:    data,
	}
}

// SuccessResponseWithMeta creates a successful response with meta information
func SuccessResponseWithMeta(message string, data interface{}, meta Meta) Response {
	return Response{
		Success: true,
		Message: message,
		Data:    data,
		Meta:    meta,
	}
}

// ErrorResponse creates an error response
func ErrorResponse(message string) Response {
	return Response{
		Success: false,
		Message: message,
		Error:   message,
	}
}

// ValidationErrorResponse creates a validation error response
func ValidationErrorResponse(err error) Response {
	return Response{
		Success: false,
		Message: "Validation failed",
		Error:   err.Error(),
	}
}

// PaginatedResponse creates a paginated response
func PaginatedResponse(message string, data interface{}, page, limit, total int) Response {
	totalPages := total / limit
	if total%limit > 0 {
		totalPages++
	}

	meta := Meta{
		Page:       page,
		Limit:      limit,
		TotalItems: total,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}

	return Response{
		Success: true,
		Message: message,
		Data:    data,
		Meta:    meta,
	}
}

// JSON sends a JSON response with standard format
func JSON(c echo.Context, status int, response Response) error {
	return c.JSON(status, response)
}

// Success sends a success JSON response
func Success(c echo.Context, status int, message string, data interface{}) error {
	return c.JSON(status, SuccessResponse(message, data))
}

// Error sends an error JSON response
func Error(c echo.Context, status int, message string) error {
	return c.JSON(status, ErrorResponse(message))
}

// InternalServerError sends a 500 error response
func InternalServerError(c echo.Context, message string) error {
	return c.JSON(http.StatusInternalServerError, ErrorResponse(message))
}

// BadRequest sends a 400 error response
func BadRequest(c echo.Context, message string) error {
	return c.JSON(http.StatusBadRequest, ErrorResponse(message))
}

// Unauthorized sends a 401 error response
func Unauthorized(c echo.Context, message string) error {
	return c.JSON(http.StatusUnauthorized, ErrorResponse(message))
}

// Forbidden sends a 403 error response
func Forbidden(c echo.Context, message string) error {
	return c.JSON(http.StatusForbidden, ErrorResponse(message))
}

// NotFound sends a 404 error response
func NotFound(c echo.Context, message string) error {
	return c.JSON(http.StatusNotFound, ErrorResponse(message))
}

// Conflict sends a 409 error response
func Conflict(c echo.Context, message string) error {
	return c.JSON(http.StatusConflict, ErrorResponse(message))
}
