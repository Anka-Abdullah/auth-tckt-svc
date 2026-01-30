package utils

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
)

// PaginationQuery holds pagination parameters
type PaginationQuery struct {
	Page    int    `json:"page"`
	Limit   int    `json:"limit"`
	SortBy  string `json:"sort_by"`
	SortDir string `json:"sort_dir"` // asc or desc
	Search  string `json:"search"`
}

// DefaultPagination returns default pagination values
func DefaultPagination() PaginationQuery {
	return PaginationQuery{
		Page:    1,
		Limit:   10,
		SortBy:  "created_at",
		SortDir: "desc",
		Search:  "",
	}
}

// GetPaginationFromQuery extracts pagination from query parameters
func GetPaginationFromQuery(c echo.Context) PaginationQuery {
	query := DefaultPagination()

	// Get page
	if pageStr := c.QueryParam("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			query.Page = page
		}
	}

	// Get limit
	if limitStr := c.QueryParam("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 100 {
			query.Limit = limit
		}
	}

	// Get sort by
	if sortBy := c.QueryParam("sort_by"); sortBy != "" {
		query.SortBy = sortBy
	}

	// Get sort direction
	if sortDir := c.QueryParam("sort_dir"); sortDir != "" {
		if sortDir == "asc" || sortDir == "desc" {
			query.SortDir = sortDir
		}
	}

	// Get search
	if search := c.QueryParam("search"); search != "" {
		query.Search = search
	}

	return query
}

// CalculateOffset calculates offset for SQL query
func (p *PaginationQuery) Offset() int {
	return (p.Page - 1) * p.Limit
}

// Validate validates pagination parameters
func (p *PaginationQuery) Validate() error {
	if p.Page < 1 {
		return NewAppError("page must be greater than 0", http.StatusBadRequest)
	}

	if p.Limit < 1 || p.Limit > 100 {
		return NewAppError("limit must be between 1 and 100", http.StatusBadRequest)
	}

	if p.SortDir != "asc" && p.SortDir != "desc" {
		return NewAppError("sort_dir must be 'asc' or 'desc'", http.StatusBadRequest)
	}

	return nil
}

// BuildPaginationResponse builds pagination response
func BuildPaginationResponse(data interface{}, total int, query PaginationQuery) map[string]interface{} {
	totalPages := total / query.Limit
	if total%query.Limit > 0 {
		totalPages++
	}

	return map[string]interface{}{
		"data": data,
		"pagination": map[string]interface{}{
			"page":        query.Page,
			"limit":       query.Limit,
			"total_items": total,
			"total_pages": totalPages,
			"has_next":    query.Page < totalPages,
			"has_prev":    query.Page > 1,
		},
	}
}
