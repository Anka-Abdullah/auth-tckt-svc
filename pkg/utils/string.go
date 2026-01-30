package utils

import (
	"math/rand"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// IsEmpty checks if a string is empty or contains only whitespace
func IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// IsNotEmpty checks if a string is not empty
func IsNotEmpty(s string) bool {
	return !IsEmpty(s)
}

// TrimSpace trims space and returns pointer
func TrimSpace(s string) *string {
	trimmed := strings.TrimSpace(s)
	return &trimmed
}

// ToLower returns lowercase string
func ToLower(s string) string {
	return strings.ToLower(s)
}

// ToUpper returns uppercase string
func ToUpper(s string) string {
	return strings.ToUpper(s)
}

// ContainsAny checks if string contains any of the substrings
func ContainsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ContainsAll checks if string contains all substrings
func ContainsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// RemoveWhitespace removes all whitespace from string
func RemoveWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// Truncate truncates a string to specified length
func Truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length] + "..."
}

// Slugify converts string to URL-friendly slug
func Slugify(s string) string {
	// Convert to lowercase
	s = strings.ToLower(s)

	// Replace spaces with hyphens
	s = strings.ReplaceAll(s, " ", "-")

	// Remove special characters
	var result strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result.WriteRune(r)
		}
	}

	// Remove consecutive hyphens
	slug := result.String()
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}

	// Trim hyphens from start and end
	slug = strings.Trim(slug, "-")

	return slug
}

// ExtractEmails extracts emails from text
func ExtractEmails(text string) []string {
	emailRegex := `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`
	re := regexp.MustCompile(emailRegex)
	return re.FindAllString(text, -1)
}

// NormalizeSpaces normalizes multiple spaces to single space
func NormalizeSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// GenerateRandomColor generates random hex color
func GenerateRandomColor() string {
	colors := []string{
		"#FF6B6B", "#4ECDC4", "#FFD166", "#06D6A0",
		"#118AB2", "#073B4C", "#EF476F", "#7209B7",
		"#3A86FF", "#FB5607", "#8338EC", "#FF006E",
	}
	rand.Seed(time.Now().UnixNano())
	return colors[rand.Intn(len(colors))]
}

// ParseBool parses string to bool with default
func ParseBool(s string, defaultValue bool) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "true" || s == "1" || s == "yes" || s == "y" {
		return true
	}
	if s == "false" || s == "0" || s == "no" || s == "n" {
		return false
	}
	return defaultValue
}
