package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash compares a password with its hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateRandomString generates a random string of specified length
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:length], nil
}

// GenerateSecureToken generates a secure random token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateAPIKey generates an API key
func GenerateAPIKey() (string, error) {
	prefix := "tk_"
	token, err := GenerateSecureToken(32)
	if err != nil {
		return "", err
	}
	return prefix + token, nil
}

// GenerateHash creates a SHA256 hash of input
func GenerateHash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// MaskEmail masks an email address for display
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	username := parts[0]
	domain := parts[1]

	if len(username) <= 2 {
		return fmt.Sprintf("***@%s", domain)
	}

	maskedUsername := string(username[0]) + "***" + string(username[len(username)-1])
	return fmt.Sprintf("%s@%s", maskedUsername, domain)
}

// MaskPhone masks a phone number for display
func MaskPhone(phone string) string {
	if len(phone) <= 4 {
		return strings.Repeat("*", len(phone))
	}

	visibleDigits := 4
	maskedPart := strings.Repeat("*", len(phone)-visibleDigits)
	visiblePart := phone[len(phone)-visibleDigits:]

	return maskedPart + visiblePart
}

// SanitizeInput sanitizes user input to prevent XSS
func SanitizeInput(input string) string {
	// Replace potentially dangerous characters
	replacements := map[string]string{
		"<":  "&lt;",
		">":  "&gt;",
		"\"": "&quot;",
		"'":  "&#39;",
		"&":  "&amp;",
	}

	sanitized := input
	for old, new := range replacements {
		sanitized = strings.ReplaceAll(sanitized, old, new)
	}

	return sanitized
}
