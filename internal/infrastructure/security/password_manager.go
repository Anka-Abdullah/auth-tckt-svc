package security

import (
	"crypto/rand"
	"encoding/hex"

	"auth-svc-ticketing/internal/core/ports"

	"golang.org/x/crypto/bcrypt"
)

type passwordManager struct{}

func NewPasswordManager() ports.PasswordManager {
	return &passwordManager{}
}

func (m *passwordManager) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func (m *passwordManager) CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (m *passwordManager) GenerateRandomPassword(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:length], nil
}
