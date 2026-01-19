package ports

import (
	"auth-svc-ticketing/internal/core/domain"
	"time"
)

type UserRepository interface {
	Create(user *domain.User) error
	FindByID(id string) (*domain.User, error)
	FindByEmail(email string) (*domain.User, error)
	Update(user *domain.User) error
	Delete(id string) error
	ExistsByEmail(email string) (bool, error)
}

type TokenRepository interface {
	SetToken(key string, value interface{}, expiration time.Duration) error
	GetToken(key string) (string, error)
	DeleteToken(key string) error
}
