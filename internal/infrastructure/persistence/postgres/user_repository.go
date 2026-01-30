package postgres

import (
	"errors"

	"auth-svc-ticketing/internal/core/domain"
	"auth-svc-ticketing/internal/core/ports"

	"gorm.io/gorm"
)

// Error constants
const (
	ErrInvalidULIDFormat = "invalid ULID format"
	ErrUserNotFound      = "user not found"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) ports.UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *domain.User) error {
	// Validate ULID if provided
	if user.ID != "" && !domain.IsValidULID(user.ID) {
		return errors.New(ErrInvalidULIDFormat)
	}

	result := r.db.Create(user)
	return result.Error
}

func (r *UserRepository) FindByID(id string) (*domain.User, error) {
	// Validate ULID
	if !domain.IsValidULID(id) {
		return nil, errors.New(ErrInvalidULIDFormat)
	}

	var user domain.User
	result := r.db.First(&user, "id = ?", id)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, domain.ErrUserNotFound
	}
	return &user, result.Error
}

func (r *UserRepository) FindByEmail(email string) (*domain.User, error) {
	var user domain.User
	result := r.db.Where("email = ?", email).First(&user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, domain.ErrUserNotFound
	}
	return &user, result.Error
}

func (r *UserRepository) Update(user *domain.User) error {
	// Validate ULID
	if !domain.IsValidULID(user.ID) {
		return errors.New(ErrInvalidULIDFormat)
	}

	result := r.db.Save(user)
	return result.Error
}

func (r *UserRepository) Delete(id string) error {
	// Validate ULID
	if !domain.IsValidULID(id) {
		return errors.New(ErrInvalidULIDFormat)
	}

	result := r.db.Delete(&domain.User{}, "id = ?", id)
	return result.Error
}

func (r *UserRepository) ExistsByEmail(email string) (bool, error) {
	var count int64
	result := r.db.Model(&domain.User{}).Where("email = ?", email).Count(&count)
	return count > 0, result.Error
}

// Migrate - untuk auto-migration jika diperlukan
func (r *UserRepository) Migrate() error {
	return r.db.AutoMigrate(
		&domain.User{},
		&domain.UserRoleModel{},
		&domain.RefreshToken{},
		&domain.PasswordResetToken{},
	)
}
