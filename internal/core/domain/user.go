package domain

import (
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
)

type User struct {
	ID           string         `json:"id" gorm:"type:char(26);primaryKey"`
	Email        string         `json:"email" gorm:"uniqueIndex;not null"`
	PasswordHash string         `json:"-" gorm:"column:password_hash;not null"`
	FullName     string         `json:"full_name" gorm:"not null"`
	Phone        string         `json:"phone" gorm:"not null"`
	IsActive     bool           `json:"is_active" gorm:"default:true"`
	IsVerified   bool           `json:"is_verified" gorm:"default:false"`
	LastLogin    *time.Time     `json:"last_login" gorm:"autoCreateTime"`
	CreatedAt    time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt    time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`
}

// BeforeCreate hook untuk generate ULID
func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	if u.ID == "" {
		u.ID = NewULID()
	}
	return
}

// SetLastLogin helper method
func (u *User) SetLastLogin() {
	now := time.Now()
	u.LastLogin = &now
}

// TableName specifies the table name
func (User) TableName() string {
	return "users"
}

type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
)

// UserRole model
type UserRoleModel struct {
	ID        string    `gorm:"type:char(26);primaryKey"`
	UserID    string    `gorm:"type:char(26);index;not null"`
	Role      string    `gorm:"not null"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

func (urm *UserRoleModel) BeforeCreate(tx *gorm.DB) (err error) {
	if urm.ID == "" {
		urm.ID = NewULID()
	}
	return
}

func (UserRoleModel) TableName() string {
	return "user_roles"
}

// NewULID generates new ULID string
func NewULID() string {
	return ulid.MustNew(ulid.Now(), ulid.DefaultEntropy()).String()
}

// IsValidULID checks if string is valid ULID
func IsValidULID(id string) bool {
	_, err := ulid.Parse(id)
	return err == nil
}
