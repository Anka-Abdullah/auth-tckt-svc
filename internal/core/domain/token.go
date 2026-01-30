package domain

import (
	"time"

	"gorm.io/gorm"
)

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	User         *User  `json:"user"`
}

// RefreshToken model untuk database
type RefreshToken struct {
	ID        string    `gorm:"type:char(26);primaryKey"`
	UserID    string    `gorm:"type:char(26);index;not null"`
	Token     string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

func (rt *RefreshToken) BeforeCreate(tx *gorm.DB) (err error) {
	if rt.ID == "" {
		rt.ID = NewULID()
	}
	return
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

// PasswordResetToken model
type PasswordResetToken struct {
	ID        string    `gorm:"type:char(26);primaryKey"`
	UserID    string    `gorm:"type:char(26);index;not null"`
	Token     string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	IsUsed    bool      `gorm:"default:false"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

func (prt *PasswordResetToken) BeforeCreate(tx *gorm.DB) (err error) {
	if prt.ID == "" {
		prt.ID = NewULID()
	}
	return
}

func (PasswordResetToken) TableName() string {
	return "password_reset_tokens"
}
