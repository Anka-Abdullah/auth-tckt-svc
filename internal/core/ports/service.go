package ports

import (
	"auth-svc-ticketing/internal/core/domain"
)

// AuthService interface
type AuthService interface {
	Register(user *domain.User, password string) (*domain.User, error)
	Login(email, password string) (*domain.TokenPair, error)
	RefreshToken(refreshToken string) (*domain.TokenPair, error)
	Logout(userID, accessToken string) error
	ForgotPassword(email string) error
	ResetPassword(token, newPassword string) error
	GetProfile(userID string) (*domain.User, error)
	CheckTokenBlacklist(token string) (bool, error)
}

// OTPService interface
type OTPService interface {
	SendOTP(email string) (string, error)
	VerifyOTP(email, otp string) (bool, error)
}
