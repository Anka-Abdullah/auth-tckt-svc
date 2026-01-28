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
	VerifyEmail(token string) error
	ForgotPassword(email string) error
	ResetPassword(token, newPassword string) error
	GetProfile(userID string) (*domain.User, error)
	CheckTokenBlacklist(token string) (bool, error)

	// OTP methods
	RegisterWithOTP(user *domain.User, password string) (*domain.User, error)
	VerifyOTP(email, otp string) error
	ResendOTP(email string) error
	LoginWithOTP(email string) (string, error)
	VerifyLoginOTP(email, otp string) (*domain.TokenPair, error)
}

// OTPService interface
type OTPService interface {
	SendOTP(email string) (string, error)
	VerifyOTP(email, otp string) (bool, error)
	ResendOTP(email string) (string, error)
}
