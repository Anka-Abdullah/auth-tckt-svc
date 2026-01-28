package services

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"auth-svc-ticketing/internal/core/domain"
	"auth-svc-ticketing/internal/core/ports"
	"auth-svc-ticketing/pkg/logger"
)

const (
	OTP_EXPIRY = 5 * time.Minute
)

type OTPService struct {
	tokenRepo ports.TokenRepository
	mailer    ports.Mailer
	logger    *logger.Logger
}

func NewOTPService(tokenRepo ports.TokenRepository, mailer ports.Mailer, logger *logger.Logger) ports.OTPService {
	return &OTPService{
		tokenRepo: tokenRepo,
		mailer:    mailer,
		logger:    logger,
	}
}

// GenerateOTP generates a 6-digit OTP
func (s *OTPService) GenerateOTP() (string, error) {
	max := big.NewInt(999999)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// SendOTP sends OTP to user's email
func (s *OTPService) SendOTP(email string) (string, error) {
	// Generate OTP
	otp, err := s.GenerateOTP()
	if err != nil {
		s.logger.Error("Failed to generate OTP", err, "email", email)
		return "", domain.ErrInternal
	}

	// Store OTP in Redis
	key := "otp:" + email
	if err := s.tokenRepo.SetToken(key, otp, OTP_EXPIRY); err != nil {
		s.logger.Error("Failed to store OTP", err, "email", email)
		return "", domain.ErrInternal
	}

	// Send OTP via email (simulated)
	// In production, integrate with actual email service
	s.logger.Info("OTP generated",
		"email", email,
		"otp", otp,
		"expires_in", OTP_EXPIRY.String(),
	)

	// Send actual email
	go func() {
		// Simulate email sending
		time.Sleep(100 * time.Millisecond)
		s.logger.Info("OTP email sent", "email", email)
	}()

	return otp, nil
}

// VerifyOTP verifies OTP
func (s *OTPService) VerifyOTP(email, otp string) (bool, error) {
	key := "otp:" + email
	storedOTP, err := s.tokenRepo.GetToken(key)
	if err != nil {
		s.logger.Error("Failed to get OTP", err, "email", email)
		return false, domain.ErrInternal
	}

	if storedOTP == "" {
		s.logger.Warn("OTP not found or expired", "email", email)
		return false, domain.ErrInvalidOTP
	}

	if storedOTP != otp {
		s.logger.Warn("Invalid OTP", "email", email)
		return false, domain.ErrInvalidOTP
	}

	// Delete OTP after successful verification
	s.tokenRepo.DeleteToken(key)

	s.logger.Info("OTP verified successfully", "email", email)
	return true, nil
}

// ResendOTP resends OTP
func (s *OTPService) ResendOTP(email string) (string, error) {
	// Delete existing OTP
	key := "otp:" + email
	s.tokenRepo.DeleteToken(key)

	// Generate and send new OTP
	return s.SendOTP(email)
}
