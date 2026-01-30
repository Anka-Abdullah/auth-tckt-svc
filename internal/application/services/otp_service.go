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

func NewOTPService(
	tokenRepo ports.TokenRepository,
	mailer ports.Mailer,
	logger *logger.Logger,
) ports.OTPService {
	return &OTPService{
		tokenRepo: tokenRepo,
		mailer:    mailer,
		logger:    logger,
	}
}

func (s *OTPService) GenerateOTP() (string, error) {
	max := big.NewInt(999999)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func (s *OTPService) SendOTP(email string) (string, error) {
	otp, err := s.GenerateOTP()
	if err != nil {
		s.logger.Error("Failed to generate OTP", err, "email", email)
		return "", domain.ErrInternal
	}

	key := "otp:" + email
	if err := s.tokenRepo.SetToken(key, otp, OTP_EXPIRY); err != nil {
		s.logger.Error("Failed to store OTP", err, "email", email)
		return "", domain.ErrInternal
	}

	// Kirim OTP via email menggunakan Mailer
	if err := s.mailer.SendOTPEmail(email, otp); err != nil {
		s.logger.Error("Failed to send OTP email", err, "email", email)
		// Jangan return error di sini karena OTP sudah disimpan di Redis
		// User masih bisa verify dengan OTP yang ada di Redis
	} else {
		s.logger.Info("OTP email sent successfully",
			"email", email,
			"expires_in", OTP_EXPIRY.String(),
		)
	}

	return otp, nil
}

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

	// Delete OTP setelah berhasil diverifikasi
	s.tokenRepo.DeleteToken(key)

	s.logger.Info("OTP verified successfully", "email", email)
	return true, nil
}
