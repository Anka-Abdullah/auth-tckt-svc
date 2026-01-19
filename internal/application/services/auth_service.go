package services

import (
	"time"

	"auth-svc-ticketing/internal/core/domain"
	"auth-svc-ticketing/internal/core/ports"
	"auth-svc-ticketing/pkg/logger"
)

// Constants untuk key prefix
const (
	RefreshTokenPrefix = "refresh:"
	BlacklistPrefix    = "blacklist:"
	ResetTokenPrefix   = "reset:"
)

type AuthService struct {
	userRepo    ports.UserRepository
	tokenRepo   ports.TokenRepository
	jwtManager  ports.JWTManager
	passwordMgr ports.PasswordManager
	mailer      ports.Mailer
	logger      *logger.Logger
}

func NewAuthService(
	userRepo ports.UserRepository,
	tokenRepo ports.TokenRepository,
	jwtManager ports.JWTManager,
	passwordMgr ports.PasswordManager,
	mailer ports.Mailer,
	logger *logger.Logger,
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
		jwtManager:  jwtManager,
		passwordMgr: passwordMgr,
		mailer:      mailer,
		logger:      logger,
	}
}

func (s *AuthService) Register(user *domain.User, password string) (*domain.User, error) {
	exists, err := s.userRepo.ExistsByEmail(user.Email)
	if err != nil {
		s.logger.Error("Failed to check email existence", err)
		return nil, err
	}
	if exists {
		return nil, domain.ErrEmailExists
	}

	hashedPassword, err := s.passwordMgr.HashPassword(password)
	if err != nil {
		s.logger.Error("Failed to hash password", err)
		return nil, err
	}

	user.PasswordHash = hashedPassword
	user.IsActive = true
	user.IsVerified = false
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Create(user); err != nil {
		s.logger.Error("Failed to create user", err)
		return nil, err
	}

	// Generate verification token
	verificationToken, err := s.jwtManager.Generate(user.ID, user.Email, []string{"user"})
	if err != nil {
		s.logger.Error("Failed to generate verification token", err)
		// Lanjut tanpa verification token untuk sekarang
	} else {
		// Send verification email async
		go func() {
			if err := s.mailer.SendVerificationEmail(user, verificationToken); err != nil {
				s.logger.Error("Failed to send verification email", err)
			}
		}()
	}

	s.logger.Info("User registered successfully",
		"user_id", user.ID,
		"email", user.Email,
	)
	return user, nil
}

func (s *AuthService) Login(email, password string) (*domain.TokenPair, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		s.logger.Warn("Login failed - user not found", "email", email)
		return nil, domain.ErrInvalidCredentials
	}

	if !user.IsActive {
		s.logger.Warn("Login failed - user inactive", "user_id", user.ID)
		return nil, domain.ErrUserInactive
	}

	if !s.passwordMgr.CheckPasswordHash(password, user.PasswordHash) {
		s.logger.Warn("Login failed - invalid password", "user_id", user.ID)
		return nil, domain.ErrInvalidCredentials
	}

	accessToken, err := s.jwtManager.Generate(user.ID, user.Email, []string{"user"})
	if err != nil {
		s.logger.Error("Failed to generate access token", err)
		return nil, err
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		s.logger.Error("Failed to generate refresh token", err)
		return nil, err
	}

	// Store refresh token dengan key yang konsisten
	refreshKey := RefreshTokenPrefix + user.ID
	if err := s.tokenRepo.SetToken(refreshKey, refreshToken, 7*24*time.Hour); err != nil {
		s.logger.Error("Failed to store refresh token", err)
	}

	// Update last login
	user.LastLogin = time.Now()
	if err := s.userRepo.Update(user); err != nil {
		s.logger.Warn("Failed to update last login", "error", err)
	}

	tokenPair := &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}

	s.logger.Info("Login successful", "user_id", user.ID)
	return tokenPair, nil
}

func (s *AuthService) RefreshToken(refreshToken string) (*domain.TokenPair, error) {
	claims, err := s.jwtManager.VerifyRefreshToken(refreshToken)
	if err != nil {
		s.logger.Warn("Refresh token verification failed", "error", err)
		return nil, domain.ErrInvalidToken
	}

	// Check if refresh token exists in storage
	refreshKey := RefreshTokenPrefix + claims.UserID
	storedToken, err := s.tokenRepo.GetToken(refreshKey)
	if err != nil || storedToken != refreshToken {
		s.logger.Warn("Refresh token not found in storage", "user_id", claims.UserID)
		return nil, domain.ErrInvalidToken
	}

	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil {
		s.logger.Error(
			"Failed to find user",
			err,
			"user_id", claims.UserID,
		)
		return nil, err
	}

	newAccessToken, err := s.jwtManager.Generate(user.ID, user.Email, []string{"user"})
	if err != nil {
		s.logger.Error("Failed to generate new access token", err)
		return nil, err
	}

	newRefreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		s.logger.Error("Failed to generate new refresh token", err)
		return nil, err
	}

	// Update stored refresh token
	if err := s.tokenRepo.SetToken(refreshKey, newRefreshToken, 7*24*time.Hour); err != nil {
		s.logger.Error("Failed to update refresh token", err)
	}

	tokenPair := &domain.TokenPair{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		User:         user,
	}

	return tokenPair, nil
}

func (s *AuthService) Logout(userID, accessToken string) error {
	// Blacklist the access token
	blacklistKey := BlacklistPrefix + accessToken
	if err := s.tokenRepo.SetToken(blacklistKey, userID, 1*time.Hour); err != nil {
		s.logger.Error("Failed to blacklist token", err)
	}

	// Remove refresh token
	refreshKey := RefreshTokenPrefix + userID
	if err := s.tokenRepo.DeleteToken(refreshKey); err != nil {
		s.logger.Error("Failed to delete refresh token", err)
	}

	s.logger.Info("User logged out", "user_id", userID)
	return nil
}

func (s *AuthService) VerifyEmail(token string) error {
	claims, err := s.jwtManager.Verify(token)
	if err != nil {
		return domain.ErrInvalidToken
	}

	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil {
		return err
	}

	user.IsVerified = true
	user.UpdatedAt = time.Now()
	if err := s.userRepo.Update(user); err != nil {
		return err
	}

	s.logger.Info("Email verified", "user_id", user.ID)
	return nil
}

func (s *AuthService) ForgotPassword(email string) error {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		// Don't reveal if user exists or not
		s.logger.Info("Password reset requested for non-existent email", "email", email)
		return nil
	}

	resetToken, err := s.jwtManager.Generate(user.ID, user.Email, []string{"user"})
	if err != nil {
		return err
	}

	// Store reset token
	resetKey := ResetTokenPrefix + user.ID
	if err := s.tokenRepo.SetToken(resetKey, resetToken, 1*time.Hour); err != nil {
		return err
	}

	// Send reset email
	if err := s.mailer.SendPasswordResetEmail(email, resetToken); err != nil {
		s.logger.Error("Failed to send password reset email", err)
		return err
	}

	s.logger.Info("Password reset email sent", "user_id", user.ID)
	return nil
}

func (s *AuthService) ResetPassword(token, newPassword string) error {
	claims, err := s.jwtManager.Verify(token)
	if err != nil {
		return domain.ErrInvalidToken
	}

	// Verify reset token exists
	resetKey := ResetTokenPrefix + claims.UserID
	storedToken, err := s.tokenRepo.GetToken(resetKey)
	if err != nil || storedToken != token {
		return domain.ErrInvalidToken
	}

	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil {
		return err
	}

	hashedPassword, err := s.passwordMgr.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now()
	if err := s.userRepo.Update(user); err != nil {
		return err
	}

	// Remove reset token
	s.tokenRepo.DeleteToken(resetKey)

	s.logger.Info("Password reset successful", "user_id", user.ID)
	return nil
}

func (s *AuthService) GetProfile(userID string) (*domain.User, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		s.logger.Error("Failed to get profile", err, "user_id", userID)
		return nil, err
	}

	// Jangan return password hash
	user.PasswordHash = ""
	return user, nil
}

// CheckTokenBlacklist - Memeriksa apakah token di-blacklist
func (s *AuthService) CheckTokenBlacklist(token string) (bool, error) {
	blacklistKey := BlacklistPrefix + token
	_, err := s.tokenRepo.GetToken(blacklistKey)
	if err != nil {
		return false, nil // Token tidak di-blacklist
	}
	return true, nil // Token di-blacklist
}
