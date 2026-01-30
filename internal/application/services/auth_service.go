package services

import (
	"time"

	"auth-svc-ticketing/internal/core/domain"
	"auth-svc-ticketing/internal/core/ports"
	"auth-svc-ticketing/pkg/logger"
)

const (
	RefreshTokenPrefix = "refresh:"
	BlacklistPrefix    = "blacklist:"
	ResetTokenPrefix   = "reset:"
	VerificationPrefix = "verify:"
	OTPPrefix          = "otp:"
)

// Log message constants
const (
	LogUserInactive             = "Login failed - user inactive"
	LogUserNotFound             = "Login failed - user not found"
	LogInvalidPassword          = "Login failed - invalid password"
	LogEmailExists              = "Email already exists"
	LogUserRegistered           = "User registered successfully"
	LogLoginSuccessful          = "Login successful"
	LogUserLoggedOut            = "User logged out"
	LogEmailVerified            = "Email verified"
	LogPasswordResetSent        = "Password reset email sent"
	LogPasswordResetSuccess     = "Password reset successful"
	LogOTPSent                  = "OTP sent"
	LogOTPVerified              = "OTP verified"
	LogUserVerified             = "User verified with OTP"
	LogOTPResent                = "OTP resent"
	LogLoginOTPSent             = "Login OTP sent"
	LogLoginOTPSuccessful       = "Login with OTP successful"
	LogCheckEmailExistence      = "Failed to check email existence"
	LogHashPasswordFailed       = "Failed to hash password"
	LogCreateUserFailed         = "Failed to create user"
	LogGenerateTokenFailed      = "Failed to generate verification token"
	LogSendEmailFailed          = "Failed to send verification email"
	LogGenerateAccessFailed     = "Failed to generate access token"
	LogGenerateRefreshFailed    = "Failed to generate refresh token"
	LogStoreRefreshFailed       = "Failed to store refresh token"
	LogUpdateLastLoginFailed    = "Failed to update last login"
	LogRefreshTokenFailed       = "Refresh token verification failed"
	LogTokenNotFound            = "Refresh token not found in storage"
	LogFindUserFailed           = "Failed to find user"
	LogUpdateRefreshFailed      = "Failed to update refresh token"
	LogBlacklistTokenFailed     = "Failed to blacklist token"
	LogDeleteRefreshFailed      = "Failed to delete refresh token"
	LogUpdateUserFailed         = "Failed to update user"
	LogGetProfileFailed         = "Failed to get profile"
	LogSendOTPFailed            = "Failed to send OTP"
	LogOTPVerificationFailed    = "OTP verification failed"
	LogUpdateVerificationFailed = "Failed to update user verification status"
	LogResendOTPFailed          = "Failed to resend OTP"
	LogInvalidULIDFormat        = "Invalid ULID format"
)

type AuthService struct {
	userRepo    ports.UserRepository
	tokenRepo   ports.TokenRepository
	jwtManager  ports.JWTManager
	passwordMgr ports.PasswordManager
	otpService  ports.OTPService
	mailer      ports.Mailer
	logger      *logger.Logger
}

func NewAuthService(
	userRepo ports.UserRepository,
	tokenRepo ports.TokenRepository,
	jwtManager ports.JWTManager,
	passwordMgr ports.PasswordManager,
	otpService ports.OTPService,
	mailer ports.Mailer,
	logger *logger.Logger,
) ports.AuthService {
	return &AuthService{
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
		jwtManager:  jwtManager,
		passwordMgr: passwordMgr,
		otpService:  otpService,
		mailer:      mailer,
		logger:      logger,
	}
}

func (s *AuthService) Register(user *domain.User, password string) (result *domain.User, err error) {
	// 1. Cek apakah email sudah ada
	exists, err := s.userRepo.ExistsByEmail(user.Email)
	if err != nil {
		s.logger.Error(LogCheckEmailExistence, err)
		return nil, err
	}
	if exists {
		return nil, domain.ErrEmailExists
	}

	// 2. Hash password
	hashedPassword, err := s.passwordMgr.HashPassword(password)
	if err != nil {
		s.logger.Error(LogHashPasswordFailed, err)
		return nil, err
	}

	// 3. Buat user dengan status unverified
	user.ID = domain.NewULID()
	user.PasswordHash = hashedPassword
	user.IsActive = true
	user.IsVerified = false // Belum verified
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Create(user); err != nil {
		s.logger.Error(LogCreateUserFailed, err)
		return nil, err
	}
	otp, err := s.otpService.SendOTP(user.Email)
	if err != nil {
		s.logger.Error("Failed to send registration OTP", err, "email", user.Email)
		// Tidak return error, karena user sudah dibuat
		// User masih bisa request OTP ulang
	} else {
		s.logger.Info("Registration OTP sent",
			"user_id", user.ID,
			"email", user.Email,
			"otp", otp, // Hanya untuk development logging
		)
	}

	s.logger.Info("User registered successfully, verification OTP sent",
		"user_id", user.ID,
		"email", user.Email,
	)
	return user, nil
}

func (s *AuthService) Login(email, password string) (*domain.TokenPair, error) {
	// 1. Cari user
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		s.logger.Warn(LogUserNotFound, "email", email)
		return nil, domain.ErrInvalidCredentials
	}

	// 2. Cek user active
	if !user.IsActive {
		s.logger.Warn(LogUserInactive, "user_id", user.ID)
		return nil, domain.ErrUserInactive
	}

	// 3. Cek password
	if !s.passwordMgr.CheckPasswordHash(password, user.PasswordHash) {
		s.logger.Warn(LogInvalidPassword, "user_id", user.ID)
		return nil, domain.ErrInvalidCredentials
	}

	// 4. Cek apakah user sudah verified
	if !user.IsVerified {
		// Kirim OTP verifikasi jika belum verified
		_, err = s.otpService.SendOTP(email)
		if err != nil {
			s.logger.Error("Failed to send verification OTP", err, "email", email)
		}
		return nil, domain.ErrUserNotVerified
	}

	// 5. Generate tokens
	accessToken, err := s.jwtManager.Generate(user.ID, user.Email, []string{"user"})
	if err != nil {
		s.logger.Error(LogGenerateAccessFailed, err)
		return nil, err
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		s.logger.Error(LogGenerateRefreshFailed, err)
		return nil, err
	}

	// 6. Store refresh token
	refreshKey := RefreshTokenPrefix + user.ID
	if err := s.tokenRepo.SetToken(refreshKey, refreshToken, 7*24*time.Hour); err != nil {
		s.logger.Error(LogStoreRefreshFailed, err)
	}

	// 7. Update last login
	user.SetLastLogin()
	if err := s.userRepo.Update(user); err != nil {
		s.logger.Warn(LogUpdateLastLoginFailed, "error", err)
	}

	tokenPair := &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}

	s.logger.Info(LogLoginSuccessful, "user_id", user.ID)
	return tokenPair, nil
}

func (s *AuthService) RefreshToken(refreshToken string) (*domain.TokenPair, error) {
	claims, err := s.jwtManager.VerifyRefreshToken(refreshToken)
	if err != nil {
		s.logger.Warn(LogRefreshTokenFailed, "error", err)
		return nil, domain.ErrInvalidToken
	}

	// Validate ULID dari claims
	if !domain.IsValidULID(claims.UserID) {
		s.logger.Warn(LogInvalidULIDFormat, "user_id", claims.UserID)
		return nil, domain.ErrInvalidToken
	}

	// Check if refresh token exists in storage
	refreshKey := RefreshTokenPrefix + claims.UserID
	storedToken, err := s.tokenRepo.GetToken(refreshKey)
	if err != nil || storedToken != refreshToken {
		s.logger.Warn(LogTokenNotFound, "user_id", claims.UserID)
		return nil, domain.ErrInvalidToken
	}

	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil {
		s.logger.Error(
			LogFindUserFailed,
			err,
			"user_id", claims.UserID,
		)
		return nil, err
	}

	newAccessToken, err := s.jwtManager.Generate(user.ID, user.Email, []string{"user"})
	if err != nil {
		s.logger.Error(LogGenerateAccessFailed, err)
		return nil, err
	}

	newRefreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		s.logger.Error(LogGenerateRefreshFailed, err)
		return nil, err
	}

	// Update stored refresh token
	if err := s.tokenRepo.SetToken(refreshKey, newRefreshToken, 7*24*time.Hour); err != nil {
		s.logger.Error(LogUpdateRefreshFailed, err)
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
		s.logger.Error(LogBlacklistTokenFailed, err)
	}

	// Remove refresh token
	refreshKey := RefreshTokenPrefix + userID
	if err := s.tokenRepo.DeleteToken(refreshKey); err != nil {
		s.logger.Error(LogDeleteRefreshFailed, err)
	}

	s.logger.Info(LogUserLoggedOut, "user_id", userID)
	return nil
}

func (s *AuthService) VerifyEmail(token string) error {
	claims, err := s.jwtManager.Verify(token)
	if err != nil {
		return domain.ErrInvalidToken
	}

	// Validate ULID
	if !domain.IsValidULID(claims.UserID) {
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

	s.logger.Info(LogEmailVerified, "user_id", user.ID)
	return nil
}

func (s *AuthService) ForgotPassword(email string) error {
	// 1. Cek apakah user exists
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		// Untuk security, jangan kasih tahu jika email tidak ditemukan
		s.logger.Info("Password reset requested for email", "email", email)
		return nil
	}

	otp, err := s.otpService.SendOTP(email)
	if err != nil {
		s.logger.Error("Failed to send password reset OTP", err, "email", email)
		return err
	}

	s.logger.Info("Password reset OTP sent",
		"user_id", user.ID,
		"email", email,
		"otp", otp, // Hanya untuk development logging
	)
	return nil
}

func (s *AuthService) ResetPassword(resetToken, newPassword string) error {
	// 1. Verify token (OTP)
	claims, err := s.jwtManager.Verify(resetToken)
	if err != nil {
		// Jika bukan JWT token, coba verifikasi sebagai OTP
		// Untuk OTP, kita perlu menyimpan email di token atau parse dari token
		// Ini adalah placeholder - implementasi sesungguhnya perlu mengekstrak email dari token

		// Untuk now, anggap resetToken adalah kombinasi email:otp
		// Format: base64(email + ":" + otp) atau implementasi yang lebih baik

		return domain.ErrInvalidToken
	}

	// 2. Cari user
	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil {
		return domain.ErrUserNotFound
	}

	// 3. Hash new password
	hashedPassword, err := s.passwordMgr.HashPassword(newPassword)
	if err != nil {
		s.logger.Error("Failed to hash new password", err, "user_id", user.ID)
		return err
	}

	// 4. Update password
	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now()
	if err := s.userRepo.Update(user); err != nil {
		s.logger.Error("Failed to update password", err, "user_id", user.ID)
		return err
	}

	// 5. Blacklist token jika perlu
	blacklistKey := BlacklistPrefix + resetToken
	s.tokenRepo.SetToken(blacklistKey, user.ID, 1*time.Hour)

	s.logger.Info("Password reset successful", "user_id", user.ID)
	return nil
}

func (s *AuthService) GetProfile(userID string) (*domain.User, error) {
	// Validate ULID
	if !domain.IsValidULID(userID) {
		return nil, domain.ErrInvalidToken
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		s.logger.Error(LogGetProfileFailed, err, "user_id", userID)
		return nil, err
	}

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
