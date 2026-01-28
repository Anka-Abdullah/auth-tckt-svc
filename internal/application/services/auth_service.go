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
	LogSendWelcomeEmailFailed   = "Failed to send welcome email"
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
	mailer      ports.Mailer
	otpService  ports.OTPService
	logger      *logger.Logger
}

func NewAuthService(
	userRepo ports.UserRepository,
	tokenRepo ports.TokenRepository,
	jwtManager ports.JWTManager,
	passwordMgr ports.PasswordManager,
	mailer ports.Mailer,
	otpService ports.OTPService,
	logger *logger.Logger,
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
		jwtManager:  jwtManager,
		passwordMgr: passwordMgr,
		mailer:      mailer,
		otpService:  otpService,
		logger:      logger,
	}
}

func (s *AuthService) Register(user *domain.User, password string) (*domain.User, error) {
	exists, err := s.userRepo.ExistsByEmail(user.Email)
	if err != nil {
		s.logger.Error(LogCheckEmailExistence, err)
		return nil, err
	}
	if exists {
		return nil, domain.ErrEmailExists
	}

	hashedPassword, err := s.passwordMgr.HashPassword(password)
	if err != nil {
		s.logger.Error(LogHashPasswordFailed, err)
		return nil, err
	}

	// Generate ULID untuk user
	user.ID = domain.NewULID()
	user.PasswordHash = hashedPassword
	user.IsActive = true
	user.IsVerified = false
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Create(user); err != nil {
		s.logger.Error(LogCreateUserFailed, err)
		return nil, err
	}

	// Generate verification token dengan ULID user
	verificationToken, err := s.jwtManager.Generate(user.ID, user.Email, []string{"user"})
	if err != nil {
		s.logger.Error(LogGenerateTokenFailed, err)
	} else {
		go func() {
			if err := s.mailer.SendVerificationEmail(user, verificationToken); err != nil {
				s.logger.Error(LogSendEmailFailed, err)
			}
		}()
	}

	s.logger.Info(LogUserRegistered,
		"user_id", user.ID,
		"email", user.Email,
	)
	return user, nil
}

func (s *AuthService) Login(email, password string) (*domain.TokenPair, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		s.logger.Warn(LogUserNotFound, "email", email)
		return nil, domain.ErrInvalidCredentials
	}

	if !user.IsActive {
		s.logger.Warn(LogUserInactive, "user_id", user.ID)
		return nil, domain.ErrUserInactive
	}

	if !s.passwordMgr.CheckPasswordHash(password, user.PasswordHash) {
		s.logger.Warn(LogInvalidPassword, "user_id", user.ID)
		return nil, domain.ErrInvalidCredentials
	}

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

	// Store refresh token dengan key yang konsisten
	refreshKey := RefreshTokenPrefix + user.ID
	if err := s.tokenRepo.SetToken(refreshKey, refreshToken, 7*24*time.Hour); err != nil {
		s.logger.Error(LogStoreRefreshFailed, err)
	}

	// Update last login - FIXED: menggunakan pointer
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
		s.logger.Error(LogSendEmailFailed, err)
		return err
	}

	s.logger.Info(LogPasswordResetSent, "user_id", user.ID)
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

	s.logger.Info(LogPasswordResetSuccess, "user_id", user.ID)
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

// RegisterWithOTP registers user with OTP verification
func (s *AuthService) RegisterWithOTP(user *domain.User, password string) (*domain.User, error) {
	// Check if email exists
	exists, err := s.userRepo.ExistsByEmail(user.Email)
	if err != nil {
		s.logger.Error(LogCheckEmailExistence, err)
		return nil, err
	}
	if exists {
		return nil, domain.ErrEmailExists
	}

	// Hash password
	hashedPassword, err := s.passwordMgr.HashPassword(password)
	if err != nil {
		s.logger.Error(LogHashPasswordFailed, err)
		return nil, err
	}

	// Generate ULID untuk user
	user.ID = domain.NewULID()
	user.PasswordHash = hashedPassword
	user.IsActive = true
	user.IsVerified = false
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Create(user); err != nil {
		s.logger.Error(LogCreateUserFailed, err)
		return nil, err
	}

	// Generate and send OTP
	_, err = s.otpService.SendOTP(user.Email)
	if err != nil {
		s.logger.Error(LogSendOTPFailed, err, "email", user.Email)
		// Don't fail registration if OTP sending fails
	}

	// Send welcome email
	go func() {
		if err := s.mailer.SendWelcomeEmail(user); err != nil {
			s.logger.Error(LogSendWelcomeEmailFailed, err)
		}
	}()

	s.logger.Info(LogUserRegistered,
		"user_id", user.ID,
		"email", user.Email,
	)

	return user, nil
}

// VerifyOTP verifies user's OTP
func (s *AuthService) VerifyOTP(email, otp string) error {
	// Find user by email
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		s.logger.Warn(LogUserNotFound, "email", email)
		// Don't reveal user existence
		return nil
	}

	// Check if already verified
	if user.IsVerified {
		return domain.ErrAlreadyVerified
	}

	// Verify OTP
	valid, err := s.otpService.VerifyOTP(email, otp)
	if err != nil {
		s.logger.Error(LogOTPVerificationFailed, err, "email", email)
		return domain.ErrInvalidToken
	}

	if !valid {
		return domain.ErrInvalidOTP
	}

	// Mark user as verified
	user.IsVerified = true
	user.UpdatedAt = time.Now()
	if err := s.userRepo.Update(user); err != nil {
		s.logger.Error(LogUpdateVerificationFailed, err, "user_id", user.ID)
		return err
	}

	s.logger.Info(LogUserVerified,
		"user_id", user.ID,
		"email", user.Email,
	)

	return nil
}

// ResendOTP resends OTP to user
func (s *AuthService) ResendOTP(email string) error {
	// Check if user exists
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		s.logger.Warn(LogUserNotFound, "email", email)
		// Don't reveal user existence
		return nil
	}

	// Check if user is already verified
	if user.IsVerified {
		return domain.ErrAlreadyVerified
	}

	// Resend OTP
	_, err = s.otpService.ResendOTP(email)
	if err != nil {
		s.logger.Error(LogResendOTPFailed, err, "email", email)
		return err
	}

	s.logger.Info(LogOTPResent, "user_id", user.ID, "email", email)
	return nil
}

// LoginWithOTP login with OTP (for passwordless login)
func (s *AuthService) LoginWithOTP(email string) (string, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		s.logger.Warn(LogUserNotFound, "email", email)
		// Don't reveal user existence
		return "", nil
	}

	if !user.IsActive {
		s.logger.Warn(LogUserInactive, "user_id", user.ID)
		return "", domain.ErrUserInactive
	}

	// Generate and send OTP
	otp, err := s.otpService.SendOTP(email)
	if err != nil {
		s.logger.Error(LogSendOTPFailed, err, "email", email)
		return "", err
	}

	s.logger.Info(LogLoginOTPSent, "user_id", user.ID, "email", email)
	return otp, nil
}

// VerifyLoginOTP verifies OTP for login
func (s *AuthService) VerifyLoginOTP(email, otp string) (*domain.TokenPair, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		s.logger.Warn(LogUserNotFound, "email", email)
		return nil, domain.ErrInvalidCredentials
	}

	if !user.IsActive {
		s.logger.Warn(LogUserInactive, "user_id", user.ID)
		return nil, domain.ErrUserInactive
	}

	// Verify OTP
	valid, err := s.otpService.VerifyOTP(email, otp)
	if err != nil {
		s.logger.Error(LogOTPVerificationFailed, err, "email", email)
		return nil, domain.ErrInvalidToken
	}

	if !valid {
		return nil, domain.ErrInvalidOTP
	}

	// Generate tokens
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

	// Store refresh token
	refreshKey := RefreshTokenPrefix + user.ID
	if err := s.tokenRepo.SetToken(refreshKey, refreshToken, 7*24*time.Hour); err != nil {
		s.logger.Error(LogStoreRefreshFailed, err)
	}

	// Update last login - FIXED: menggunakan pointer
	user.SetLastLogin()
	if err := s.userRepo.Update(user); err != nil {
		s.logger.Warn(LogUpdateLastLoginFailed, "error", err)
	}

	tokenPair := &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}

	s.logger.Info(LogLoginOTPSuccessful, "user_id", user.ID)
	return tokenPair, nil
}
