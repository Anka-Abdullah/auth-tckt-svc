package handlers

import (
	"auth-svc-ticketing/internal/core/domain"
	"auth-svc-ticketing/internal/core/ports"
	"auth-svc-ticketing/pkg/logger"
	"auth-svc-ticketing/pkg/utils"
	"net/http"

	"github.com/labstack/echo/v4"
)

// Request/Response DTOs
type (
	RegisterRequest struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required,min=8"`
		FullName string `json:"full_name" validate:"required"`
		Phone    string `json:"phone" validate:"required"`
	}

	LoginRequest struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	RefreshTokenRequest struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	ForgotPasswordRequest struct {
		Email string `json:"email" validate:"required,email"`
	}

	ResetPasswordRequest struct {
		Token       string `json:"token" validate:"required"`
		NewPassword string `json:"new_password" validate:"required,min=8"`
	}

	VerifyEmailRequest struct {
		Token string `json:"token" validate:"required"`
	}

	AuthResponse struct {
		AccessToken  string       `json:"access_token"`
		RefreshToken string       `json:"refresh_token"`
		User         *domain.User `json:"user"`
	}
)

type AuthHandler struct {
	authService ports.AuthService
	logger      *logger.Logger
	validator   *utils.CustomValidator
}

func NewAuthHandler(
	authService ports.AuthService,
	logger *logger.Logger,
) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      logger,
		validator:   utils.NewCustomValidator(),
	}
}

// Register godoc
// @Summary      Register new user
// @Description  Register a new user account
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body RegisterRequest true "Registration data"
// @Success      201  {object}  utils.Response{data=domain.User}
// @Failure      400  {object}  utils.ErrorResponse
// @Failure      409  {object}  utils.ErrorResponse
// @Failure      500  {object}  utils.ErrorResponse
// @Router       /auth/register [post]
func (h *AuthHandler) Register(c echo.Context) error {
	h.logger.Info("Register endpoint called")

	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind request", err)
		return c.JSON(http.StatusBadRequest, utils.ErrorResponse("Invalid request payload"))
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		h.logger.Warn("Validation failed", "error", err)
		return c.JSON(http.StatusBadRequest, utils.ErrorResponse(err.Error()))
	}

	// Create user domain object
	user := &domain.User{
		Email:    req.Email,
		FullName: req.FullName,
		Phone:    req.Phone,
	}

	// Call service
	result, err := h.authService.Register(user, req.Password)
	if err != nil {
		h.logger.Error("Registration failed", err,
			"email", req.Email,
			"function", logger.GetFunctionName(),
		)
		return utils.HandleError(c, err)
	}

	h.logger.Info("User registered successfully",
		"user_id", result.ID,
		"email", result.Email,
	)

	return c.JSON(http.StatusCreated, utils.SuccessResponse(
		"Registration successful. Please check your email for verification.",
		result,
	))
}

// Login godoc
// @Summary      User login
// @Description  Authenticate user and return tokens
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body LoginRequest true "Login credentials"
// @Success      200  {object}  utils.Response{data=AuthResponse}
// @Failure      400  {object}  utils.ErrorResponse
// @Failure      401  {object}  utils.ErrorResponse
// @Failure      403  {object}  utils.ErrorResponse
// @Failure      500  {object}  utils.ErrorResponse
// @Router       /auth/login [post]
func (h *AuthHandler) Login(c echo.Context) error {
	h.logger.Info("Login endpoint called")

	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind login request", err)
		return c.JSON(http.StatusBadRequest, utils.ErrorResponse("Invalid request payload"))
	}

	if err := h.validator.Validate(req); err != nil {
		h.logger.Warn("Login validation failed", "error", err)
		return c.JSON(http.StatusBadRequest, utils.ErrorResponse(err.Error()))
	}

	// Call auth service
	tokens, err := h.authService.Login(req.Email, req.Password)
	if err != nil {
		h.logger.Warn("Login failed", "error", err, "email", req.Email)
		return utils.HandleError(c, err)
	}

	h.logger.Info("Login successful", "email", req.Email)

	response := AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		User:         tokens.User,
	}

	return c.JSON(http.StatusOK, utils.SuccessResponse(
		"Login successful",
		response,
	))
}

// RefreshToken godoc
// @Summary      Refresh access token
// @Description  Get new access token using refresh token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body RefreshTokenRequest true "Refresh token"
// @Success      200  {object}  utils.Response{data=AuthResponse}
// @Failure      400  {object}  utils.ErrorResponse
// @Failure      401  {object}  utils.ErrorResponse
// @Failure      500  {object}  utils.ErrorResponse
// @Router       /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c echo.Context) error {
	var req RefreshTokenRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, utils.ErrorResponse("Invalid request"))
	}

	if err := h.validator.Validate(req); err != nil {
		return c.JSON(http.StatusBadRequest, utils.ErrorResponse(err.Error()))
	}

	tokens, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		h.logger.Error("Refresh token failed", err)
		return utils.HandleError(c, err)
	}

	response := AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		User:         tokens.User,
	}

	return c.JSON(http.StatusOK, utils.SuccessResponse(
		"Token refreshed successfully",
		response,
	))
}

// Logout godoc
// @Summary      User logout
// @Description  Invalidate user tokens
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  utils.Response
// @Failure      401  {object}  utils.ErrorResponse
// @Failure      500  {object}  utils.ErrorResponse
// @Router       /auth/logout [post]
func (h *AuthHandler) Logout(c echo.Context) error {
	userID := c.Get("user_id").(string)
	accessToken := c.Get("access_token").(string)

	if err := h.authService.Logout(userID, accessToken); err != nil {
		h.logger.Error("Logout failed", err, "user_id", userID)
		return utils.HandleError(c, err)
	}

	h.logger.Info("User logged out", "user_id", userID)

	return c.JSON(http.StatusOK, utils.SuccessResponse(
		"Logged out successfully",
		nil,
	))
}

// ForgotPassword godoc
// @Summary      Request password reset
// @Description  Send password reset email
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body ForgotPasswordRequest true "Email address"
// @Success      200  {object}  utils.Response
// @Failure      400  {object}  utils.ErrorResponse
// @Failure      404  {object}  utils.ErrorResponse
// @Failure      500  {object}  utils.ErrorResponse
// @Router       /auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c echo.Context) error {
	var req ForgotPasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, utils.ErrorResponse("Invalid request"))
	}

	if err := h.validator.Validate(req); err != nil {
		return c.JSON(http.StatusBadRequest, utils.ErrorResponse(err.Error()))
	}

	if err := h.authService.ForgotPassword(req.Email); err != nil {
		h.logger.Error("Forgot password failed", err, "email", req.Email)
		return utils.HandleError(c, err)
	}

	h.logger.Info("Password reset email sent", "email", req.Email)

	return c.JSON(http.StatusOK, utils.SuccessResponse(
		"Password reset instructions sent to your email",
		nil,
	))
}

// ResetPassword godoc
// @Summary      Reset password
// @Description  Reset password using token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body ResetPasswordRequest true "Reset data"
// @Success      200  {object}  utils.Response
// @Failure      400  {object}  utils.ErrorResponse
// @Failure      401  {object}  utils.ErrorResponse
// @Failure      500  {object}  utils.ErrorResponse
// @Router       /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c echo.Context) error {
	var req ResetPasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, utils.ErrorResponse("Invalid request"))
	}

	if err := h.validator.Validate(req); err != nil {
		return c.JSON(http.StatusBadRequest, utils.ErrorResponse(err.Error()))
	}

	if err := h.authService.ResetPassword(req.Token, req.NewPassword); err != nil {
		h.logger.Error("Reset password failed", err, "token", req.Token[:10]+"...")
		return utils.HandleError(c, err)
	}

	h.logger.Info("Password reset successful")

	return c.JSON(http.StatusOK, utils.SuccessResponse(
		"Password reset successful",
		nil,
	))
}

// VerifyEmail godoc
// @Summary      Verify email
// @Description  Verify email using token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body VerifyEmailRequest true "Verification token"
// @Success      200  {object}  utils.Response
// @Failure      400  {object}  utils.ErrorResponse
// @Failure      401  {object}  utils.ErrorResponse
// @Failure      500  {object}  utils.ErrorResponse
// @Router       /auth/verify-email [post]
func (h *AuthHandler) VerifyEmail(c echo.Context) error {
	var req VerifyEmailRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, utils.ErrorResponse("Invalid request"))
	}

	if err := h.validator.Validate(req); err != nil {
		return c.JSON(http.StatusBadRequest, utils.ErrorResponse(err.Error()))
	}

	if err := h.authService.VerifyEmail(req.Token); err != nil {
		h.logger.Error("Email verification failed", err, "token", req.Token[:10]+"...")
		return utils.HandleError(c, err)
	}

	h.logger.Info("Email verified successfully")

	return c.JSON(http.StatusOK, utils.SuccessResponse(
		"Email verified successfully",
		nil,
	))
}

// GetProfile godoc
// @Summary      Get user profile
// @Description  Get authenticated user profile
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  utils.Response{data=domain.User}
// @Failure      401  {object}  utils.ErrorResponse
// @Failure      500  {object}  utils.ErrorResponse
// @Router       /auth/profile [get]
func (h *AuthHandler) GetProfile(c echo.Context) error {
	userID := c.Get("user_id").(string)

	user, err := h.authService.GetProfile(userID)
	if err != nil {
		h.logger.Error("Get profile failed", err, "user_id", userID)
		return utils.HandleError(c, err)
	}

	return c.JSON(http.StatusOK, utils.SuccessResponse(
		"Profile retrieved successfully",
		user,
	))
}
