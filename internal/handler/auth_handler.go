package handler

import (
	"net/http"
	
	"authentio/internal/config"
	"authentio/internal/models"
	"authentio/internal/service"
	"authentio/pkg/response"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// AuthHandler Structure and Constructor
// =============================================================================

// AuthHandler handles authentication-related HTTP endpoints.
type AuthHandler struct {
	authService service.AuthService
}

// NewAuthHandler creates a new AuthHandler with the given service.
func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// =============================================================================
// Token Management Endpoints
// =============================================================================

// Refresh godoc
// @Summary Refresh access token
// @Description Get a new access token using a valid refresh token
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body RefreshTokenRequest true "Refresh token request"
// @Success 200 {object} response.LoginResponse "New tokens generated successfully"
// @Failure 400 {object} map[string]string "Invalid or expired refresh token"
// @Router /auth/refresh [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

// =============================================================================
// Password Reset Flow Endpoints
// =============================================================================

// ForgotPassword godoc
// @Summary Request password reset
// @Description Send a password reset code to the user's email address
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body ForgotPasswordRequest true "Password reset request"
// @Success 200 {object} map[string]string "Password reset email sent successfully"
// @Failure 400 {object} map[string]string "Invalid email format"
// @Router /auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.authService.RequestPasswordReset(c.Request.Context(), req.Email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password reset email sent"})
}

// ResetPassword godoc
// @Summary Reset user password
// @Description Reset user password using verification code received via email
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body ResetPasswordRequest true "Password reset confirmation"
// @Success 200 {object} map[string]string "Password reset successful"
// @Failure 400 {object} map[string]string "Invalid code, email, or password requirements not met"
// @Router /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req struct {
		Email       string `json:"email" binding:"required,email"`
		Code        string `json:"code" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.authService.ResetPassword(c.Request.Context(), req.Email, req.Code, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful"})
}

// =============================================================================
// Two-Factor Authentication Endpoints
// =============================================================================

// Verify2FA godoc
// @Summary Verify two-factor authentication code
// @Description Verify the 2FA code sent to user's email during login process
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body Verify2FARequest true "2FA verification request"
// @Success 200 {object} map[string]string "2FA verification successful"
// @Failure 400 {object} map[string]string "Invalid or expired 2FA code"
// @Router /auth/2fa/verify [post]
func (h *AuthHandler) Verify2FA(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
		Code  string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.authService.Verify2FA(c.Request.Context(), req.Email, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "2FA verification successful"})
}

// =============================================================================
// Basic Authentication Endpoints
// =============================================================================

// Register godoc
// @Summary Register a new user
// @Description Create a new user account with email, password, and personal information
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body models.RegisterRequest true "User registration data"
// @Success 201 {object} response.RegisterResponse "User registered successfully"
// @Failure 400 {object} map[string]string "Invalid input data or validation failed"
// @Failure 409 {object} map[string]string "Email already exists"
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := Validate.Struct(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"validation_error": FormatValidationError(err)})
		return
	}

	var _ response.RegisterResponse

	resp, err := h.authService.Register(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, resp)
}

// Login godoc
// @Summary User login
// @Description Authenticate user with email and password, returns JWT tokens
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body models.LoginRequest true "User login credentials"
// @Success 200 {object} response.LoginResponse "Login successful with JWT tokens"
// @Failure 400 {object} map[string]string "Invalid input data"
// @Failure 401 {object} map[string]string "Invalid email or password"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := Validate.Struct(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"validation_error": FormatValidationError(err)})
		return
	}

	resp, err := h.authService.Login(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// =============================================================================
// Google OAuth2 Authentication Endpoints
// =============================================================================

// GoogleRedirect godoc
// @Summary Initiate Google OAuth redirect
// @Description Redirects user to Google OAuth consent screen for authentication
// @Tags authentication
// @Produce json
// @Success 302 "Redirect to Google OAuth"
// @Router /auth/google/redirect [get]
func (h *AuthHandler) GoogleRedirect(c *gin.Context) {
    url := config.GoogleOAuthConfig.AuthCodeURL("state")
    c.Redirect(http.StatusFound, url)
}

// GoogleLogin godoc
// @Summary Google OAuth login with ID token
// @Description Authenticate user using Google OAuth ID token (frontend flow)
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body GoogleLoginRequest true "Google ID token"
// @Success 200 {object} response.LoginResponse "Google authentication successful"
// @Failure 400 {object} map[string]string "Invalid ID token format"
// @Failure 401 {object} map[string]string "Invalid Google token"
// @Router /auth/google/login [post]
func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	var req struct {
		IDToken string `json:"id_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	resp, err := h.authService.GoogleAuth(c.Request.Context(), req.IDToken, config.GoogleOAuthConfig.ClientID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// GoogleCallback godoc
// @Summary Google OAuth callback handler
// @Description Handle Google OAuth callback with authorization code (server-side flow)
// @Tags authentication
// @Produce json
// @Param code query string true "Authorization code from Google"
// @Success 200 {object} response.LoginResponse "OAuth authentication successful"
// @Failure 400 {object} map[string]string "Missing authorization code"
// @Failure 401 {object} map[string]string "Failed to exchange code for tokens"
// @Router /auth/google/callback [get]
func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing authorization code"})
		return
	}

	// Exchange code for tokens + verify ID token
	resp, err := h.authService.GoogleCallback(c.Request.Context(), code, config.GoogleOAuthConfig)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}