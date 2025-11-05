package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"authentio/internal/constants"
	"authentio/internal/models"
	"authentio/internal/repository"
	"authentio/pkg/email"
	"authentio/pkg/jwt"
	"authentio/pkg/logger"
	"authentio/pkg/password"
	"authentio/pkg/response"

	"google.golang.org/api/idtoken"
	"golang.org/x/oauth2"
)

// ============================================================================
// AuthService Structure
// ============================================================================

// AuthService handles all authentication-related business logic including
// registration, login, password reset, 2FA, and OAuth flows.
type AuthService struct {
	userRepo     repository.UserRepository
	twoFARepo    repository.TwoFARepository
	otpRepo      repository.OTPRepository
	tokenRepo    repository.TokenRepository
	jwtManager   *jwt.Manager
	emailClient  *email.Client
	googleClient *oauth2.Config
}

// ============================================================================
// Constructor
// ============================================================================

// NewAuthService constructs the AuthService with its dependencies.
func NewAuthService(
	userRepo repository.UserRepository,
	twoFARepo repository.TwoFARepository,
	otpRepo repository.OTPRepository,
	tokenRepo repository.TokenRepository,
	jwtManager *jwt.Manager,
	emailClient *email.Client,
	googleClient *oauth2.Config,
) *AuthService {
	return &AuthService{
		userRepo:     userRepo,
		twoFARepo:    twoFARepo,
		otpRepo:      otpRepo,
		tokenRepo:    tokenRepo,
		jwtManager:   jwtManager,
		emailClient:  emailClient,
		googleClient: googleClient,
	}
}

// ============================================================================
// Core Authentication Methods
// ============================================================================

// Register handles user registration flow including validation, user creation,
// and sending welcome email.
func (s *AuthService) Register(ctx context.Context, req models.RegisterRequest) (*response.RegisterResponse, error) {
	// Check if email already exists
	existingUser, _ := s.userRepo.FindByEmail(ctx, req.Email)
	if existingUser != nil {
		return nil, errors.New("email already exists")
	}

	// Hash password before storage
	hashed, err := password.Hash(req.Password)
	if err != nil {
		return nil, err
	}

	// Create user entity
	user := &models.User{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  hashed,
		IsActive:  true,
		BaseModel: models.BaseModel{
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	// Persist user to database
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Send welcome email (non-blocking, log errors but don't fail registration)
	go s.sendWelcomeEmail(user.Email, user.FirstName)

	// Convert to response DTO
	userResponse := response.UserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		IsActive:  user.IsActive,
	}

	logger.Info("user registered successfully", "email", req.Email)

	return &response.RegisterResponse{
		User:    userResponse,
		Message: "Registration successful",
	}, nil
}

// Login validates user credentials and returns JWT tokens upon successful authentication.
func (s *AuthService) Login(ctx context.Context, req models.LoginRequest) (*response.LoginResponse, error) {
	// Find user by email
	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil || user == nil {
		return nil, errors.New("invalid email or password")
	}

	// Verify password
	if !password.Check(req.Password, user.Password) {
		return nil, errors.New("invalid credentials")
	}

	// Generate authentication response with tokens
	return s.generateAuthResponse(user)
}

// ============================================================================
// OAuth Authentication Methods
// ============================================================================

// GoogleAuth handles Google OAuth authentication by validating ID tokens
// and creating new users or logging in existing ones.
func (s *AuthService) GoogleAuth(ctx context.Context, idTokenStr string, audience string) (*response.LoginResponse, error) {
	// Validate the Google ID token
	payload, err := idtoken.Validate(ctx, idTokenStr, audience)
	if err != nil {
		return nil, fmt.Errorf("invalid Google token: %w", err)
	}

	// Extract user information from token claims
	email, _ := payload.Claims["email"].(string)
	firstName, _ := payload.Claims["given_name"].(string)
	lastName, _ := payload.Claims["family_name"].(string)

	if email == "" {
		return nil, errors.New("invalid token payload: missing email")
	}

	// Check if user exists, create if new
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err == sql.ErrNoRows {
		// Create new user for Google OAuth
		user = &models.User{
			Email:     email,
			FirstName: firstName,
			LastName:  lastName,
			IsActive:  true,
			Provider:  "google",
			BaseModel: models.BaseModel{
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		}

		if err := s.userRepo.Create(ctx, user); err != nil {
			return nil, err
		}

		// Send welcome email for new Google OAuth users
		go s.sendWelcomeEmail(user.Email, user.FirstName)
	} else if err != nil {
		return nil, err
	}

	// Generate authentication response
	return s.generateAuthResponse(user)
}

// GoogleCallback handles the OAuth callback flow by exchanging authorization code
// for tokens and processing the authentication.
func (s *AuthService) GoogleCallback(ctx context.Context, code string, oauthConfig *oauth2.Config) (*response.LoginResponse, error) {
	// Exchange authorization code for tokens
	token, err := s.googleClient.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Extract ID token from response
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("no id_token in response")
	}

	// Reuse GoogleAuth to validate ID token and login/create user
	return s.GoogleAuth(ctx, rawIDToken, oauthConfig.ClientID)
}

// ============================================================================
// Password Reset Flow
// ============================================================================

// RequestPasswordReset initiates the password reset flow by generating a reset code
// and sending it to the user's email.
func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) error {
	// Check if user exists (but don't reveal if they don't to prevent email enumeration)
	user, _ := s.userRepo.FindByEmail(ctx, email)
	if user == nil {
		logger.Info("password reset requested for non-existent email", "email", email)
		return nil // Return success to prevent email enumeration
	}

	// Generate reset code
	code := generateRandomCode(6)

	// Store OTP with password_reset type
	otp := &models.OTP{
		UserID: &user.ID,
		Email:  email,
		Code:   code,
		Type:   string(constants.TypePasswordReset),
	}

	if err := s.otpRepo.CreateOTP(ctx, otp); err != nil {
		return err
	}

	// Send password reset email
	if err := s.emailClient.SendPasswordReset(email, code); err != nil {
		logger.Error("failed to send password reset email", "error", err, "email", email)
		return fmt.Errorf("failed to send reset email")
	}

	logger.Info("password reset code sent", "email", email)
	return nil
}

// ResetPassword verifies the reset code and updates the user's password.
func (s *AuthService) ResetPassword(ctx context.Context, email, code, newPassword string) error {
	// Verify the reset code
	valid, err := s.otpRepo.VerifyOTP(ctx, email, code, string(constants.TypePasswordReset))
	if err != nil || !valid {
		return errors.New("invalid or expired reset code")
	}

	// Find the user
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Hash new password
	hashedPassword, err := password.Hash(newPassword)
	if err != nil {
		return err
	}

	// Update user's password
	user.Password = hashedPassword
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	// Send password change confirmation email
	if err := s.emailClient.Send(
		[]string{email},
		"Password Changed Successfully",
		"<p>Your password has been successfully changed.</p><p>If you didn't make this change, please contact support immediately.</p>",
	); err != nil {
		logger.Warn("failed to send password change confirmation email", "error", err, "email", email)
		// Don't return error - password was already changed successfully
	}

	logger.Info("password reset successful", "email", email)
	return nil
}

// ============================================================================
// Two-Factor Authentication (2FA) Methods
// ============================================================================

// Send2FAOTP generates and sends a 2FA OTP code to the user's email.
func (s *AuthService) Send2FAOTP(ctx context.Context, email string) error {
	// Check if user exists
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Generate OTP code
	code := generateRandomCode(6)

	// Store OTP with 2FA type
	otp := &models.OTP{
		UserID: &user.ID,
		Email:  email,
		Code:   code,
		Type:   string(constants.Type2FA),
	}

	if err := s.otpRepo.CreateOTP(ctx, otp); err != nil {
		return err
	}

	// Send OTP via email
	if err := s.emailClient.SendOTP(email, code); err != nil {
		logger.Error("failed to send 2FA email", "error", err, "email", email)
		return fmt.Errorf("failed to send verification email")
	}

	logger.Info("2FA code sent via email", "email", email)
	return nil
}

// Verify2FA checks OTP validity for 2FA verification.
func (s *AuthService) Verify2FA(ctx context.Context, email, code string) error {
	valid, err := s.otpRepo.VerifyOTP(ctx, email, code, string(constants.Type2FA))
	if err != nil || !valid {
		return errors.New("invalid or expired code")
	}
	return nil
}

// EnableEmail2FA enables email-based 2FA for a user.
func (s *AuthService) EnableEmail2FA(ctx context.Context, userID int64) error {
	return s.twoFARepo.EnableEmail2FA(ctx, userID)
}

// Disable2FA disables 2FA for a user.
func (s *AuthService) Disable2FA(ctx context.Context, userID int64) error {
	return s.twoFARepo.Disable2FA(ctx, userID)
}

// Is2FAEnabled checks if 2FA is enabled for a user.
func (s *AuthService) Is2FAEnabled(ctx context.Context, userID int64) (bool, error) {
	return s.twoFARepo.Is2FAEnabled(ctx, userID)
}

// ============================================================================
// Token Management
// ============================================================================

// RefreshToken generates new access token using a valid refresh token.
func (s *AuthService) RefreshToken(ctx context.Context, refreshTokenStr string) (*response.LoginResponse, error) {
	// Get the refresh token from database
	token, err := s.tokenRepo.GetRefreshToken(ctx, refreshTokenStr)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Get the user associated with the refresh token
	user, err := s.userRepo.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Generate new access token
	accessToken, err := s.jwtManager.GenerateToken(user.ID, user.Email, user.FirstName, user.LastName)
	if err != nil {
		return nil, err
	}

	// Token rotation: delete old refresh token for security
	if err := s.tokenRepo.DeleteRefreshToken(ctx, refreshTokenStr); err != nil {
		logger.Error("failed to delete old refresh token", "error", err)
	}

	// Generate new refresh token
	newRefreshToken := &models.RefreshToken{
		UserID: user.ID,
		Token:  generateSecureToken(),
		BaseModel: models.BaseModel{
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			ExpiredAt: timePtr(time.Now().Add(30 * 24 * time.Hour)),
		},
	}

	// Save new refresh token
	if err := s.tokenRepo.SaveRefreshToken(ctx, newRefreshToken); err != nil {
		return nil, err
	}

	userResponse := response.UserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		IsActive:  user.IsActive,
	}

	return &response.LoginResponse{
		User:         userResponse,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken.Token,
		ExpiresIn:    3600, // 1 hour in seconds
	}, nil
}

// Logout invalidates a specific refresh token.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	return s.tokenRepo.DeleteRefreshToken(ctx, refreshToken)
}

// LogoutAll invalidates all refresh tokens for a user.
func (s *AuthService) LogoutAll(ctx context.Context, userID int64) error {
	return s.tokenRepo.DeleteUserRefreshTokens(ctx, userID)
}

// ============================================================================
// Profile Management
// ============================================================================

// GetUserProfile returns user profile without sensitive data.
func (s *AuthService) GetUserProfile(ctx context.Context, userID int64) (*response.UserResponse, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	userResponse := &response.UserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		IsActive:  user.IsActive,
	}

	return userResponse, nil
}

// UpdateProfile updates user profile information.
func (s *AuthService) UpdateProfile(ctx context.Context, userID int64, firstName, lastName, email string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// If email is being changed, check it's not already taken
	if email != "" && email != user.Email {
		existingUser, _ := s.userRepo.FindByEmail(ctx, email)
		if existingUser != nil {
			return errors.New("email already exists")
		}
		user.Email = email
	}

	// Update other fields if provided
	if firstName != "" {
		user.FirstName = firstName
	}
	if lastName != "" {
		user.LastName = lastName
	}

	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	logger.Info("profile updated successfully", "userID", userID)
	return nil
}

// ============================================================================
// Email Methods
// ============================================================================

// sendWelcomeEmail sends a welcome email to new users after successful registration.
// This method runs asynchronously and logs errors without failing the main operation.
func (s *AuthService) sendWelcomeEmail(email, firstName string) {
	subject := "Welcome to Authentio! 🎉"
	body := fmt.Sprintf(`
		<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
			<h1 style="color: #2563eb;">Welcome to Authentio, %s!</h1>
			<p>Thank you for joining our secure authentication service. We're excited to have you on board!</p>
			
			<div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
				<h3 style="color: #2563eb; margin-top: 0;">Getting Started:</h3>
				<ul>
					<li>Explore your user dashboard</li>
					<li>Set up two-factor authentication for enhanced security</li>
					<li>Update your profile information</li>
				</ul>
			</div>
			
			<p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
			
			<p style="color: #6b7280; font-size: 14px; margin-top: 30px;">
				Best regards,<br>
				<strong>The Authentio Team</strong>
			</p>
		</div>
	`, firstName)

	if err := s.emailClient.Send([]string{email}, subject, body); err != nil {
		logger.Error("failed to send welcome email", "error", err, "email", email)
	} else {
		logger.Info("welcome email sent successfully", "email", email)
	}
}

// ============================================================================
// Internal Helper Methods
// ============================================================================

// generateAuthResponse creates authentication tokens and returns a unified login response.
func (s *AuthService) generateAuthResponse(user *models.User) (*response.LoginResponse, error) {
	// Generate access token
	accessToken, err := s.jwtManager.GenerateToken(user.ID, user.Email, user.FirstName, user.LastName)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken := &models.RefreshToken{
		UserID: user.ID,
		Token:  generateSecureToken(),
		BaseModel: models.BaseModel{
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			ExpiredAt: timePtr(time.Now().Add(30 * 24 * time.Hour)), // 30 days
		},
	}

	// Save refresh token to database
	if err := s.tokenRepo.SaveRefreshToken(context.Background(), refreshToken); err != nil {
		return nil, err
	}

	// Create user response DTO
	userResponse := response.UserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		IsActive:  user.IsActive,
	}

	logger.Info("authentication tokens generated", "email", user.Email)

	return &response.LoginResponse{
		User:         userResponse,
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
		ExpiresIn:    3600, // 1 hour in seconds
	}, nil
}

// ============================================================================
// Utility Functions
// ============================================================================

// generateRandomCode generates a random numeric code of specified length.
func generateRandomCode(length int) string {
	const digits = "0123456789"
	bytes := make([]byte, length)
	for i := range bytes {
		bytes[i] = digits[time.Now().UnixNano()%int64(len(digits))]
	}
	return string(bytes)
}

// generateSecureToken generates a cryptographically secure random token.
func generateSecureToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(err) // Should never happen with proper system entropy
	}
	return hex.EncodeToString(bytes)
}

// timePtr returns a pointer to a time.Time value.
func timePtr(t time.Time) *time.Time {
	return &t
}