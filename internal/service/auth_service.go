package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"authentio/internal/constants"
	"authentio/internal/models"
	"authentio/internal/repository"
	"authentio/pkg/jwt"
	"authentio/pkg/logger"
	"authentio/pkg/password"
	"authentio/pkg/response"
)

type AuthService struct {
	userRepo    repository.UserRepository
	twoFARepo   repository.TwoFARepository
	otpRepo     repository.OTPRepository
	tokenRepo   repository.TokenRepository
	jwtManager  *jwt.Manager
}

// NewAuthService constructs the AuthService with its dependencies.
func NewAuthService(
	userRepo repository.UserRepository,
	twoFARepo repository.TwoFARepository,
	otpRepo repository.OTPRepository,
	tokenRepo repository.TokenRepository,
	jwtManager *jwt.Manager,
) *AuthService {
	return &AuthService{
		userRepo:   userRepo,
		otpRepo:    otpRepo,
		twoFARepo:  twoFARepo,
		tokenRepo:  tokenRepo,
		jwtManager: jwtManager,
	}
}

type RegisterResponse struct {
	User    response.UserResponse `json:"user"`
	Message string                `json:"message"`
}

// LoginResponse is returned after successful login
type LoginResponse struct {
	User         response.UserResponse `json:"user"`
	AccessToken  string               `json:"access_token"`
	RefreshToken string               `json:"refresh_token"`
	ExpiresIn    int                  `json:"expires_in"`    // Access token expiration in seconds
}

// Register handles user registration flow.
func (s *AuthService) Register(ctx context.Context, req models.RegisterRequest)  (*RegisterResponse, error) {
	existingUser, _ := s.userRepo.FindByEmail(ctx, req.Email)
	if existingUser != nil {
		return nil, errors.New("email already exists")
	}

	hashed, err := password.Hash(req.Password)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		FirstName: req.FirstName,  // Add firstName
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  hashed,
		IsActive:  true,
		BaseModel: models.BaseModel{
            CreatedAt: time.Now(),
            UpdatedAt: time.Now(),
    },
	}


	if err := s.userRepo.Create(ctx, user); err != nil {
		 return nil, err
	}

		// Convert to response DTO
	userResponse := response.UserResponse{
		ID:       user.ID,
		FirstName: user.FirstName,  // Add firstName
		LastName:  user.LastName,  
		Email:    user.Email,
		IsActive: user.IsActive,
	}

	// logger.Info("user registered", "email", req.Email)

	logger.Info("user registered", "email", req.Email)
      return &RegisterResponse{
	User:  userResponse,
	Message: "Registration successful",
	}, nil
}

// Login validates credentials and returns a signed JWT.
func (s *AuthService) Login(ctx context.Context, req models.LoginRequest) (*LoginResponse, error) {
	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil || user == nil {
		return nil, errors.New("invalid email or password")
	}

	if !password.Check(req.Password, user.Password) {
		return nil, errors.New("invalid credentials")
	}

	// Generate access token
	accessToken, err := s.jwtManager.GenerateToken(user.ID, user.Email, user.FirstName, user.LastName)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken := &models.RefreshToken{
		UserID: user.ID,
		Token:  generateSecureToken(), // We'll implement this
		// ExpiredAt: time.Now().Add(30 * 24 * time.Hour), // 30 days
		BaseModel: models.BaseModel{
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			ExpiredAt: timePtr(time.Now().Add(30 * 24 * time.Hour)),
		},
	}

	
	// Save refresh token
	if err := s.tokenRepo.SaveRefreshToken(ctx, refreshToken); err != nil {
		return nil, err
	}
	
	// Convert to response DTO
	userResponse := response.UserResponse{
		ID:        user.ID, 
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		IsActive:  user.IsActive,
	}

	logger.Info("user logged in", "email", req.Email)

	return &LoginResponse{
		User:         userResponse,
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
		ExpiresIn:    3600, // 1 hour - should match your JWT expiration
	}, nil
}

// GetUserProfile returns user profile without sensitive data
func (s *AuthService) GetUserProfile(ctx context.Context, userID int64) (*response.UserResponse, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	userResponse := &response.UserResponse{
		ID:       user.ID,
		FirstName: user.FirstName,  // Add firstName
		LastName:  user.LastName, 
		Email:    user.Email,
		IsActive: user.IsActive,
	}

	return userResponse, nil
}

// Verify2FA checks OTP validity and activates user 2FA.
func (s *AuthService) Verify2FA(ctx context.Context, email, code string) error {
	valid, err := s.otpRepo.VerifyOTP(ctx, email, code, string(constants.Type2FA))
	if err != nil || !valid {
		return errors.New("invalid or expired code")
	}
	return nil
}

// RequestPasswordReset initiates password reset flow
func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) error {
	// Check if user exists (but don't reveal if they don't)
	user, _ := s.userRepo.FindByEmail(ctx, email)
	if user == nil {
		// Still return success to prevent email enumeration
		logger.Info("Password reset requested for non-existent email", "email", email)
		return nil
	}

	// Generate OTP code
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

	// TODO: Send email with the code
	logger.Info("Password reset code generated", "email", email, "code", code)

	return nil
}

// ResetPassword resets user password after OTP verification
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

	logger.Info("Password reset successful", "email", email)
	return nil
}

// EnableEmail2FA enables email-based 2FA for a user
func (s *AuthService) EnableEmail2FA(ctx context.Context, userID int64) error {
	return s.twoFARepo.EnableEmail2FA(ctx, userID)
}

// Disable2FA disables 2FA for a user
func (s *AuthService) Disable2FA(ctx context.Context, userID int64) error {
	return s.twoFARepo.Disable2FA(ctx, userID)
}

// Is2FAEnabled checks if 2FA is enabled for a user
func (s *AuthService) Is2FAEnabled(ctx context.Context, userID int64) (bool, error) {
	return s.twoFARepo.Is2FAEnabled(ctx, userID)
}

// Send2FAOTP generates and sends a 2FA OTP code
func (s *AuthService) Send2FAOTP(ctx context.Context, email string) error {
	// Check if user exists
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Generate OTP code
	code := generateRandomCode(6)

	// Store OTP with 2fa type
	otp := &models.OTP{
		UserID: &user.ID,
		Email:  email,
		Code:   code,
		Type:   string(constants.Type2FA),
	}

	if err := s.otpRepo.CreateOTP(ctx, otp); err != nil {
		return err
	}

	// TODO: Send email with the code
	logger.Info("2FA code sent", "email", email, "code", code)

	return nil
}

// UpdateProfile updates user profile information
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

	logger.Info("profile updated", "userID", userID)
	return nil
}

// RefreshToken generates new access token using a refresh token
func (s *AuthService) RefreshToken(ctx context.Context, refreshTokenStr string) (*LoginResponse, error) {
	// Get the refresh token from database
	token, err := s.tokenRepo.GetRefreshToken(ctx, refreshTokenStr)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Get the user
	user, err := s.userRepo.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Generate new access token
	accessToken, err := s.jwtManager.GenerateToken(user.ID, user.Email, user.FirstName, user.LastName)
	if err != nil {
		return nil, err
	}

	// Optional: Rotate refresh token for better security
	// Delete old refresh token
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

	return &LoginResponse{
		User:         userResponse,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken.Token,
		ExpiresIn:    3600,
	}, nil
}



// Logout invalidates the refresh token
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	return s.tokenRepo.DeleteRefreshToken(ctx, refreshToken)
}

// LogoutAll invalidates all refresh tokens for a user
func (s *AuthService) LogoutAll(ctx context.Context, userID int64) error {
	return s.tokenRepo.DeleteUserRefreshTokens(ctx, userID)
}

// Helper function to generate random code
func generateRandomCode(length int) string {
	const digits = "0123456789"
	bytes := make([]byte, length)
	for i := range bytes {
		bytes[i] = digits[time.Now().UnixNano()%int64(len(digits))]
	}
	return string(bytes)
}

// Helper function to generate secure random token
func generateSecureToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(err) // Should never happen
	}
	return hex.EncodeToString(bytes)
}

// Helper to create time pointer
      func timePtr(t time.Time) *time.Time {
        return &t
      }