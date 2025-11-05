package handler

// =============================================================================
// REQUEST DATA TRANSFER OBJECTS (DTOs)
// =============================================================================
// This file contains all request structures used in HTTP endpoints.
// These DTOs define the expected input format for API requests and are used
// for both request binding and Swagger documentation generation.
// =============================================================================

// =============================================================================
// TOKEN MANAGEMENT REQUEST DTOs
// =============================================================================

// RefreshTokenRequest represents a request to refresh access tokens
// Used in: POST /auth/refresh
type RefreshTokenRequest struct {
    RefreshToken string `json:"refresh_token" binding:"required"`  // Valid refresh token to exchange for new access token
}

// =============================================================================
// PASSWORD MANAGEMENT REQUEST DTOs
// =============================================================================

// ForgotPasswordRequest represents a password reset initiation request
// Used in: POST /auth/forgot-password
type ForgotPasswordRequest struct {
    Email string `json:"email" binding:"required,email"`  // User's registered email address
}

// ResetPasswordRequest represents a password reset confirmation request
// Used in: POST /auth/reset-password
type ResetPasswordRequest struct {
    Email       string `json:"email" binding:"required,email"`        // User's registered email address
    Code        string `json:"code" binding:"required"`               // OTP code received via email
    NewPassword string `json:"new_password" binding:"required,min=8"` // New password (minimum 8 characters)
}

// =============================================================================
// TWO-FACTOR AUTHENTICATION REQUEST DTOs
// =============================================================================

// Verify2FARequest represents a two-factor authentication verification request
// Used in: POST /auth/2fa/verify
type Verify2FARequest struct {
    Email string `json:"email" binding:"required,email"`  // User's email address
    Code  string `json:"code" binding:"required"`         // 2FA verification code
}

// SendOTPRequest represents a request to send OTP for two-factor authentication
// Used in: POST /2fa/sendOtp
type SendOTPRequest struct {
    Email string `json:"email" binding:"required,email"`  // Email address to send OTP to
}

// VerifyOTPRequest represents a request to verify OTP for two-factor authentication
// Used in: POST /2fa/verifyOtp
type VerifyOTPRequest struct {
    Email string `json:"email" binding:"required,email"`  // User's email address
    Code  string `json:"code" binding:"required"`         // OTP code to verify
}

// =============================================================================
// OAUTH2 AUTHENTICATION REQUEST DTOs
// =============================================================================

// GoogleLoginRequest represents a Google OAuth2 authentication request
// Used in: POST /auth/google/login
type GoogleLoginRequest struct {
    IDToken string `json:"id_token" binding:"required"`  // Google ID token from frontend OAuth flow
}


// =============================================================================
// USER MANAGEMENT REQUEST DTOs
// =============================================================================

// UpdateProfileRequest represents a user profile update request
// Used in: PUT /user/updateProfile
type UpdateProfileRequest struct {
    FirstName string `json:"first_name"`                   // User's first name
    LastName  string `json:"last_name"`                    // User's last name
    Email     string `json:"email" binding:"omitempty,email"`  // User's email address (optional update)
}

// =============================================================================
// END OF REQUEST DTOs
// =============================================================================


