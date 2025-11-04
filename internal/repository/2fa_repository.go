package repository

import (
	"context"
	_"authentio/internal/models"
	_"errors"
)

type TwoFARepository interface {

// EnableEmail2FA enables email-based 2FA for a user
	EnableEmail2FA(ctx context.Context, userID int64) error
	
	// Disable2FA disables 2FA for a user
	Disable2FA(ctx context.Context, userID int64) error
	
	// Is2FAEnabled checks if 2FA is enabled for a user
	Is2FAEnabled(ctx context.Context, userID int64) (bool, error)
	
	// Get2FAMethod returns the 2FA method (e.g., "email", "sms", "totp")
	Get2FAMethod(ctx context.Context, userID int64) (string, error)

	// VerifyOTP verifies an OTP code for 2FA
	VerifyOTP(ctx context.Context, userID int64, email, code, otpType string) (bool, error)
}