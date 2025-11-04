package database

import (
	_ "authentio/internal/models"
	"authentio/internal/repository"
	"context"
	"database/sql"
	"errors"
)

type twoFARepository struct {
	db *sql.DB
}

func NewTwoFARepository(db *sql.DB) repository.TwoFARepository {
	return &twoFARepository{db: db}
}

func (r *twoFARepository) EnableEmail2FA(ctx context.Context, userID int64) error {
	// For email OTP, secret is not used
	query := `
		INSERT INTO two_fa_configs (user_id, method, secret, enabled) 
		VALUES ($1, 'email', '', TRUE)
		ON CONFLICT (user_id) 
		DO UPDATE SET method = 'email', enabled = TRUE, updated_at = CURRENT_TIMESTAMP`
	
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *twoFARepository) Disable2FA(ctx context.Context, userID int64) error {
	query := `UPDATE two_fa_configs SET enabled = FALSE WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *twoFARepository) Is2FAEnabled(ctx context.Context, userID int64) (bool, error) {
	query := `SELECT enabled FROM two_fa_configs WHERE user_id = $1`
	
	var enabled bool
	err := r.db.QueryRowContext(ctx, query, userID).Scan(&enabled)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	
	return enabled, nil
}

func (r *twoFARepository) Get2FASecret(ctx context.Context, userID int64) (string, error) {
	// Not used for email OTP
	return "", errors.New("not applicable for email OTP")
}

func (r *twoFARepository) VerifyOTP(ctx context.Context, userID int64,email, code, otpType string) (bool, error) {
	// This method is not used for email OTP
	// Email OTP verification is handled by OTPRepository
	return false, errors.New("use OTPRepository for email OTP verification")
}

// Get2FAMethod returns the 2FA method (e.g., "email", "sms", "totp") for a user
func (r *twoFARepository) Get2FAMethod(ctx context.Context, userID int64) (string, error) {
	query := `SELECT method FROM two_fa_configs WHERE user_id = $1`
	var method string
	err := r.db.QueryRowContext(ctx, query, userID).Scan(&method)
	if err == sql.ErrNoRows {
		return "", nil // No 2FA method set
	}
	if err != nil {
		return "", err
	}
	return method, nil
}