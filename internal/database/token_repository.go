package database

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"authentio/internal/models"
	"authentio/internal/repository"
)

type tokenRepository struct {
	db *sql.DB
}

// NewTokenRepository creates a new TokenRepository instance
func NewTokenRepository(db *sql.DB) repository.TokenRepository {
	return &tokenRepository{db: db}
}

// SaveRefreshToken stores a new refresh token
func (r *tokenRepository) SaveRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (user_id, token, expires_at, created_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id`

	err := r.db.QueryRowContext(ctx, query,
		token.UserID,
		token.Token,
		token.ExpiredAt,
		time.Now(),
	).Scan(&token.ID)

	if err != nil {
		return err
	}

	return nil
}

// GetRefreshToken retrieves a refresh token by its token string
func (r *tokenRepository) GetRefreshToken(ctx context.Context, tokenStr string) (*models.RefreshToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, created_at
		FROM refresh_tokens
		WHERE token = $1 AND expires_at > $2`

	token := &models.RefreshToken{}
	err := r.db.QueryRowContext(ctx, query, tokenStr, time.Now()).Scan(
		&token.ID,
		&token.UserID,
		&token.Token,
		&token.ExpiredAt,
		&token.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("token not found or expired")
	}
	if err != nil {
		return nil, err
	}

	return token, nil
}

// DeleteRefreshToken removes a refresh token
func (r *tokenRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	query := `DELETE FROM refresh_tokens WHERE token = $1`
	result, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return errors.New("token not found")
	}

	return nil
}

// DeleteUserRefreshTokens removes all refresh tokens for a specific user
func (r *tokenRepository) DeleteUserRefreshTokens(ctx context.Context, userID int64) error {
	query := `DELETE FROM refresh_tokens WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

// CleanupExpiredTokens removes all expired refresh tokens
func (r *tokenRepository) CleanupExpiredTokens(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at <= $1`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}