package service

import (
	"authentio/internal/models"
	"authentio/internal/repository"
	"context"
)

type TokenService struct {
	tokenRepo repository.TokenRepository
}

func NewTokenService(tokenRepo repository.TokenRepository) *TokenService {
	return &TokenService{tokenRepo: tokenRepo}
}

// SaveRefreshToken stores a new refresh token
func (s *TokenService) SaveRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	return s.tokenRepo.SaveRefreshToken(ctx, token)
}

// GetRefreshToken retrieves a refresh token by its token string
func (s *TokenService) GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	return s.tokenRepo.GetRefreshToken(ctx, token)
}

// DeleteRefreshToken removes a refresh token
func (s *TokenService) DeleteRefreshToken(ctx context.Context, token string) error {
	return s.tokenRepo.DeleteRefreshToken(ctx, token)
}

// DeleteUserRefreshTokens removes all refresh tokens for a specific user
func (s *TokenService) DeleteUserRefreshTokens(ctx context.Context, userID int64) error {
	return s.tokenRepo.DeleteUserRefreshTokens(ctx, userID)
}

// CleanupExpiredTokens removes all expired refresh tokens
func (s *TokenService) CleanupExpiredTokens(ctx context.Context) error {
	return s.tokenRepo.CleanupExpiredTokens(ctx)
}
