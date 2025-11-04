package service

import (
	"context"
	"errors"

	"authentio/internal/repository"
	"authentio/pkg/logger"
)

type TwoFAService struct {
	twoFARepo repository.TwoFARepository
	userRepo  repository.UserRepository
}

func NewTwoFAService(twoFARepo repository.TwoFARepository, userRepo repository.UserRepository) *TwoFAService {
	return &TwoFAService{twoFARepo: twoFARepo, userRepo: userRepo}
}

func (s *TwoFAService) EnableEmail2FA(ctx context.Context, userID int64) error {
	return s.twoFARepo.EnableEmail2FA(ctx, userID)
}

func (s *TwoFAService) Disable2FA(ctx context.Context, userID int64) error {
	return s.twoFARepo.Disable2FA(ctx, userID)
}

func (s *TwoFAService) Is2FAEnabled(ctx context.Context, userID int64) (bool, error) {
	return s.twoFARepo.Is2FAEnabled(ctx, userID)
}

func (s *TwoFAService) Get2FAMethod(ctx context.Context, userID int64) (string, error) {
	return s.twoFARepo.Get2FAMethod(ctx, userID)
}

// VerifyOTP verifies an OTP for a user by email. It resolves the userID from email.
func (s *TwoFAService) VerifyOTP(ctx context.Context, email, code, otpType string) (bool, error) {
	// Resolve user
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil || user == nil {
		logger.Info("verify otp: user not found", "email", email)
		return false, errors.New("user not found")
	}

	return s.twoFARepo.VerifyOTP(ctx, user.ID, email, code, otpType)
}
