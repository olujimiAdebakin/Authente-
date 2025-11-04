package service

import (
	"authentio/internal/models"
	"authentio/internal/repository"
	"context"
)

type UserService struct {
	userRepo repository.UserRepository
}

func NewUserService(userRepo repository.UserRepository) *UserService {
	return &UserService{userRepo: userRepo}
}

func (s *UserService) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.userRepo.FindByEmail(ctx, email)
}

func (s *UserService) FindByID(ctx context.Context, id int64) (*models.User, error) {
	return s.userRepo.FindByID(ctx, id)
}

func (s *UserService) Create(ctx context.Context, user *models.User) error {
	return s.userRepo.Create(ctx, user)
}

func (s *UserService) Update(ctx context.Context, user *models.User) error {
	return s.userRepo.Update(ctx, user)
}

func (s *UserService) Delete(ctx context.Context, id int64) error {
	return s.userRepo.Delete(ctx, id)
}
