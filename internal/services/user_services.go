package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mayart-ai/auth-service/internal/models"
	"github.com/mayart-ai/auth-service/internal/repositories"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
  userRepo *repositories.UserRepo	
}

const dbTimeout = 3 * time.Second

// New is the function used to create an instance of the service package. 
// It returns the type UserService.
func New(userRepo *repositories.UserRepo) *UserService {
  return &UserService{userRepo: userRepo}
}

func (s *UserService) GetAll(ctx context.Context) ([]*models.User, error) {
  ctx, cancel := context.WithTimeout(ctx, dbTimeout)
  defer cancel() 

  return s.userRepo.GetAll(ctx)
}

func (s *UserService) GetById(ctx context.Context, id int) (*models.User, error) {
	// Validate the input user data
	if id == 0 {
		return nil, fmt.Errorf("user ID must be provided")
	}

  ctx, cancel := context.WithTimeout(ctx, dbTimeout)
  defer cancel() 

  return s.userRepo.GetById(ctx, id)
}

func (s *UserService) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	if email == "" {
		return nil, fmt.Errorf("user email must be provided")
	}

  ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
  defer cancel() 

  return s.userRepo.GetByEmail(ctx, email)
}

// Update updates the fields of a user. Only non-zero or non-empty fields in the user struct will be updated.
func (s *UserService) Update(ctx context.Context, u models.User) error {
	if u.ID == 0 {
		return fmt.Errorf("user ID must be provided")
	}

  ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	// Call the repository's Update method
	err := s.userRepo.Update(ctx, u)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func (s *UserService) DeleteByID(ctx context.Context, id int) error {
	if id == 0 {
		return fmt.Errorf("user ID must be provided")
	}

	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
  defer cancel()

  return s.userRepo.DeleteByID(ctx, id)
}

func (s *UserService) Insert(u models.User) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
  defer cancel()

  return s.userRepo.Insert(ctx, u) 
}

// ResetPassword is the method used to change a user's password.
func (s *UserService) ResetPassword(ctx context.Context, user *models.User) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

  // Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Create a user struct with the new password
	u := models.User{
		ID:       user.ID,                  // Specify the user ID
		Password: string(hashedPassword), // Update the password field
	}

  return s.userRepo.Update(ctx, u)
}

// PasswordMatches uses Go's bcrypt package to compare a user supplied password
// with the hash we have stored for a given user in the database. If the password
// and hash match, we return true; otherwise, we return false.
func (s *UserService) PasswordMatches(plainText string, u *models.User) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(plainText))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword): // invalid password
			return false, nil
		default:
			return false, fmt.Errorf("Error comparing password for user ID %d: %v", u.ID, err)
		}
	}

  // Passwords matches
	return true, nil
}
