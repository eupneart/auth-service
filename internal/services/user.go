package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/eupneart/auth-service/internal/models"
	"github.com/eupneart/auth-service/internal/repositories"
	"github.com/eupneart/auth-service/utils"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	userRepo repositories.UserRepoInterface
}

const dbTimeout = 3 * time.Second

// New is the function used to create an instance of the service package.
// It returns the type UserService.
func New(userRepo repositories.UserRepoInterface) *UserService {
	return &UserService{userRepo: userRepo}
}

func (s *UserService) GetAll(ctx context.Context) ([]*models.User, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	users, err := s.userRepo.GetAll(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get all users from repository",
			"error", err,
			"method", "UserService.GetAll")
		return nil, err
	}

	slog.InfoContext(ctx, "successfully retrieved all users",
		"user_count", len(users),
		"method", "UserService.GetAll")

	return users, nil
}

func (s *UserService) GetByID(ctx context.Context, id int64) (*models.User, error) {
	// Validate the input user data
	if id == 0 {
		slog.WarnContext(ctx, "invalid user ID provided (zero value)",
			"id", id,
			"method", "UserService.GetByID")
		return nil, fmt.Errorf("user ID must be provided")
	}

	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by ID from repository",
			"error", err,
			"id", id,
			"method", "UserService.GetByID")
		return nil, err
	}
	if user == nil {
		slog.WarnContext(ctx, "user repository returned nil user",
			"id", id,
			"method", "UserService.GetByID")
		return nil, nil
	}

	slog.InfoContext(ctx, "successfully retrieved user by ID",
		"id", id,
		"email", user.Email,
		"method", "UserService.GetByID")

	return user, nil
}

func (s *UserService) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	if email == "" {
		slog.WarnContext(ctx, "empty email provided",
			"email", email,
			"method", "UserService.GetByEmail")
		return nil, fmt.Errorf("user email must be provided")
	}

	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by email from repository",
			"error", err,
			"email", email,
			"method", "UserService.GetByEmail")
		return nil, err
	}

	if user != nil {
		slog.InfoContext(ctx, "successfully retrieved user by email",
			"email", email,
			"user_id", user.ID,
			"method", "UserService.GetByEmail")
	}

	return user, nil
}

// Update updates the fields of a user. Only non-zero or non-empty fields in the user struct will be updated.
func (s *UserService) Update(ctx context.Context, u models.User) error {
	if u.ID == 0 {
		slog.WarnContext(ctx, "invalid user ID provided for update (zero value)",
			"id", u.ID,
			"method", "UserService.Update")
		return fmt.Errorf("user ID must be provided")
	}

	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	// Call the repository's Update method
	err := s.userRepo.Update(ctx, u)
	if err != nil {
		slog.ErrorContext(ctx, "failed to update user in repository",
			"error", err,
			"user_id", u.ID,
			"email", u.Email,
			"method", "UserService.Update")
		return fmt.Errorf("failed to update user: %w", err)
	}

	slog.InfoContext(ctx, "successfully updated user",
		"user_id", u.ID,
		"email", u.Email,
		"method", "UserService.Update")

	return nil
}

func (s *UserService) DeleteByID(ctx context.Context, id int64) error {
	if id == 0 {
		slog.WarnContext(ctx, "invalid user ID provided for deletion (zero value)",
			"id", id,
			"method", "UserService.DeleteByID")
		return fmt.Errorf("user ID must be provided")
	}

	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	err := s.userRepo.DeleteByID(ctx, id)
	if err != nil {
		slog.ErrorContext(ctx, "failed to delete user from repository",
			"error", err,
			"id", id,
			"method", "UserService.DeleteByID")
		return err
	}

	slog.InfoContext(ctx, "successfully deleted user",
		"id", id,
		"method", "UserService.DeleteByID")

	return nil
}

func (s *UserService) Insert(ctx context.Context, u models.User) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	// Encrypt the user pwd (hash the pwd)
	encryptedPwd, err := bcrypt.GenerateFromPassword([]byte(u.Password), 12)
	if err != nil {
		slog.ErrorContext(ctx, "failed to encrypt password",
			"error", err,
			"email", u.Email,
			"method", "UserService.Insert")
		return 0, fmt.Errorf("encrypting password: %w", err)
	}

	// Update the user password
	u.Password = string(encryptedPwd)

	newUserID, err := s.userRepo.Insert(ctx, u)
	if err != nil {
		slog.ErrorContext(ctx, "failed to insert user in repository",
			"error", err,
			"email", u.Email,
			"first_name", u.FirstName,
			"last_name", u.LastName,
			"method", "UserService.Insert")
		return 0, err
	}

	slog.InfoContext(ctx, "successfully inserted new user",
		"user_id", newUserID,
		"email", u.Email,
		"first_name", u.FirstName,
		"last_name", u.LastName,
		"method", "UserService.Insert")

	return newUserID, nil
}

// ResetPassword is the method used to change a user's password.
func (s *UserService) ResetPassword(ctx context.Context, user *models.User) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}

	if user.ID == 0 {
		return fmt.Errorf("user ID must be provided")
	}

	if user.Password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	if !utils.IsValidPassword(user.Password) {
		return fmt.Errorf("password does not meet strength requirements")
	}

	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash password during reset",
			"error", err,
			"user_id", user.ID,
			"method", "UserService.ResetPassword")
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Persist via the dedicated password-update path (not the generic Update,
	// which does not touch the password column).
	err = s.userRepo.UpdatePassword(ctx, user.ID, string(hashedPassword))
	if err != nil {
		slog.ErrorContext(ctx, "failed to update password in repository",
			"error", err,
			"user_id", user.ID,
			"method", "UserService.ResetPassword")
		return err
	}

	slog.InfoContext(ctx, "successfully reset user password",
		"user_id", user.ID,
		"method", "UserService.ResetPassword")

	return nil
}

// PasswordMatches uses Go's bcrypt package to compare a user supplied password
// with the hash we have stored for a given user in the database. If the password
// and hash match, we return true; otherwise, we return false.
func (s *UserService) PasswordMatches(u *models.User, plainText string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(plainText))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword): // invalid password
			slog.Warn("password mismatch during authentication",
				"user_id", u.ID,
				"email", u.Email,
				"method", "UserService.PasswordMatches")
			return false, nil
		default:
			slog.Error("unexpected error during password comparison",
				"error", err,
				"user_id", u.ID,
				"email", u.Email,
				"method", "UserService.PasswordMatches")
			return false, fmt.Errorf("Error comparing password for user ID %d: %v", u.ID, err)
		}
	}

	// Passwords match
	slog.Info("password validation successful",
		"user_id", u.ID,
		"email", u.Email,
		"method", "UserService.PasswordMatches")

	return true, nil
}
