package services

import (
    "context"
    "github.com/eupneart/auth-service/internal/models"
)

// Interfaces for user service business logic operations
type UserAuthenticator interface {
    GetByEmail(ctx context.Context, email string) (*models.User, error)
    PasswordMatches(u *models.User, plainText string) (bool, error)
}

type UserFinder interface {
    GetAll(ctx context.Context) ([]*models.User, error)
    GetById(ctx context.Context, id int) (*models.User, error)
    GetByEmail(ctx context.Context, email string) (*models.User, error)
}

type UserModifier interface {
    Update(ctx context.Context, u models.User) error
    DeleteByID(ctx context.Context, id int) error
    Insert(ctx context.Context, u models.User) (int, error)
}
