package repositories

import (
	"context"

	"github.com/eupneart/auth-service/internal/models"
)

type UserRepoInterface interface {
	GetAll(ctx context.Context) ([]*models.User, error)
	GetById(ctx context.Context, id int) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	Update(ctx context.Context, u models.User) error
	DeleteByID(ctx context.Context, id int) error
	Insert(ctx context.Context, u models.User) (int, error)
}
