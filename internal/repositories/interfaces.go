package repositories

import (
	"context"

	"github.com/eupneart/auth-service/internal/models"
)

type UserRepoInterface interface {
	GetAll(ctx context.Context) ([]*models.User, error)
	GetByID(ctx context.Context, id int64) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	Update(ctx context.Context, u models.User) error
	UpdatePassword(ctx context.Context, userID int64, hashedPassword string) error
	DeleteByID(ctx context.Context, id int64) error
	Insert(ctx context.Context, u models.User) (int64, error)
}

type TokenStore interface {
	SaveTokenMetadata(ctx context.Context, metadata *models.TokenMetadata) error
	GetTokenMetadata(ctx context.Context, tokenID string) (*models.TokenMetadata, error)
	IsTokenRevoked(ctx context.Context, tokenID string) (bool, error)
	RevokeToken(ctx context.Context, tokenID string) error
	RevokeTokenByID(ctx context.Context, tokenID string) error
	RevokeAllTokensForUser(ctx context.Context, userID int64) error
	UpdateLastUsed(ctx context.Context, tokenID string) error
	CleanupExpiredTokens(ctx context.Context) error
	GetAllTokensForUser(ctx context.Context, userID string) ([]models.TokenMetadata, error)
}

type PasswordResetTokenStore interface {
	CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error
	// ConsumePasswordResetToken atomically marks a valid token as consumed and
	// returns it, or ErrResetTokenNotFound if it is missing, expired, or already used.
	ConsumePasswordResetToken(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error)
	InvalidatePasswordResetTokensForUser(ctx context.Context, userID int64) error
}
