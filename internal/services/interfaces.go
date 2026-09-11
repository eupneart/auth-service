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
	GetByID(ctx context.Context, id int64) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
}

type UserModifier interface {
	Update(ctx context.Context, u models.User) error
	DeleteByID(ctx context.Context, id int) error
	Insert(ctx context.Context, u models.User) (int, error)
}

// Interface for tokens service business logic operations
type TokenService interface {
	GenerateTokens(ctx context.Context, user *models.User) (accessToken, refreshToken string, err error)
	ValidateToken(ctx context.Context, tokenStr string) (*models.Claims, error)
	RefreshAccessToken(ctx context.Context, refreshToken string) (accessToken string, err error)
	RevokeToken(ctx context.Context, tokenStr string) error
	RevokeSession(ctx context.Context, claims *models.Claims) error
	GetTokenMetadata(ctx context.Context, tokenID string) (*models.TokenMetadata, error)
	IsTokenRevoked(ctx context.Context, tokenID string) (bool, error)
	RevokeAllTokensForUser(ctx context.Context, userID int64) error
	CleanupExpiredTokens(ctx context.Context) error
}

// PasswordResetMailer delivers a prebuilt reset link. Implementations must not
// log or persist resetURL beyond delivery: it is a bearer credential.
type PasswordResetMailer interface {
	SendPasswordReset(ctx context.Context, recipient, resetURL string) error
}
