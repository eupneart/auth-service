package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/eupneart/auth-service/internal/models"
)

// ErrResetTokenNotFound is returned when a password-reset token is missing,
// expired, or already consumed. Callers must treat all three cases identically
// so responses never reveal which one occurred.
var ErrResetTokenNotFound = errors.New("password reset token not found")

const passwordResetTokenColumns = `
  id, user_id, token_hash, created_at, expires_at, consumed_at
`

type PasswordResetTokenRepo struct {
	DB *sql.DB
}

func NewPasswordResetTokenRepo(db *sql.DB) PasswordResetTokenStore {
	return &PasswordResetTokenRepo{DB: db}
}

func (r *PasswordResetTokenRepo) CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	stmt := `INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at)
             VALUES ($1, $2, $3, $4) RETURNING id, created_at`

	err := r.DB.QueryRowContext(ctx, stmt,
		token.UserID,
		token.TokenHash,
		time.Now(),
		token.ExpiresAt,
	).Scan(&token.ID, &token.CreatedAt)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create password reset token",
			"error", err,
			"user_id", token.UserID,
			"method", "PasswordResetTokenRepo.CreatePasswordResetToken")
		return fmt.Errorf("creating password reset token: %w", err)
	}

	slog.DebugContext(ctx, "created password reset token",
		"user_id", token.UserID,
		"token_id", token.ID)

	return nil
}

func (r *PasswordResetTokenRepo) ConsumePasswordResetToken(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error) {
	// Single UPDATE ... RETURNING so the check-and-consume is atomic and a token
	// can never be redeemed twice, even under concurrent requests.
	stmt := fmt.Sprintf(`UPDATE password_reset_tokens
             SET consumed_at = $1
             WHERE token_hash = $2 AND consumed_at IS NULL AND expires_at > $1
             RETURNING %s`, passwordResetTokenColumns)

	now := time.Now()
	token, err := scanPasswordResetToken(r.DB.QueryRowContext(ctx, stmt, now, tokenHash))
	if err != nil {
		if err == sql.ErrNoRows {
			slog.WarnContext(ctx, "password reset token invalid, expired, or already used",
				"method", "PasswordResetTokenRepo.ConsumePasswordResetToken")
			return nil, ErrResetTokenNotFound
		}
		slog.ErrorContext(ctx, "failed to consume password reset token",
			"error", err,
			"method", "PasswordResetTokenRepo.ConsumePasswordResetToken")
		return nil, fmt.Errorf("consuming password reset token: %w", err)
	}

	slog.InfoContext(ctx, "consumed password reset token",
		"user_id", token.UserID,
		"token_id", token.ID)

	return token, nil
}

func (r *PasswordResetTokenRepo) InvalidatePasswordResetTokensForUser(ctx context.Context, userID int64) error {
	stmt := `UPDATE password_reset_tokens SET consumed_at = $1
             WHERE user_id = $2 AND consumed_at IS NULL`

	result, err := r.DB.ExecContext(ctx, stmt, time.Now(), userID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to invalidate password reset tokens for user",
			"error", err,
			"user_id", userID,
			"method", "PasswordResetTokenRepo.InvalidatePasswordResetTokensForUser")
		return fmt.Errorf("invalidating password reset tokens for user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	slog.InfoContext(ctx, "invalidated password reset tokens for user",
		"user_id", userID,
		"tokens_invalidated", rowsAffected)

	return nil
}

// ========================= Helper functions ============================

func scanPasswordResetToken(row *sql.Row) (*models.PasswordResetToken, error) {
	var token models.PasswordResetToken
	var consumedAt sql.NullTime

	err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.CreatedAt,
		&token.ExpiresAt,
		&consumedAt,
	)
	if err != nil {
		return nil, err
	}

	if consumedAt.Valid {
		token.ConsumedAt = &consumedAt.Time
	}

	return &token, nil
}
