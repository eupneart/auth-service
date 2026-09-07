package repositories

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/eupneart/auth-service/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordResetTokenRepo_CreatePasswordResetToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPasswordResetTokenRepo(db)

	created := time.Now()
	token := &models.PasswordResetToken{
		UserID:    7,
		TokenHash: "deadbeef",
		ExpiresAt: created.Add(15 * time.Minute),
	}

	mock.ExpectQuery("INSERT INTO password_reset_tokens").
		WithArgs(int64(7), "deadbeef", sqlmock.AnyArg(), token.ExpiresAt).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(int64(42), created))

	err = repo.CreatePasswordResetToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, int64(42), token.ID)
	assert.Equal(t, created, token.CreatedAt)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPasswordResetTokenRepo_ConsumePasswordResetToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPasswordResetTokenRepo(db)

	now := time.Now()
	rows := sqlmock.NewRows([]string{"id", "user_id", "token_hash", "created_at", "expires_at", "consumed_at"}).
		AddRow(int64(1), int64(7), "deadbeef", now.Add(-time.Minute), now.Add(14*time.Minute), now)

	mock.ExpectQuery("UPDATE password_reset_tokens").
		WithArgs(sqlmock.AnyArg(), "deadbeef").
		WillReturnRows(rows)

	token, err := repo.ConsumePasswordResetToken(context.Background(), "deadbeef")
	require.NoError(t, err)
	assert.Equal(t, int64(7), token.UserID)
	require.NotNil(t, token.ConsumedAt)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPasswordResetTokenRepo_ConsumePasswordResetToken_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPasswordResetTokenRepo(db)

	mock.ExpectQuery("UPDATE password_reset_tokens").
		WithArgs(sqlmock.AnyArg(), "missing").
		WillReturnError(sql.ErrNoRows)

	_, err = repo.ConsumePasswordResetToken(context.Background(), "missing")
	require.ErrorIs(t, err, ErrResetTokenNotFound)
}

func TestPasswordResetTokenRepo_ConsumePasswordResetToken_ExecError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPasswordResetTokenRepo(db)

	mock.ExpectQuery("UPDATE password_reset_tokens").
		WithArgs(sqlmock.AnyArg(), "deadbeef").
		WillReturnError(sql.ErrConnDone)

	_, err = repo.ConsumePasswordResetToken(context.Background(), "deadbeef")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrResetTokenNotFound))
	assert.Contains(t, err.Error(), "consuming password reset token")
}

func TestPasswordResetTokenRepo_InvalidatePasswordResetTokensForUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPasswordResetTokenRepo(db)

	mock.ExpectExec("UPDATE password_reset_tokens SET consumed_at").
		WithArgs(sqlmock.AnyArg(), int64(7)).
		WillReturnResult(sqlmock.NewResult(0, 2))

	err = repo.InvalidatePasswordResetTokensForUser(context.Background(), 7)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}
