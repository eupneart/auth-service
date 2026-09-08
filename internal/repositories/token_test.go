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

// tokenMetadataColumns mirrors the tokenColumns select list, in order.
var tokenMetadataColumns = []string{
	"id", "user_id", "token_type", "device_id", "client_id",
	"is_revoked", "created_at", "expires_at", "last_used_at",
}

func TestNewTokenRepo(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	assert.NotNil(t, NewTokenRepo(db))
}

func TestTokenRepo_SaveTokenMetadata(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	now := time.Now()
	metadata := &models.TokenMetadata{
		ID:         "token-id",
		UserID:     7,
		TokenType:  models.TokenTypeAccess,
		DeviceID:   "device-1",
		ClientID:   "client-1",
		IsRevoked:  false,
		CreatedAt:  now,
		ExpiresAt:  now.Add(15 * time.Minute),
		LastUsedAt: now,
	}

	mock.ExpectExec("INSERT INTO token_metadata").
		WithArgs("token-id", int64(7), models.TokenTypeAccess, "device-1", "client-1",
			false, now, metadata.ExpiresAt, now).
		WillReturnResult(sqlmock.NewResult(1, 1))

	require.NoError(t, repo.SaveTokenMetadata(context.Background(), metadata))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepo_SaveTokenMetadata_ExecError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("INSERT INTO token_metadata").WillReturnError(sql.ErrConnDone)

	err = repo.SaveTokenMetadata(context.Background(), &models.TokenMetadata{ID: "token-id"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "saving token metadata")
}

func TestTokenRepo_GetTokenMetadata(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	now := time.Now()
	row := sqlmock.NewRows(tokenMetadataColumns).
		AddRow("token-id", int64(7), models.TokenTypeAccess, "device-1", "client-1",
			false, now, now.Add(15*time.Minute), now)

	mock.ExpectQuery("FROM token_metadata WHERE id").
		WithArgs("token-id").
		WillReturnRows(row)

	metadata, err := repo.GetTokenMetadata(context.Background(), "token-id")
	require.NoError(t, err)
	assert.Equal(t, "token-id", metadata.ID)
	assert.Equal(t, int64(7), metadata.UserID)
	assert.Equal(t, "device-1", metadata.DeviceID)
	assert.Equal(t, "client-1", metadata.ClientID)
	require.NoError(t, mock.ExpectationsWereMet())
}

// device_id, client_id and last_used_at are nullable in the schema. A NULL must
// scan into the zero value rather than failing the whole lookup.
func TestTokenRepo_GetTokenMetadata_NullableColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	now := time.Now()
	row := sqlmock.NewRows(tokenMetadataColumns).
		AddRow("token-id", int64(7), models.TokenTypeAccess, nil, nil,
			false, now, now.Add(15*time.Minute), nil)

	mock.ExpectQuery("FROM token_metadata WHERE id").
		WithArgs("token-id").
		WillReturnRows(row)

	metadata, err := repo.GetTokenMetadata(context.Background(), "token-id")
	require.NoError(t, err)
	assert.Empty(t, metadata.DeviceID)
	assert.Empty(t, metadata.ClientID)
	assert.True(t, metadata.LastUsedAt.IsZero())
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepo_GetTokenMetadata_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectQuery("FROM token_metadata WHERE id").
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)

	_, err = repo.GetTokenMetadata(context.Background(), "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token not found")
}

func TestTokenRepo_GetTokenMetadata_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectQuery("FROM token_metadata WHERE id").
		WithArgs("token-id").
		WillReturnError(sql.ErrConnDone)

	_, err = repo.GetTokenMetadata(context.Background(), "token-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "querying token metadata")
}

func TestTokenRepo_IsTokenRevoked(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectQuery("SELECT is_revoked FROM token_metadata").
		WithArgs("token-id").
		WillReturnRows(sqlmock.NewRows([]string{"is_revoked"}).AddRow(true))

	revoked, err := repo.IsTokenRevoked(context.Background(), "token-id")
	require.NoError(t, err)
	assert.True(t, revoked)
	require.NoError(t, mock.ExpectationsWereMet())
}

// A token with no metadata row must be reported as revoked. Reporting it as
// live would let a token the service has no record of pass validation.
func TestTokenRepo_IsTokenRevoked_UnknownTokenIsRevoked(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectQuery("SELECT is_revoked FROM token_metadata").
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)

	revoked, err := repo.IsTokenRevoked(context.Background(), "missing")
	require.NoError(t, err)
	assert.True(t, revoked)
}

// A database failure must not be reported as "not revoked": the caller would
// treat the token as usable.
func TestTokenRepo_IsTokenRevoked_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectQuery("SELECT is_revoked FROM token_metadata").
		WithArgs("token-id").
		WillReturnError(sql.ErrConnDone)

	revoked, err := repo.IsTokenRevoked(context.Background(), "token-id")
	require.Error(t, err)
	assert.False(t, revoked)
	assert.Contains(t, err.Error(), "checking token revocation status")
}

func TestTokenRepo_RevokeToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET is_revoked = true WHERE id").
		WithArgs("token-id").
		WillReturnResult(sqlmock.NewResult(0, 1))

	require.NoError(t, repo.RevokeToken(context.Background(), "token-id"))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepo_RevokeToken_ExecError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET is_revoked = true WHERE id").
		WithArgs("token-id").
		WillReturnError(sql.ErrConnDone)

	err = repo.RevokeToken(context.Background(), "token-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoking token")
}

func TestTokenRepo_RevokeToken_RowsAffectedError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET is_revoked = true WHERE id").
		WithArgs("token-id").
		WillReturnResult(sqlmock.NewErrorResult(errors.New("no rows affected support")))

	err = repo.RevokeToken(context.Background(), "token-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checking revocation result")
}

func TestTokenRepo_RevokeToken_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET is_revoked = true WHERE id").
		WithArgs("missing").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = repo.RevokeToken(context.Background(), "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token not found")
}

func TestTokenRepo_RevokeTokenByID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET is_revoked = true WHERE id").
		WithArgs("token-id").
		WillReturnResult(sqlmock.NewResult(0, 1))

	require.NoError(t, repo.RevokeTokenByID(context.Background(), "token-id"))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepo_RevokeAllTokensForUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET is_revoked = true WHERE user_id").
		WithArgs(int64(7)).
		WillReturnResult(sqlmock.NewResult(0, 3))

	require.NoError(t, repo.RevokeAllTokensForUser(context.Background(), 7))
	require.NoError(t, mock.ExpectationsWereMet())
}

// Revoking every token for a user who has none is not an error: the postcondition
// (no live sessions) already holds.
func TestTokenRepo_RevokeAllTokensForUser_NoTokens(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET is_revoked = true WHERE user_id").
		WithArgs(int64(7)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	require.NoError(t, repo.RevokeAllTokensForUser(context.Background(), 7))
}

func TestTokenRepo_RevokeAllTokensForUser_ExecError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET is_revoked = true WHERE user_id").
		WithArgs(int64(7)).
		WillReturnError(sql.ErrConnDone)

	err = repo.RevokeAllTokensForUser(context.Background(), 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoking all tokens for user")
}

func TestTokenRepo_RevokeAllTokensForUser_RowsAffectedError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET is_revoked = true WHERE user_id").
		WithArgs(int64(7)).
		WillReturnResult(sqlmock.NewErrorResult(errors.New("no rows affected support")))

	err = repo.RevokeAllTokensForUser(context.Background(), 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checking revocation result")
}

func TestTokenRepo_UpdateLastUsed(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET last_used_at").
		WithArgs(sqlmock.AnyArg(), "token-id"). // last_used_at, id
		WillReturnResult(sqlmock.NewResult(0, 1))

	require.NoError(t, repo.UpdateLastUsed(context.Background(), "token-id"))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepo_UpdateLastUsed_ExecError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET last_used_at").
		WithArgs(sqlmock.AnyArg(), "token-id"). // last_used_at, id
		WillReturnError(sql.ErrConnDone)

	err = repo.UpdateLastUsed(context.Background(), "token-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "updating last used timestamp")
}

// Bookkeeping failures after the write must not surface as errors: the caller
// runs this during token validation, which should not fail because a timestamp
// could not be recorded.
func TestTokenRepo_UpdateLastUsed_RowsAffectedErrorIsIgnored(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET last_used_at").
		WithArgs(sqlmock.AnyArg(), "token-id"). // last_used_at, id
		WillReturnResult(sqlmock.NewErrorResult(errors.New("no rows affected support")))

	require.NoError(t, repo.UpdateLastUsed(context.Background(), "token-id"))
}

func TestTokenRepo_UpdateLastUsed_UnknownTokenIsIgnored(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("UPDATE token_metadata SET last_used_at").
		WithArgs(sqlmock.AnyArg(), "missing"). // last_used_at, id
		WillReturnResult(sqlmock.NewResult(0, 0))

	require.NoError(t, repo.UpdateLastUsed(context.Background(), "missing"))
}

func TestTokenRepo_CleanupExpiredTokens(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("DELETE FROM token_metadata").
		WithArgs(sqlmock.AnyArg()). // expires_at cutoff
		WillReturnResult(sqlmock.NewResult(0, 5))

	require.NoError(t, repo.CleanupExpiredTokens(context.Background()))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepo_CleanupExpiredTokens_ExecError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("DELETE FROM token_metadata").
		WithArgs(sqlmock.AnyArg()). // expires_at cutoff
		WillReturnError(sql.ErrConnDone)

	err = repo.CleanupExpiredTokens(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cleaning up expired tokens")
}

func TestTokenRepo_CleanupExpiredTokens_RowsAffectedError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectExec("DELETE FROM token_metadata").
		WithArgs(sqlmock.AnyArg()). // expires_at cutoff
		WillReturnResult(sqlmock.NewErrorResult(errors.New("no rows affected support")))

	err = repo.CleanupExpiredTokens(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checking cleanup result")
}

func TestTokenRepo_GetAllTokensForUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	now := time.Now()
	rows := sqlmock.NewRows(tokenMetadataColumns).
		AddRow("token-1", int64(7), models.TokenTypeAccess, "device-1", "client-1",
			false, now, now.Add(15*time.Minute), now).
		AddRow("token-2", int64(7), models.TokenTypeRefresh, nil, nil,
			true, now, now.Add(24*time.Hour), nil)

	mock.ExpectQuery("FROM token_metadata WHERE user_id").
		WithArgs("7").
		WillReturnRows(rows)

	tokens, err := repo.GetAllTokensForUser(context.Background(), "7")
	require.NoError(t, err)
	require.Len(t, tokens, 2)
	assert.Equal(t, "token-1", tokens[0].ID)
	assert.Equal(t, "device-1", tokens[0].DeviceID)
	assert.Empty(t, tokens[1].DeviceID)
	assert.True(t, tokens[1].LastUsedAt.IsZero())
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepo_GetAllTokensForUser_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	mock.ExpectQuery("FROM token_metadata WHERE user_id").
		WithArgs("7").
		WillReturnError(sql.ErrConnDone)

	_, err = repo.GetAllTokensForUser(context.Background(), "7")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "querying all tokens for user")
}

func TestTokenRepo_GetAllTokensForUser_ScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	rows := sqlmock.NewRows(tokenMetadataColumns).
		AddRow("token-1", int64(7), models.TokenTypeAccess, "device-1", "client-1",
			false, "not-a-timestamp", time.Now(), nil)

	mock.ExpectQuery("FROM token_metadata WHERE user_id").
		WithArgs("7").
		WillReturnRows(rows)

	_, err = repo.GetAllTokensForUser(context.Background(), "7")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scanning token metadata")
}

func TestTokenRepo_GetAllTokensForUser_RowsError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewTokenRepo(db)

	rows := sqlmock.NewRows(tokenMetadataColumns).
		AddRow("token-1", int64(7), models.TokenTypeAccess, nil, nil,
			false, time.Now(), time.Now(), nil).
		RowError(0, errors.New("connection lost mid-iteration"))

	mock.ExpectQuery("FROM token_metadata WHERE user_id").
		WithArgs("7").
		WillReturnRows(rows)

	_, err = repo.GetAllTokensForUser(context.Background(), "7")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scanning token metadata")
}

// GetActiveTokensForUser is not part of TokenStore, so it is reached through the
// concrete repository.
func TestTokenRepo_GetActiveTokensForUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := &TokenRepo{DB: db}

	now := time.Now()
	rows := sqlmock.NewRows(tokenMetadataColumns).
		AddRow("token-1", int64(7), models.TokenTypeAccess, "device-1", "client-1",
			false, now, now.Add(15*time.Minute), now)

	mock.ExpectQuery("AND is_revoked = false AND expires_at").
		WithArgs("7", sqlmock.AnyArg()). // user_id, expires_at cutoff
		WillReturnRows(rows)

	tokens, err := repo.GetActiveTokensForUser(context.Background(), "7")
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "token-1", tokens[0].ID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepo_GetActiveTokensForUser_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := &TokenRepo{DB: db}

	mock.ExpectQuery("AND is_revoked = false AND expires_at").
		WithArgs("7", sqlmock.AnyArg()). // user_id, expires_at cutoff
		WillReturnError(sql.ErrConnDone)

	_, err = repo.GetActiveTokensForUser(context.Background(), "7")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "querying active tokens for user")
}

func TestTokenRepo_GetActiveTokensForUser_ScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := &TokenRepo{DB: db}

	rows := sqlmock.NewRows(tokenMetadataColumns).
		AddRow("token-1", int64(7), models.TokenTypeAccess, nil, nil,
			false, "not-a-timestamp", time.Now(), nil)

	mock.ExpectQuery("AND is_revoked = false AND expires_at").
		WithArgs("7", sqlmock.AnyArg()). // user_id, expires_at cutoff
		WillReturnRows(rows)

	_, err = repo.GetActiveTokensForUser(context.Background(), "7")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scanning active token metadata")
}

// GetTokenCountForUser is not part of TokenStore, so it is reached through the
// concrete repository.
func TestTokenRepo_GetTokenCountForUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := &TokenRepo{DB: db}

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("7", sqlmock.AnyArg()). // user_id, expires_at cutoff
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(3)))

	count, err := repo.GetTokenCountForUser(context.Background(), "7", "")
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepo_GetTokenCountForUser_ByTokenType(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := &TokenRepo{DB: db}

	mock.ExpectQuery("AND token_type").
		WithArgs("7", models.TokenTypeRefresh, sqlmock.AnyArg()). // user_id, token_type, expires_at cutoff
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))

	count, err := repo.GetTokenCountForUser(context.Background(), "7", models.TokenTypeRefresh)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepo_GetTokenCountForUser_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := &TokenRepo{DB: db}

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("7", sqlmock.AnyArg()). // user_id, expires_at cutoff
		WillReturnError(sql.ErrConnDone)

	count, err := repo.GetTokenCountForUser(context.Background(), "7", "")
	require.Error(t, err)
	assert.Zero(t, count)
	assert.Contains(t, err.Error(), "getting token count for user")
}
