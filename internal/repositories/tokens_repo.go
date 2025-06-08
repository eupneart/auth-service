package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/eupneart/auth-service/internal/models"
)

const tokenColumns = `
  id, user_id, token_type, device_id, client_id,
  is_revoked, created_at, expires_at, last_used_at
`

type TokenRepo struct {
	DB *sql.DB
}

func NewTokenRepo(db *sql.DB) TokenStore {
	return &TokenRepo{DB: db}
}

// SaveTokenMetadata stores metadata for a token
func (r *TokenRepo) SaveTokenMetadata(ctx context.Context, metadata *models.TokenMetadata) error {
	stmt := `INSERT INTO token_metadata (id, user_id, token_type, device_id, client_id, is_revoked, created_at, expires_at, last_used_at) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.DB.ExecContext(ctx, stmt,
		metadata.ID,
		metadata.UserID,
		metadata.TokenType,
		metadata.DeviceID,
		metadata.ClientID,
		metadata.IsRevoked,
		metadata.CreatedAt,
		metadata.ExpiresAt,
		metadata.LastUsedAt,
	)
	if err != nil {
		slog.Error("failed to save token metadata",
			"error", err,
			"query", stmt,
			"token_id", metadata.ID,
			"user_id", metadata.UserID,
			"method", "TokenRepo.SaveTokenMetadata")
		return fmt.Errorf("saving token metadata: %w", err)
	}

	slog.Debug("successfully saved token metadata",
		"token_id", metadata.ID,
		"user_id", metadata.UserID,
		"token_type", metadata.TokenType)

	return nil
}

// GetTokenMetadata retrieves metadata for a specific token
func (r *TokenRepo) GetTokenMetadata(ctx context.Context, tokenID string) (*models.TokenMetadata, error) {
	query := fmt.Sprintf(`SELECT %s FROM token_metadata WHERE id = $1`, tokenColumns)

	row := r.DB.QueryRowContext(ctx, query, tokenID)

	metadata, err := scanTokenMetadata(row)
	if err != nil {
		if err == sql.ErrNoRows {
			slog.Warn("token metadata not found",
				"token_id", tokenID,
				"method", "TokenRepo.GetTokenMetadata")
			return nil, fmt.Errorf("token not found")
		}
		slog.Error("failed to query token metadata",
			"error", err,
			"query", query,
			"token_id", tokenID,
			"method", "TokenRepo.GetTokenMetadata")
		return nil, fmt.Errorf("querying token metadata: %w", err)
	}

	slog.Debug("successfully retrieved token metadata",
		"token_id", tokenID,
		"user_id", metadata.UserID)

	return metadata, nil
}

// IsTokenRevoked checks if a token has been revoked
func (r *TokenRepo) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	query := `SELECT is_revoked FROM token_metadata WHERE id = $1`

	var isRevoked bool
	err := r.DB.QueryRowContext(ctx, query, tokenID).Scan(&isRevoked)
	if err != nil {
		if err == sql.ErrNoRows {
			// If token doesn't exist, consider it as revoked/invalid
			slog.Warn("token not found when checking revocation status",
				"token_id", tokenID,
				"method", "TokenRepo.IsTokenRevoked")
			return true, nil
		}
		slog.Error("failed to check token revocation status",
			"error", err,
			"query", query,
			"token_id", tokenID,
			"method", "TokenRepo.IsTokenRevoked")
		return false, fmt.Errorf("checking token revocation status: %w", err)
	}

	slog.Debug("token revocation status checked",
		"token_id", tokenID,
		"is_revoked", isRevoked)

	return isRevoked, nil
}

// RevokeToken marks a token as revoked
func (r *TokenRepo) RevokeToken(ctx context.Context, tokenID string) error {
	stmt := `UPDATE token_metadata SET is_revoked = true WHERE id = $1`

	result, err := r.DB.ExecContext(ctx, stmt, tokenID)
	if err != nil {
		slog.Error("failed to revoke token",
			"error", err,
			"query", stmt,
			"token_id", tokenID,
			"method", "TokenRepo.RevokeToken")
		return fmt.Errorf("revoking token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		slog.Error("failed to get rows affected after token revocation",
			"error", err,
			"token_id", tokenID,
			"method", "TokenRepo.RevokeToken")
		return fmt.Errorf("checking revocation result: %w", err)
	}

	if rowsAffected == 0 {
		slog.Warn("no token found to revoke",
			"token_id", tokenID,
			"method", "TokenRepo.RevokeToken")
		return fmt.Errorf("token not found")
	}

	slog.Info("successfully revoked token",
		"token_id", tokenID)

	return nil
}

// RevokeTokenByID marks a token as revoked by its ID (same as RevokeToken)
func (r *TokenRepo) RevokeTokenByID(ctx context.Context, tokenID string) error {
	return r.RevokeToken(ctx, tokenID)
}

// RevokeAllTokensForUser revokes all tokens for a specific user
func (r *TokenRepo) RevokeAllTokensForUser(ctx context.Context, userID string) error {
	stmt := `UPDATE token_metadata SET is_revoked = true WHERE user_id = $1 AND is_revoked = false`

	result, err := r.DB.ExecContext(ctx, stmt, userID)
	if err != nil {
		slog.Error("failed to revoke all tokens for user",
			"error", err,
			"query", stmt,
			"user_id", userID,
			"method", "TokenRepo.RevokeAllTokensForUser")
		return fmt.Errorf("revoking all tokens for user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		slog.Error("failed to get rows affected after revoking all tokens",
			"error", err,
			"user_id", userID,
			"method", "TokenRepo.RevokeAllTokensForUser")
		return fmt.Errorf("checking revocation result: %w", err)
	}

	slog.Info("successfully revoked all tokens for user",
		"user_id", userID,
		"tokens_revoked", rowsAffected)

	return nil
}

// UpdateLastUsed updates the last used timestamp for a token
func (r *TokenRepo) UpdateLastUsed(ctx context.Context, tokenID string) error {
	stmt := `UPDATE token_metadata SET last_used_at = $1 WHERE id = $2`

	result, err := r.DB.ExecContext(ctx, stmt, time.Now(), tokenID)
	if err != nil {
		slog.Error("failed to update last used timestamp",
			"error", err,
			"query", stmt,
			"token_id", tokenID,
			"method", "TokenRepo.UpdateLastUsed")
		return fmt.Errorf("updating last used timestamp: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		slog.Error("failed to get rows affected after updating last used",
			"error", err,
			"token_id", tokenID,
			"method", "TokenRepo.UpdateLastUsed")
		// Don't return error as this shouldn't fail token validation
		return nil
	}

	if rowsAffected == 0 {
		slog.Warn("no token found to update last used timestamp",
			"token_id", tokenID,
			"method", "TokenRepo.UpdateLastUsed")
		// Don't return error as this shouldn't fail token validation
	}

	return nil
}

// CleanupExpiredTokens removes expired tokens from storage
func (r *TokenRepo) CleanupExpiredTokens(ctx context.Context) error {
	stmt := `DELETE FROM token_metadata WHERE expires_at < $1`

	result, err := r.DB.ExecContext(ctx, stmt, time.Now())
	if err != nil {
		slog.Error("failed to cleanup expired tokens",
			"error", err,
			"query", stmt,
			"method", "TokenRepo.CleanupExpiredTokens")
		return fmt.Errorf("cleaning up expired tokens: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		slog.Error("failed to get rows affected after cleanup",
			"error", err,
			"method", "TokenRepo.CleanupExpiredTokens")
		return fmt.Errorf("checking cleanup result: %w", err)
	}

	slog.Info("successfully cleaned up expired tokens",
		"tokens_deleted", rowsAffected)

	return nil
}

// GetAllTokensForUser returns all tokens for a specific user
func (r *TokenRepo) GetAllTokensForUser(ctx context.Context, userID string) ([]models.TokenMetadata, error) {
	query := fmt.Sprintf(`SELECT %s FROM token_metadata WHERE user_id = $1 ORDER BY created_at DESC`, tokenColumns)

	rows, err := r.DB.QueryContext(ctx, query, userID)
	if err != nil {
		slog.Error("failed to query all tokens for user",
			"error", err,
			"query", query,
			"user_id", userID,
			"method", "TokenRepo.GetAllTokensForUser")
		return nil, fmt.Errorf("querying all tokens for user: %w", err)
	}
	defer rows.Close()

	tokens, err := scanTokenMetadataRows(rows)
	if err != nil {
		slog.Error("failed to scan token metadata rows",
			"error", err,
			"user_id", userID,
			"method", "TokenRepo.GetAllTokensForUser")
		return nil, fmt.Errorf("scanning token metadata: %w", err)
	}

	slog.Debug("successfully retrieved tokens for user",
		"user_id", userID,
		"token_count", len(tokens))

	return tokens, nil
}

// GetActiveTokensForUser returns only active (non-revoked, non-expired) tokens for a user
func (r *TokenRepo) GetActiveTokensForUser(ctx context.Context, userID string) ([]models.TokenMetadata, error) {
	query := fmt.Sprintf(`SELECT %s FROM token_metadata 
                          WHERE user_id = $1 AND is_revoked = false AND expires_at > $2 
                          ORDER BY created_at DESC`, tokenColumns)

	rows, err := r.DB.QueryContext(ctx, query, userID, time.Now())
	if err != nil {
		slog.Error("failed to query active tokens for user",
			"error", err,
			"query", query,
			"user_id", userID,
			"method", "TokenRepo.GetActiveTokensForUser")
		return nil, fmt.Errorf("querying active tokens for user: %w", err)
	}
	defer rows.Close()

	tokens, err := scanTokenMetadataRows(rows)
	if err != nil {
		slog.Error("failed to scan active token metadata rows",
			"error", err,
			"user_id", userID,
			"method", "TokenRepo.GetActiveTokensForUser")
		return nil, fmt.Errorf("scanning active token metadata: %w", err)
	}

	slog.Debug("successfully retrieved active tokens for user",
		"user_id", userID,
		"active_token_count", len(tokens))

	return tokens, nil
}

// GetTokenCountForUser returns the count of active tokens for a user
func (r *TokenRepo) GetTokenCountForUser(ctx context.Context, userID string, tokenType string) (int64, error) {
	var query string
	var args []interface{}

	if tokenType == "" {
		query = `SELECT COUNT(*) FROM token_metadata 
                 WHERE user_id = $1 AND is_revoked = false AND expires_at > $2`
		args = []interface{}{userID, time.Now()}
	} else {
		query = `SELECT COUNT(*) FROM token_metadata 
                 WHERE user_id = $1 AND token_type = $2 AND is_revoked = false AND expires_at > $3`
		args = []interface{}{userID, tokenType, time.Now()}
	}

	var count int64
	err := r.DB.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		slog.Error("failed to get token count for user",
			"error", err,
			"query", query,
			"user_id", userID,
			"token_type", tokenType,
			"method", "TokenRepo.GetTokenCountForUser")
		return 0, fmt.Errorf("getting token count for user: %w", err)
	}

	slog.Debug("successfully retrieved token count for user",
		"user_id", userID,
		"token_type", tokenType,
		"count", count)

	return count, nil
}

// ========================= Helper functions ============================

// scanTokenMetadata is a helper function to scan a single row into a TokenMetadata struct.
func scanTokenMetadata(row *sql.Row) (*models.TokenMetadata, error) {
	var metadata models.TokenMetadata
	var deviceID, clientID sql.NullString
	var lastUsedAt sql.NullTime

	err := row.Scan(
		&metadata.ID,
		&metadata.UserID,
		&metadata.TokenType,
		&deviceID,
		&clientID,
		&metadata.IsRevoked,
		&metadata.CreatedAt,
		&metadata.ExpiresAt,
		&lastUsedAt,
	)
	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if deviceID.Valid {
		metadata.DeviceID = deviceID.String
	}
	if clientID.Valid {
		metadata.ClientID = clientID.String
	}
	if lastUsedAt.Valid {
		metadata.LastUsedAt = lastUsedAt.Time
	}

	return &metadata, nil
}

// scanTokenMetadataRows is a helper function to scan multiple rows into a slice of TokenMetadata structs.
func scanTokenMetadataRows(rows *sql.Rows) ([]models.TokenMetadata, error) {
	var tokens []models.TokenMetadata

	for rows.Next() {
		var metadata models.TokenMetadata
		var deviceID, clientID sql.NullString
		var lastUsedAt sql.NullTime

		if err := rows.Scan(
			&metadata.ID,
			&metadata.UserID,
			&metadata.TokenType,
			&deviceID,
			&clientID,
			&metadata.IsRevoked,
			&metadata.CreatedAt,
			&metadata.ExpiresAt,
			&lastUsedAt,
		); err != nil {
			slog.Error("failed to scan token metadata row",
				"error", err,
				"method", "scanTokenMetadataRows")
			return nil, err
		}

		// Handle nullable fields
		if deviceID.Valid {
			metadata.DeviceID = deviceID.String
		}
		if clientID.Valid {
			metadata.ClientID = clientID.String
		}
		if lastUsedAt.Valid {
			metadata.LastUsedAt = lastUsedAt.Time
		}

		tokens = append(tokens, metadata)
	}

	// Check if there was any error while iterating through the rows
	if err := rows.Err(); err != nil {
		slog.Error("error iterating through token metadata rows",
			"error", err,
			"method", "scanTokenMetadataRows")
		return nil, fmt.Errorf("scanning token metadata: %w", err)
	}

	return tokens, nil
}
