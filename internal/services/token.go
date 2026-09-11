package services

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/eupneart/auth-service/internal/models"
	"github.com/eupneart/auth-service/internal/repositories"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenServiceConfig struct {
	JWTSecret            string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	Issuer               string
}

type tokenService struct {
	config   TokenServiceConfig
	userRepo repositories.UserRepoInterface
	store    repositories.TokenStore
	logger   *slog.Logger
}

func NewTokenService(config TokenServiceConfig, userRepo repositories.UserRepoInterface, store repositories.TokenStore, logger *slog.Logger) TokenService {
	return &tokenService{
		config:   config,
		userRepo: userRepo,
		store:    store,
		logger:   logger,
	}
}

func (s *tokenService) GenerateTokens(ctx context.Context, user *models.User) (accessToken, refreshToken string, err error) {
	s.logger.InfoContext(ctx, "Generating tokens for user",
		slog.Int64("user_id", user.ID),
		slog.String("email", user.Email))

	// Generate unique IDs for both tokens
	accessTokenID := uuid.New().String()
	refreshTokenID := uuid.New().String()

	// Both tokens share one session id so logging out revokes the pair, not
	// only the access token the caller happens to present.
	sessionID := uuid.New().String()

	// Create access token claims
	accessClaims := &models.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    s.config.Issuer,
			Subject:   strconv.FormatInt(user.ID, 10),
			ID:        accessTokenID,
		},
		UserID:    user.ID,
		Email:     user.Email,
		Role:      user.Role,
		TokenType: models.TokenTypeAccess,
		SessionID: sessionID,
	}

	// Create refresh token claims
	refreshClaims := &models.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.RefreshTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    s.config.Issuer,
			Subject:   strconv.FormatInt(user.ID, 10),
			ID:        refreshTokenID,
		},
		UserID:    user.ID,
		Email:     user.Email,
		Role:      user.Role,
		TokenType: models.TokenTypeRefresh,
		SessionID: sessionID,
	}

	// Generate access token
	accessTokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessTokenJWT.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to generate access token",
			slog.Int64("user_id", user.ID),
			slog.String("error", err.Error()))
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshTokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = refreshTokenJWT.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to generate refresh token",
			slog.Int64("user_id", user.ID),
			slog.String("error", err.Error()))
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store token metadata
	accessMetadata := &models.TokenMetadata{
		ID:        accessTokenID,
		UserID:    user.ID,
		TokenType: models.TokenTypeAccess,
		SessionID: sessionID,
		IsRevoked: false,
		CreatedAt: time.Now(),
		ExpiresAt: accessClaims.ExpiresAt.Time,
	}

	refreshMetadata := &models.TokenMetadata{
		ID:        refreshTokenID,
		UserID:    user.ID,
		TokenType: models.TokenTypeRefresh,
		SessionID: sessionID,
		IsRevoked: false,
		CreatedAt: time.Now(),
		ExpiresAt: refreshClaims.ExpiresAt.Time,
	}

	// Store both tokens metadata
	if err := s.store.SaveTokenMetadata(ctx, accessMetadata); err != nil {
		s.logger.ErrorContext(ctx, "Failed to store access token metadata",
			slog.Int64("user_id", user.ID),
			slog.String("token_id", accessTokenID),
			slog.String("error", err.Error()))
		return "", "", fmt.Errorf("failed to store access token metadata: %w", err)
	}

	if err := s.store.SaveTokenMetadata(ctx, refreshMetadata); err != nil {
		s.logger.ErrorContext(ctx, "Failed to store refresh token metadata",
			slog.Int64("user_id", user.ID),
			slog.String("token_id", refreshTokenID),
			slog.String("error", err.Error()))
		return "", "", fmt.Errorf("failed to store refresh token metadata: %w", err)
	}

	s.logger.InfoContext(ctx, "Successfully generated tokens",
		slog.Int64("user_id", user.ID),
		slog.String("access_token_id", accessTokenID),
		slog.String("refresh_token_id", refreshTokenID),
		slog.String("session_id", sessionID))

	return accessToken, refreshToken, nil
}

// ValidateToken verifies a token and returns its claims if valid
func (s *tokenService) ValidateToken(ctx context.Context, tokenStr string) (*models.Claims, error) {
	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenStr, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWTSecret), nil
	})
	if err != nil {
		s.logger.WarnContext(ctx, "Failed to parse token", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*models.Claims)
	if !ok || !token.Valid {
		s.logger.WarnContext(ctx, "Invalid token claims or token not valid")
		return nil, ErrInvalidToken
	}

	// Check if token is revoked
	revoked, err := s.store.IsTokenRevoked(ctx, claims.ID)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to check token revocation status",
			slog.String("token_id", claims.ID),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to check token revocation status: %w", err)
	}
	if revoked {
		s.logger.WarnContext(ctx, "Attempted to use revoked token",
			slog.String("token_id", claims.ID),
			slog.Int64("user_id", claims.UserID))
		return nil, ErrTokenRevoked
	}

	// Update last used timestamp
	if err := s.store.UpdateLastUsed(ctx, claims.ID); err != nil {
		s.logger.ErrorContext(ctx, "Failed to update token last used timestamp",
			slog.String("token_id", claims.ID),
			slog.String("error", err.Error()))
		// Don't fail the validation for this error
	}

	s.logger.DebugContext(ctx, "Token validated successfully",
		slog.String("token_id", claims.ID),
		slog.Int64("user_id", claims.UserID),
		slog.String("token_type", claims.TokenType))

	return claims, nil
}

// RefreshAccessToken generates a new access token using a refresh token
func (s *tokenService) RefreshAccessToken(ctx context.Context, refreshToken string) (accessToken string, err error) {
	s.logger.InfoContext(ctx, "Refreshing access token")

	// Validate refresh token
	claims, err := s.ValidateToken(ctx, refreshToken)
	if err != nil {
		s.logger.WarnContext(ctx, "Invalid refresh token provided", slog.String("error", err.Error()))
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if it's actually a refresh token
	if claims.TokenType != models.TokenTypeRefresh {
		s.logger.WarnContext(ctx, "Attempted to refresh with non-refresh token",
			slog.String("token_type", claims.TokenType),
			slog.Int64("user_id", claims.UserID))
		return "", ErrInvalidTokenType
	}

	// Get user to fetch latest roles and information
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to get user for token refresh",
			slog.Int64("user_id", claims.UserID),
			slog.String("error", err.Error()))
		return "", fmt.Errorf("failed to get user: %w", err)
	}

	// Generate new access token (but not refresh token)
	accessTokenID := uuid.New().String()

	accessClaims := &models.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    s.config.Issuer,
			Subject:   strconv.FormatInt(user.ID, 10),
			ID:        accessTokenID,
		},
		UserID:    user.ID,
		Email:     user.Email,
		Role:      user.Role,
		TokenType: models.TokenTypeAccess,
		// Rotation stays inside the session the refresh token belongs to, so a
		// later logout revokes this token too.
		SessionID: claims.SessionID,
	}

	// Generate access token
	accessTokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessTokenJWT.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to generate new access token",
			slog.Int64("user_id", user.ID),
			slog.String("error", err.Error()))
		return "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Store new access token metadata
	accessMetadata := &models.TokenMetadata{
		ID:        accessTokenID,
		UserID:    user.ID,
		TokenType: models.TokenTypeAccess,
		SessionID: claims.SessionID,
		IsRevoked: false,
		CreatedAt: time.Now(),
		ExpiresAt: accessClaims.ExpiresAt.Time,
	}

	if err := s.store.SaveTokenMetadata(ctx, accessMetadata); err != nil {
		s.logger.ErrorContext(ctx, "Failed to store new access token metadata",
			slog.String("token_id", accessTokenID),
			slog.Int64("user_id", user.ID),
			slog.String("error", err.Error()))
		return "", fmt.Errorf("failed to store access token metadata: %w", err)
	}

	s.logger.InfoContext(ctx, "Successfully refreshed access token",
		slog.Int64("user_id", user.ID),
		slog.String("new_token_id", accessTokenID),
		slog.String("refresh_token_id", claims.ID),
		slog.String("session_id", claims.SessionID))

	return accessToken, nil
}

// RevokeToken invalidates a token (for blacklisting)
func (s *tokenService) RevokeToken(ctx context.Context, tokenStr string) error {
	// Parse token to get ID
	claims, err := s.parseTokenWithoutValidation(tokenStr)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to parse token for revocation", slog.String("error", err.Error()))
		return fmt.Errorf("failed to parse token for revocation: %w", err)
	}

	s.logger.InfoContext(ctx, "Revoking token",
		slog.String("token_id", claims.ID),
		slog.Int64("user_id", claims.UserID),
		slog.String("token_type", claims.TokenType))

	// Revoke token in store
	if err := s.store.RevokeToken(ctx, claims.ID); err != nil {
		s.logger.ErrorContext(ctx, "Failed to revoke token",
			slog.String("token_id", claims.ID),
			slog.String("error", err.Error()))
		return err
	}

	s.logger.InfoContext(ctx, "Successfully revoked token",
		slog.String("token_id", claims.ID),
		slog.Int64("user_id", claims.UserID))

	return nil
}

// RevokeSession revokes every token issued in the same session as the given
// claims: the access token, the refresh token it was paired with, and any
// access token rotated from that refresh token. Revoking only the presented
// access token would leave the refresh token able to mint replacements for the
// rest of its lifetime.
func (s *tokenService) RevokeSession(ctx context.Context, claims *models.Claims) error {
	if claims.SessionID == "" {
		// Issued before tokens carried a session id; this token is the only one
		// that can still be identified.
		s.logger.WarnContext(ctx, "Revoking a token with no session id",
			slog.String("token_id", claims.ID),
			slog.Int64("user_id", claims.UserID))
		return s.store.RevokeToken(ctx, claims.ID)
	}

	s.logger.InfoContext(ctx, "Revoking session",
		slog.String("session_id", claims.SessionID),
		slog.Int64("user_id", claims.UserID))

	if err := s.store.RevokeSession(ctx, claims.SessionID); err != nil {
		s.logger.ErrorContext(ctx, "Failed to revoke session",
			slog.String("session_id", claims.SessionID),
			slog.String("error", err.Error()))
		return err
	}

	return nil
}

// GetTokenMetadata retrieves stored metadata for a token
func (s *tokenService) GetTokenMetadata(ctx context.Context, tokenID string) (*models.TokenMetadata, error) {
	metadata, err := s.store.GetTokenMetadata(ctx, tokenID)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to get token metadata",
			slog.String("token_id", tokenID),
			slog.String("error", err.Error()))
		return nil, err
	}
	return metadata, nil
}

// IsTokenRevoked checks if a token has been revoked
func (s *tokenService) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	revoked, err := s.store.IsTokenRevoked(ctx, tokenID)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to check if token is revoked",
			slog.String("token_id", tokenID),
			slog.String("error", err.Error()))
		return false, err
	}
	return revoked, nil
}

// RevokeAllTokensForUser invalidates all tokens for a specific user
func (s *tokenService) RevokeAllTokensForUser(ctx context.Context, userID int64) error {
	s.logger.InfoContext(ctx, "Revoking all tokens for user", slog.Int64("user_id", userID))

	err := s.store.RevokeAllTokensForUser(ctx, userID)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to revoke all tokens for user",
			slog.Int64("user_id", userID),
			slog.String("error", err.Error()))
		return err
	}

	s.logger.InfoContext(ctx, "Successfully revoked all tokens for user", slog.Int64("user_id", userID))
	return nil
}

// CleanupExpiredTokens removes expired tokens from storage
func (s *tokenService) CleanupExpiredTokens(ctx context.Context) error {
	s.logger.InfoContext(ctx, "Starting cleanup of expired tokens")

	err := s.store.CleanupExpiredTokens(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to cleanup expired tokens", slog.String("error", err.Error()))
		return err
	}

	s.logger.InfoContext(ctx, "Successfully cleaned up expired tokens")
	return nil
}

// Helper function to parse token without validation
func (s *tokenService) parseTokenWithoutValidation(tokenString string) (*models.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.config.JWTSecret), nil
	})

	if err != nil && token == nil {
		return nil, err
	}

	claims, ok := token.Claims.(*models.Claims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	return claims, nil
}
