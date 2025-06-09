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
	s.logger.Info("Generating tokens for user",
		slog.Int64("user_id", user.ID),
		slog.String("email", user.Email))

	// Generate unique IDs for both tokens
	accessTokenID := uuid.New().String()
	refreshTokenID := uuid.New().String()

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
		TokenType: models.TokenTypeRefresh,
	}

	// Generate access token
	accessTokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessTokenJWT.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		s.logger.Error("Failed to generate access token",
			slog.Int64("user_id", user.ID),
			slog.String("error", err.Error()))
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshTokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = refreshTokenJWT.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		s.logger.Error("Failed to generate refresh token",
			slog.Int64("user_id", user.ID),
			slog.String("error", err.Error()))
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store token metadata
	accessMetadata := &models.TokenMetadata{
		ID:        accessTokenID,
		UserID:    user.ID,
		TokenType: models.TokenTypeAccess,
		IsRevoked: false,
		CreatedAt: time.Now(),
		ExpiresAt: accessClaims.ExpiresAt.Time,
	}

	refreshMetadata := &models.TokenMetadata{
		ID:        refreshTokenID,
		UserID:    user.ID,
		TokenType: models.TokenTypeRefresh,
		IsRevoked: false,
		CreatedAt: time.Now(),
		ExpiresAt: refreshClaims.ExpiresAt.Time,
	}

	// Store both tokens metadata
	if err := s.store.SaveTokenMetadata(ctx, accessMetadata); err != nil {
		s.logger.Error("Failed to store access token metadata",
			slog.Int64("user_id", user.ID),
			slog.String("token_id", accessTokenID),
			slog.String("error", err.Error()))
		return "", "", fmt.Errorf("failed to store access token metadata: %w", err)
	}

	if err := s.store.SaveTokenMetadata(ctx, refreshMetadata); err != nil {
		s.logger.Error("Failed to store refresh token metadata",
			slog.Int64("user_id", user.ID),
			slog.String("token_id", refreshTokenID),
			slog.String("error", err.Error()))
		return "", "", fmt.Errorf("failed to store refresh token metadata: %w", err)
	}

	s.logger.Info("Successfully generated tokens",
		slog.Int64("user_id", user.ID),
		slog.String("access_token_id", accessTokenID),
		slog.String("refresh_token_id", refreshTokenID))

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
		s.logger.Warn("Failed to parse token", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*models.Claims)
	if !ok || !token.Valid {
		s.logger.Warn("Invalid token claims or token not valid")
		return nil, ErrInvalidToken
	}

	// Check if token is revoked
	revoked, err := s.store.IsTokenRevoked(ctx, claims.ID)
	if err != nil {
		s.logger.Error("Failed to check token revocation status",
			slog.String("token_id", claims.ID),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to check token revocation status: %w", err)
	}
	if revoked {
		s.logger.Warn("Attempted to use revoked token",
			slog.String("token_id", claims.ID),
			slog.Int64("user_id", claims.UserID))
		return nil, ErrTokenRevoked
	}

	// Update last used timestamp
	if err := s.store.UpdateLastUsed(ctx, claims.ID); err != nil {
		s.logger.Error("Failed to update token last used timestamp",
			slog.String("token_id", claims.ID),
			slog.String("error", err.Error()))
		// Don't fail the validation for this error
	}

	s.logger.Debug("Token validated successfully",
		slog.String("token_id", claims.ID),
		slog.Int64("user_id", claims.UserID),
		slog.String("token_type", claims.TokenType))

	return claims, nil
}

// RefreshAccessToken generates a new access token using a refresh token
func (s *tokenService) RefreshAccessToken(ctx context.Context, refreshToken string) (accessToken string, err error) {
	s.logger.Info("Refreshing access token")

	// Validate refresh token
	claims, err := s.ValidateToken(ctx, refreshToken)
	if err != nil {
		s.logger.Warn("Invalid refresh token provided", slog.String("error", err.Error()))
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if it's actually a refresh token
	if claims.TokenType != models.TokenTypeRefresh {
		s.logger.Warn("Attempted to refresh with non-refresh token",
			slog.String("token_type", claims.TokenType),
			slog.Int64("user_id", claims.UserID))
		return "", ErrInvalidTokenType
	}

	// Get user to fetch latest roles and information
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		s.logger.Error("Failed to get user for token refresh",
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
	}

	// Generate access token
	accessTokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessTokenJWT.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		s.logger.Error("Failed to generate new access token",
			slog.Int64("user_id", user.ID),
			slog.String("error", err.Error()))
		return "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Store new access token metadata
	accessMetadata := &models.TokenMetadata{
		ID:        accessTokenID,
		UserID:    user.ID,
		TokenType: models.TokenTypeAccess,
		IsRevoked: false,
		CreatedAt: time.Now(),
		ExpiresAt: accessClaims.ExpiresAt.Time,
	}

	if err := s.store.SaveTokenMetadata(ctx, accessMetadata); err != nil {
		s.logger.Error("Failed to store new access token metadata",
			slog.String("token_id", accessTokenID),
			slog.Int64("user_id", user.ID),
			slog.String("error", err.Error()))
		return "", fmt.Errorf("failed to store access token metadata: %w", err)
	}

	s.logger.Info("Successfully refreshed access token",
		slog.Int64("user_id", user.ID),
		slog.String("new_token_id", accessTokenID),
		slog.String("refresh_token_id", claims.ID))

	return accessToken, nil
}

// RevokeToken invalidates a token (for blacklisting)
func (s *tokenService) RevokeToken(ctx context.Context, tokenStr string) error {
	// Parse token to get ID
	claims, err := s.parseTokenWithoutValidation(tokenStr)
	if err != nil {
		s.logger.Error("Failed to parse token for revocation", slog.String("error", err.Error()))
		return fmt.Errorf("failed to parse token for revocation: %w", err)
	}

	s.logger.Info("Revoking token",
		slog.String("token_id", claims.ID),
		slog.Int64("user_id", claims.UserID),
		slog.String("token_type", claims.TokenType))

	// Revoke token in store
	if err := s.store.RevokeToken(ctx, claims.ID); err != nil {
		s.logger.Error("Failed to revoke token",
			slog.String("token_id", claims.ID),
			slog.String("error", err.Error()))
		return err
	}

	s.logger.Info("Successfully revoked token",
		slog.String("token_id", claims.ID),
		slog.Int64("user_id", claims.UserID))

	return nil
}

// GetTokenMetadata retrieves stored metadata for a token
func (s *tokenService) GetTokenMetadata(ctx context.Context, tokenID string) (*models.TokenMetadata, error) {
	metadata, err := s.store.GetTokenMetadata(ctx, tokenID)
	if err != nil {
		s.logger.Error("Failed to get token metadata",
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
		s.logger.Error("Failed to check if token is revoked",
			slog.String("token_id", tokenID),
			slog.String("error", err.Error()))
		return false, err
	}
	return revoked, nil
}

// RevokeAllTokensForUser invalidates all tokens for a specific user
func (s *tokenService) RevokeAllTokensForUser(ctx context.Context, userID string) error {
	s.logger.Info("Revoking all tokens for user", slog.String("user_id", userID))

	err := s.store.RevokeAllTokensForUser(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to revoke all tokens for user",
			slog.String("user_id", userID),
			slog.String("error", err.Error()))
		return err
	}

	s.logger.Info("Successfully revoked all tokens for user", slog.String("user_id", userID))
	return nil
}

// CleanupExpiredTokens removes expired tokens from storage
func (s *tokenService) CleanupExpiredTokens(ctx context.Context) error {
	s.logger.Info("Starting cleanup of expired tokens")

	err := s.store.CleanupExpiredTokens(ctx)
	if err != nil {
		s.logger.Error("Failed to cleanup expired tokens", slog.String("error", err.Error()))
		return err
	}

	s.logger.Info("Successfully cleaned up expired tokens")
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
