package services

import (
	"context"
	"fmt"
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
}

func NewTokenService(config TokenServiceConfig, userRepo repositories.UserRepoInterface, store repositories.TokenStore) TokenService {
	return &tokenService{
		config:   config,
		userRepo: userRepo,
		store:    store,
	}
}

func (s *tokenService) GenerateTokens(ctx context.Context, user *models.User) (accessToken, refreshToken string, err error) {
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
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshTokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = refreshTokenJWT.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
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
		return "", "", fmt.Errorf("failed to store access token metadata: %w", err)
	}

	if err := s.store.SaveTokenMetadata(ctx, refreshMetadata); err != nil {
		return "", "", fmt.Errorf("failed to store refresh token metadata: %w", err)
	}

	return accessToken, refreshToken, nil
}

// ValidateToken verifies a token and returns its claims if valid
func (s *tokenService) ValidateToken(ctx context.Context, tokenString string) (*models.Claims, error) {
	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWTSecret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*models.Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Check if token is revoked
	revoked, err := s.store.IsTokenRevoked(ctx, claims.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check token revocation status: %w", err)
	}
	if revoked {
		return nil, ErrTokenRevoked
	}

	// Update last used timestamp
	if err := s.store.UpdateLastUsed(ctx, claims.ID); err != nil {
		// Log error but don't fail the validation
    // TODO: logging the error here
	}

	return claims, nil
}

// RefreshAccessToken generates a new access token using a refresh token
func (s *tokenService) RefreshAccessToken(ctx context.Context, refreshToken string) (accessToken string, err error) {
	// Validate refresh token
	claims, err := s.ValidateToken(ctx, refreshToken)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if it's actually a refresh token
	if claims.TokenType != models.TokenTypeRefresh {
		return "", ErrInvalidTokenType
	}

	// Get user to fetch latest roles and information
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
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
		return "", fmt.Errorf("failed to store access token metadata: %w", err)
	}

	return accessToken, nil
}

// RevokeToken invalidates a token (for blacklisting)
func (s *tokenService) RevokeToken(ctx context.Context, tokenString string) error {
	// Parse token to get ID
	claims, err := s.parseTokenWithoutValidation(tokenString)
	if err != nil {
		return fmt.Errorf("failed to parse token for revocation: %w", err)
	}

	// Revoke token in store
	return s.store.RevokeToken(ctx, claims.ID)
}

// GetTokenMetadata retrieves stored metadata for a token
func (s *tokenService) GetTokenMetadata(ctx context.Context, tokenID string) (*models.TokenMetadata, error) {
	return s.store.GetTokenMetadata(ctx, tokenID)
}

// IsTokenRevoked checks if a token has been revoked
func (s *tokenService) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	return s.store.IsTokenRevoked(ctx, tokenID)
}

// RevokeAllTokensForUser invalidates all tokens for a specific user
func (s *tokenService) RevokeAllTokensForUser(ctx context.Context, userID string) error {
	return s.store.RevokeAllTokensForUser(ctx, userID)
}

// CleanupExpiredTokens removes expired tokens from storage
func (s *tokenService) CleanupExpiredTokens(ctx context.Context) error {
	return s.store.CleanupExpiredTokens(ctx)
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
