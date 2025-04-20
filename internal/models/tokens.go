package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims structure for both access and refresh tokens
type Claims struct {
	jwt.RegisteredClaims
	
	// User-specific claims
	UserID    string   `json:"user_id"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	
	// Token-specific claims
	TokenType string   `json:"token_type"` // "access" or "refresh"
	
	// Extra metadata
	DeviceID  string   `json:"device_id,omitempty"`  // For tracking different devices
	ClientID  string   `json:"client_id,omitempty"`  // For different client applications
}

// TokenResponse represents the API response containing both access and refresh tokens
type TokenResponse struct {
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	TokenType      string `json:"token_type"` // Bearer
	ExpiresIn      int64  `json:"expires_in"` // Access token expiration in seconds
	RefreshExpiresIn int64 `json:"refresh_expires_in,omitempty"` // Refresh token expiration in seconds
}

// TokenPair represents the internal structure for token management
type TokenPair struct {
	AccessToken    string
	RefreshToken   string
	AccessTokenID  string // JTI for access token
	RefreshTokenID string // JTI for refresh token
	ExpiresAt      time.Time
	RefreshExpiresAt time.Time
}

// TokenMetadata represents additional token metadata for storage/tracking
type TokenMetadata struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	TokenType  string    `json:"token_type"`
	DeviceID   string    `json:"device_id,omitempty"`
	ClientID   string    `json:"client_id,omitempty"`
	IsRevoked  bool      `json:"is_revoked"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
}

// RefreshTokenRequest represents the request body for token refresh
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	DeviceID     string `json:"device_id,omitempty"`
}

// TokenRevocationRequest represents the request to revoke a token
type TokenRevocationRequest struct {
	Token     string `json:"token" binding:"required"`
	TokenType string `json:"token_type,omitempty"` // Optional: "access" or "refresh"
}

// TokenValidationResponse represents the response for token validation
type TokenValidationResponse struct {
	Valid     bool      `json:"valid"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Claims    *Claims   `json:"claims,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// TokenPreferences represents user-specific token preferences
type TokenPreferences struct {
	UserID                 string `json:"user_id"`
	AccessTokenLifetime    int    `json:"access_token_lifetime"`  // in minutes
	RefreshTokenLifetime   int    `json:"refresh_token_lifetime"` // in hours
	AllowMultipleDevices   bool   `json:"allow_multiple_devices"`
	MaxActiveSessions      int    `json:"max_active_sessions"`
}

// Constants for token types and defaults
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
	
	DefaultAccessTokenLifetime  = 15 * time.Minute
	DefaultRefreshTokenLifetime = 7 * 24 * time.Hour // 7 days
	DefaultTokenType            = "Bearer"
)
