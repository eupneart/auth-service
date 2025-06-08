package services

import "errors"

var (
  // Token-specific errors
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenRevoked = errors.New("token has been revoked")
	ErrInvalidTokenType = errors.New("invalid token type")
	ErrInvalidClaims = errors.New("invalid token claims")
	ErrSigningKeyNotFound = errors.New("signing key not found")
	ErrMaxSessionsExceeded = errors.New("maximum number of sessions exceeded")
	ErrUserNotFound = errors.New("user not found")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)
