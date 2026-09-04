package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/eupneart/auth-service/internal/models"
	"github.com/eupneart/auth-service/internal/services"
)

type contextKey string

const (
	claimsContextKey contextKey = "claims"
	userIDContextKey contextKey = "user_id"
	tokenContextKey  contextKey = "token"
)

// Auth validates a Bearer token and adds its claims to the request context.
func Auth(tokenService services.TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if strings.TrimSpace(authHeader) == "" {
				slog.Warn("missing authorization header", "remote_addr", r.RemoteAddr)
				http.Error(w, "missing authorization header", http.StatusUnauthorized)
				return
			}
			parts := strings.Fields(authHeader)
			if len(parts) != 2 || parts[0] != models.DefaultTokenType || parts[1] == "" {
				slog.Warn("invalid authorization header", "remote_addr", r.RemoteAddr)
				http.Error(w, "invalid authorization format", http.StatusUnauthorized)
				return
			}
			if tokenService == nil {
				slog.Error("token service is not configured")
				http.Error(w, "authentication unavailable", http.StatusInternalServerError)
				return
			}

			token := parts[1]
			claims, err := tokenService.ValidateToken(r.Context(), token)
			if err != nil || claims == nil {
				slog.Warn("token validation failed", "error", err, "remote_addr", r.RemoteAddr)
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			if claims.TokenType != models.TokenTypeAccess {
				slog.Warn("non-access token used for protected route",
					"token_type", claims.TokenType,
					"user_id", claims.UserID,
					"remote_addr", r.RemoteAddr)
				http.Error(w, "invalid token type", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			ctx = context.WithValue(ctx, userIDContextKey, claims.UserID)
			ctx = context.WithValue(ctx, tokenContextKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetClaimsFromContext(r *http.Request) *models.Claims {
	claims, ok := r.Context().Value(claimsContextKey).(*models.Claims)
	if !ok {
		return nil
	}
	return claims
}

func GetUserIDFromContext(r *http.Request) int64 {
	userID, ok := r.Context().Value(userIDContextKey).(int64)
	if !ok {
		return 0
	}
	return userID
}

func GetTokenFromContext(r *http.Request) (string, error) {
	token, ok := r.Context().Value(tokenContextKey).(string)
	if !ok || token == "" {
		return "", errors.New("token not found in context")
	}
	return token, nil
}
