package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eupneart/auth-service/internal/models"
	"github.com/stretchr/testify/assert"
)

type tokenServiceStub struct {
	claims *models.Claims
	err    error
}

func (s tokenServiceStub) GenerateTokens(context.Context, *models.User) (string, string, error) {
	return "", "", nil
}

func (s tokenServiceStub) ValidateToken(context.Context, string) (*models.Claims, error) {
	return s.claims, s.err
}

func (s tokenServiceStub) RefreshAccessToken(context.Context, string) (string, error) {
	return "", nil
}

func (s tokenServiceStub) RevokeToken(context.Context, string) error { return nil }
func (s tokenServiceStub) GetTokenMetadata(context.Context, string) (*models.TokenMetadata, error) {
	return nil, nil
}
func (s tokenServiceStub) IsTokenRevoked(context.Context, string) (bool, error) { return false, nil }
func (s tokenServiceStub) RevokeAllTokensForUser(context.Context, int64) error  { return nil }
func (s tokenServiceStub) CleanupExpiredTokens(context.Context) error           { return nil }

func TestAuthMiddlewarePropagatesClaims(t *testing.T) {
	service := tokenServiceStub{claims: &models.Claims{
		UserID: 7, Email: "user@example.com", TokenType: models.TokenTypeAccess,
	}}
	handler := Auth(service)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, int64(7), GetUserIDFromContext(r))
		assert.Equal(t, "access-token", func() string {
			token, _ := GetTokenFromContext(r)
			return token
		}())
		assert.NotNil(t, GetClaimsFromContext(r))
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestAuthMiddlewareRejectsMissingAndMalformedHeaders(t *testing.T) {
	for _, header := range []string{"", "Basic credentials", "Bearer"} {
		t.Run(header, func(t *testing.T) {
			handler := Auth(tokenServiceStub{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("protected handler should not be called")
			}))
			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			req.Header.Set("Authorization", header)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

func TestAuthMiddlewareRejectsInvalidTokenAndNilClaims(t *testing.T) {
	testCases := []tokenServiceStub{
		{err: errors.New("token expired")},
		{claims: nil},
	}
	for _, service := range testCases {
		handlerCalled := false
		handler := Auth(service)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			handlerCalled = true
		}))
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		req.Header.Set("Authorization", "Bearer access-token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.False(t, handlerCalled)
	}
}

func TestAuthMiddlewareRejectsRefreshToken(t *testing.T) {
	service := tokenServiceStub{
		claims: &models.Claims{UserID: 7, TokenType: models.TokenTypeRefresh},
	}
	handlerCalled := false
	handler := Auth(service)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handlerCalled = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer refresh-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, handlerCalled)
}

// The context getters are reachable from handlers that were not wrapped in Auth,
// where the values are absent. They must report that rather than panic, so a
// missing identity can never be read as user 0 holding valid claims.
func TestContextGettersOnUnauthenticatedRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/me", nil)

	assert.Nil(t, GetClaimsFromContext(req))
	assert.Zero(t, GetUserIDFromContext(req))

	token, err := GetTokenFromContext(req)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestGetTokenFromContextRejectsEmptyToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req = req.WithContext(context.WithValue(req.Context(), tokenContextKey, ""))

	token, err := GetTokenFromContext(req)
	assert.Error(t, err)
	assert.Empty(t, token)
}
