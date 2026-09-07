package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eupneart/auth-service/internal/models"
	"github.com/stretchr/testify/assert"
)

type routeTokenServiceStub struct{}

func (routeTokenServiceStub) GenerateTokens(context.Context, *models.User) (string, string, error) {
	return "", "", nil
}
func (routeTokenServiceStub) ValidateToken(context.Context, string) (*models.Claims, error) {
	return &models.Claims{UserID: 1}, nil
}
func (routeTokenServiceStub) RefreshAccessToken(context.Context, string) (string, error) {
	return "access-token", nil
}
func (routeTokenServiceStub) RevokeToken(context.Context, string) error { return nil }
func (routeTokenServiceStub) GetTokenMetadata(context.Context, string) (*models.TokenMetadata, error) {
	return nil, nil
}
func (routeTokenServiceStub) IsTokenRevoked(context.Context, string) (bool, error) { return false, nil }
func (routeTokenServiceStub) RevokeAllTokensForUser(context.Context, int64) error  { return nil }
func (routeTokenServiceStub) CleanupExpiredTokens(context.Context) error           { return nil }

func TestRoutesPublicAndProtectedEndpoints(t *testing.T) {
	server := NewServer(nil, nil, routeTokenServiceStub{}, nil)
	router := server.Routes()

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		status int
	}{
		{"refresh is public", http.MethodPost, "/refresh", `{"refresh_token":"refresh-token"}`, http.StatusOK},
		{"validate is public", http.MethodPost, "/validate", `{"token":"access-token"}`, http.StatusOK},
		{"logout is protected", http.MethodPost, "/logout", "", http.StatusUnauthorized},
		{"me is protected", http.MethodGet, "/me", "", http.StatusUnauthorized},
		{"password change is protected", http.MethodPost, "/password/change",
			`{"current_password":"OldPassw0rd!","new_password":"NewPassw0rd!"}`, http.StatusUnauthorized},
		{"ping remains available", http.MethodGet, "/ping", "", http.StatusOK},
		// Reaching validation proves the route is mounted and unauthenticated;
		// the payloads are rejected before any service call.
		{"forgot password is public", http.MethodPost, "/password/forgot",
			`{"email":"not-an-email"}`, http.StatusBadRequest},
		{"reset password is public", http.MethodPost, "/password/reset",
			`{}`, http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.body != "" {
				req = httptest.NewRequest(tc.method, tc.path,
					strings.NewReader(tc.body))
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tc.status, w.Code)
		})
	}
}

func TestRoutesRateLimitRecoveryEndpoints(t *testing.T) {
	server := NewServer(nil, nil, routeTokenServiceStub{}, nil)
	router := server.Routes()

	send := func() int {
		req := httptest.NewRequest(http.MethodPost, "/password/forgot",
			strings.NewReader(`{"email":"not-an-email"}`))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	for range passwordRequestsPerIP {
		assert.Equal(t, http.StatusBadRequest, send())
	}

	assert.Equal(t, http.StatusTooManyRequests, send(),
		"requests past the allowance must be rejected before reaching the handler")
}

func TestRoutesRateLimitDoesNotApplyToOtherEndpoints(t *testing.T) {
	server := NewServer(nil, nil, routeTokenServiceStub{}, nil)
	router := server.Routes()

	for range passwordRequestsPerIP + 5 {
		req := httptest.NewRequest(http.MethodPost, "/validate",
			strings.NewReader(`{"token":"access-token"}`))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
}
