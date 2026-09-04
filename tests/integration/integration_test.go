package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eupneart/auth-service/internal/api"
	"github.com/eupneart/auth-service/internal/models"
	"github.com/eupneart/auth-service/internal/services"
	"github.com/stretchr/testify/require"
)

type lifecycleTokenService struct {
	revoked bool
}

func (s *lifecycleTokenService) GenerateTokens(context.Context, *models.User) (string, string, error) {
	return "access-token", "refresh-token", nil
}
func (s *lifecycleTokenService) ValidateToken(_ context.Context, token string) (*models.Claims, error) {
	if s.revoked && token == "access-token" {
		return nil, errors.New("token has been revoked")
	}
	if token != "access-token" && token != "refresh-token" {
		return nil, errors.New("invalid token")
	}
	tokenType := models.TokenTypeAccess
	if token == "refresh-token" {
		tokenType = models.TokenTypeRefresh
	}
	return &models.Claims{UserID: 1, Email: "user@example.com", TokenType: tokenType}, nil
}
func (s *lifecycleTokenService) RefreshAccessToken(context.Context, string) (string, error) {
	return "access-token", nil
}
func (s *lifecycleTokenService) RevokeToken(context.Context, string) error {
	s.revoked = true
	return nil
}
func (s *lifecycleTokenService) GetTokenMetadata(context.Context, string) (*models.TokenMetadata, error) {
	return nil, nil
}
func (s *lifecycleTokenService) IsTokenRevoked(context.Context, string) (bool, error) {
	return s.revoked, nil
}
func (s *lifecycleTokenService) RevokeAllTokensForUser(context.Context, int64) error { return nil }
func (s *lifecycleTokenService) CleanupExpiredTokens(context.Context) error          { return nil }

type lifecycleUserRepo struct{}

func (lifecycleUserRepo) GetAll(context.Context) ([]*models.User, error) { return nil, nil }
func (lifecycleUserRepo) GetByID(context.Context, int64) (*models.User, error) {
	return &models.User{ID: 1, Email: "user@example.com", IsActive: true}, nil
}
func (lifecycleUserRepo) GetByEmail(context.Context, string) (*models.User, error) {
	return nil, nil
}
func (lifecycleUserRepo) Update(context.Context, models.User) error { return nil }
func (lifecycleUserRepo) DeleteByID(context.Context, int64) error   { return nil }
func (lifecycleUserRepo) Insert(context.Context, models.User) (int64, error) {
	return 1, nil
}

func TestTokenLifecycle(t *testing.T) {
	tokenService := &lifecycleTokenService{}
	server := api.NewServer(nil, services.New(lifecycleUserRepo{}), tokenService)
	router := server.Routes()

	refreshResponse := request(t, router, http.MethodPost, "/refresh",
		`{"refresh_token":"refresh-token"}`, "")
	require.Equal(t, http.StatusOK, refreshResponse.Code)
	require.Contains(t, refreshResponse.Body.String(), "access-token")

	validateResponse := request(t, router, http.MethodPost, "/validate",
		`{"token":"access-token"}`, "")
	require.Equal(t, http.StatusOK, validateResponse.Code)
	require.Contains(t, validateResponse.Body.String(), `"valid": true`)

	meResponse := request(t, router, http.MethodGet, "/me", "", "Bearer access-token")
	require.Equal(t, http.StatusOK, meResponse.Code)
	require.Contains(t, meResponse.Body.String(), "user@example.com")

	logoutResponse := request(t, router, http.MethodPost, "/logout", "", "Bearer access-token")
	require.Equal(t, http.StatusOK, logoutResponse.Code)

	reuseResponse := request(t, router, http.MethodGet, "/me", "", "Bearer access-token")
	require.Equal(t, http.StatusUnauthorized, reuseResponse.Code)
}

func request(t *testing.T, handler http.Handler, method, path, body, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}
