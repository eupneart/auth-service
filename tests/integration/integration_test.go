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

// lifecycleTokenService issues session-tagged tokens of the form
// "<session>-access-token" and "<session>-refresh-token". Tracking revocation
// per token and per session separately is what lets a test tell the difference
// between revoking one token and ending a whole session.
type lifecycleTokenService struct {
	revokedTokens   map[string]bool
	revokedSessions map[string]bool
}

func newLifecycleTokenService() *lifecycleTokenService {
	return &lifecycleTokenService{
		revokedTokens:   map[string]bool{},
		revokedSessions: map[string]bool{},
	}
}

func (s *lifecycleTokenService) GenerateTokens(context.Context, *models.User) (string, string, error) {
	return "session-1-access-token", "session-1-refresh-token", nil
}
func (s *lifecycleTokenService) ValidateToken(_ context.Context, token string) (*models.Claims, error) {
	session, tokenType, ok := parseLifecycleToken(token)
	if !ok {
		return nil, errors.New("invalid token")
	}
	if s.revokedTokens[token] || s.revokedSessions[session] {
		return nil, errors.New("token has been revoked")
	}
	return &models.Claims{
		UserID:    1,
		Email:     "user@example.com",
		TokenType: tokenType,
		SessionID: session,
	}, nil
}

// RefreshAccessToken validates the refresh token the way the real service does,
// so a refresh token belonging to a revoked session cannot mint a replacement.
func (s *lifecycleTokenService) RefreshAccessToken(ctx context.Context, refreshToken string) (string, error) {
	claims, err := s.ValidateToken(ctx, refreshToken)
	if err != nil {
		return "", err
	}
	if claims.TokenType != models.TokenTypeRefresh {
		return "", errors.New("invalid token type")
	}
	return claims.SessionID + "-access-token", nil
}
func (s *lifecycleTokenService) RevokeToken(_ context.Context, token string) error {
	s.revokedTokens[token] = true
	return nil
}
func (s *lifecycleTokenService) RevokeSession(_ context.Context, claims *models.Claims) error {
	s.revokedSessions[claims.SessionID] = true
	return nil
}
func (s *lifecycleTokenService) GetTokenMetadata(context.Context, string) (*models.TokenMetadata, error) {
	return nil, nil
}
func (s *lifecycleTokenService) IsTokenRevoked(_ context.Context, tokenID string) (bool, error) {
	return s.revokedTokens[tokenID], nil
}
func (s *lifecycleTokenService) RevokeAllTokensForUser(context.Context, int64) error { return nil }
func (s *lifecycleTokenService) CleanupExpiredTokens(context.Context) error          { return nil }

func parseLifecycleToken(token string) (session, tokenType string, ok bool) {
	switch {
	case strings.HasSuffix(token, "-access-token"):
		return strings.TrimSuffix(token, "-access-token"), models.TokenTypeAccess, true
	case strings.HasSuffix(token, "-refresh-token"):
		return strings.TrimSuffix(token, "-refresh-token"), models.TokenTypeRefresh, true
	}
	return "", "", false
}

type lifecycleUserRepo struct{}

func (lifecycleUserRepo) GetAll(context.Context) ([]*models.User, error) { return nil, nil }
func (lifecycleUserRepo) GetByID(context.Context, int64) (*models.User, error) {
	return &models.User{ID: 1, Email: "user@example.com", IsActive: true}, nil
}
func (lifecycleUserRepo) GetByEmail(context.Context, string) (*models.User, error) {
	return nil, nil
}
func (lifecycleUserRepo) Update(context.Context, models.User) error           { return nil }
func (lifecycleUserRepo) UpdatePassword(context.Context, int64, string) error { return nil }
func (lifecycleUserRepo) DeleteByID(context.Context, int64) error             { return nil }
func (lifecycleUserRepo) Insert(context.Context, models.User) (int64, error) {
	return 1, nil
}

func TestTokenLifecycle(t *testing.T) {
	tokenService := newLifecycleTokenService()
	server := api.NewServer(nil, services.New(lifecycleUserRepo{}), tokenService, nil)
	router := server.Routes()

	refreshResponse := request(t, router, http.MethodPost, "/refresh",
		`{"refresh_token":"session-1-refresh-token"}`, "")
	require.Equal(t, http.StatusOK, refreshResponse.Code)
	require.Contains(t, refreshResponse.Body.String(), "session-1-access-token")

	validateResponse := request(t, router, http.MethodPost, "/validate",
		`{"token":"session-1-access-token"}`, "")
	require.Equal(t, http.StatusOK, validateResponse.Code)
	require.Contains(t, validateResponse.Body.String(), `"valid": true`)

	meResponse := request(t, router, http.MethodGet, "/me", "", "Bearer session-1-access-token")
	require.Equal(t, http.StatusOK, meResponse.Code)
	require.Contains(t, meResponse.Body.String(), "user@example.com")

	logoutResponse := request(t, router, http.MethodPost, "/logout", "", "Bearer session-1-access-token")
	require.Equal(t, http.StatusOK, logoutResponse.Code)

	reuseResponse := request(t, router, http.MethodGet, "/me", "", "Bearer session-1-access-token")
	require.Equal(t, http.StatusUnauthorized, reuseResponse.Code)
}

// Logging out must take the refresh token with it. While it did not, the caller
// could sign out and still mint a working access token for the rest of the
// refresh token's lifetime.
func TestLogoutRevokesTheRefreshToken(t *testing.T) {
	tokenService := newLifecycleTokenService()
	router := api.NewServer(nil, services.New(lifecycleUserRepo{}), tokenService, nil).Routes()

	logoutResponse := request(t, router, http.MethodPost, "/logout", "", "Bearer session-1-access-token")
	require.Equal(t, http.StatusOK, logoutResponse.Code)

	refreshResponse := request(t, router, http.MethodPost, "/refresh",
		`{"refresh_token":"session-1-refresh-token"}`, "")
	require.Equal(t, http.StatusUnauthorized, refreshResponse.Code)
}

// Every access token rotated from a refresh token stays in the same session, so
// logging out with the newest one still invalidates the original refresh token.
func TestLogoutAfterRefreshRevokesTheWholeSession(t *testing.T) {
	tokenService := newLifecycleTokenService()
	router := api.NewServer(nil, services.New(lifecycleUserRepo{}), tokenService, nil).Routes()

	refreshResponse := request(t, router, http.MethodPost, "/refresh",
		`{"refresh_token":"session-1-refresh-token"}`, "")
	require.Equal(t, http.StatusOK, refreshResponse.Code)

	logoutResponse := request(t, router, http.MethodPost, "/logout", "", "Bearer session-1-access-token")
	require.Equal(t, http.StatusOK, logoutResponse.Code)

	reuseResponse := request(t, router, http.MethodPost, "/refresh",
		`{"refresh_token":"session-1-refresh-token"}`, "")
	require.Equal(t, http.StatusUnauthorized, reuseResponse.Code)
}

// Sessions are revoked one at a time: signing out on one device must not sign
// the user out everywhere. Only ChangePassword and ResetWithToken do that.
func TestLogoutLeavesOtherSessionsAlone(t *testing.T) {
	tokenService := newLifecycleTokenService()
	router := api.NewServer(nil, services.New(lifecycleUserRepo{}), tokenService, nil).Routes()

	logoutResponse := request(t, router, http.MethodPost, "/logout", "", "Bearer session-1-access-token")
	require.Equal(t, http.StatusOK, logoutResponse.Code)

	otherSession := request(t, router, http.MethodGet, "/me", "", "Bearer session-2-access-token")
	require.Equal(t, http.StatusOK, otherSession.Code)

	otherRefresh := request(t, router, http.MethodPost, "/refresh",
		`{"refresh_token":"session-2-refresh-token"}`, "")
	require.Equal(t, http.StatusOK, otherRefresh.Code)
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
