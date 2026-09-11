package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/eupneart/auth-service/internal/api"
	"github.com/eupneart/auth-service/internal/models"
	"github.com/eupneart/auth-service/internal/repositories"
	"github.com/eupneart/auth-service/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	recoveryEmail       = "user@example.com"
	recoveryOldPassword = "OldPassw0rd!"
	recoveryNewPassword = "NewPassw0rd!"
	recoveryBaseURL     = "https://app.example.com/reset-password"
)

// recoveryUserRepo keeps the account in memory so the test can observe the
// stored password hash changing.
type recoveryUserRepo struct {
	mu   sync.Mutex
	user *models.User
}

func newRecoveryUserRepo(t *testing.T) *recoveryUserRepo {
	t.Helper()

	hashed, err := bcrypt.GenerateFromPassword([]byte(recoveryOldPassword), bcrypt.MinCost)
	require.NoError(t, err)

	return &recoveryUserRepo{
		user: &models.User{ID: 1, Email: recoveryEmail, Password: string(hashed), IsActive: true},
	}
}

func (r *recoveryUserRepo) storedPassword() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.user.Password
}

func (r *recoveryUserRepo) GetAll(context.Context) ([]*models.User, error) { return nil, nil }

func (r *recoveryUserRepo) GetByID(_ context.Context, id int64) (*models.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id != r.user.ID {
		return nil, nil
	}
	copied := *r.user
	return &copied, nil
}

func (r *recoveryUserRepo) GetByEmail(_ context.Context, email string) (*models.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if email != r.user.Email {
		return nil, nil
	}
	copied := *r.user
	return &copied, nil
}

func (r *recoveryUserRepo) Update(context.Context, models.User) error { return nil }

func (r *recoveryUserRepo) UpdatePassword(_ context.Context, _ int64, hashedPassword string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.user.Password = hashedPassword
	return nil
}

func (r *recoveryUserRepo) DeleteByID(context.Context, int64) error { return nil }

func (r *recoveryUserRepo) Insert(context.Context, models.User) (int64, error) { return 1, nil }

// recoveryTokenStore reproduces the repository's single-use semantics in memory:
// a token is consumable once, and only while unexpired.
type recoveryTokenStore struct {
	mu     sync.Mutex
	tokens map[string]*models.PasswordResetToken
	nextID int64
}

func newRecoveryTokenStore() *recoveryTokenStore {
	return &recoveryTokenStore{tokens: make(map[string]*models.PasswordResetToken)}
}

func (s *recoveryTokenStore) CreatePasswordResetToken(_ context.Context, token *models.PasswordResetToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	token.ID = s.nextID
	token.CreatedAt = time.Now()
	stored := *token
	s.tokens[token.TokenHash] = &stored
	return nil
}

func (s *recoveryTokenStore) ConsumePasswordResetToken(_ context.Context, tokenHash string) (*models.PasswordResetToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, ok := s.tokens[tokenHash]
	if !ok || token.ConsumedAt != nil || time.Now().After(token.ExpiresAt) {
		return nil, repositories.ErrResetTokenNotFound
	}

	now := time.Now()
	token.ConsumedAt = &now
	consumed := *token
	return &consumed, nil
}

func (s *recoveryTokenStore) InvalidatePasswordResetTokensForUser(_ context.Context, userID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, token := range s.tokens {
		if token.UserID == userID && token.ConsumedAt == nil {
			token.ConsumedAt = &now
		}
	}
	return nil
}

func (s *recoveryTokenStore) storedHashes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	hashes := make([]string, 0, len(s.tokens))
	for hash := range s.tokens {
		hashes = append(hashes, hash)
	}
	return hashes
}

type recoveryMailer struct {
	mu    sync.Mutex
	urls  []string
	sends int
}

func (m *recoveryMailer) SendPasswordReset(_ context.Context, _, resetURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.urls = append(m.urls, resetURL)
	m.sends++
	return nil
}

func (m *recoveryMailer) lastURL() (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.urls) == 0 {
		return "", m.sends
	}
	return m.urls[len(m.urls)-1], m.sends
}

// recoveryTokenService rejects the pre-existing session once the password change
// revokes it.
type recoveryTokenService struct {
	mu      sync.Mutex
	revoked bool
}

func (s *recoveryTokenService) isRevoked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked
}

func (s *recoveryTokenService) GenerateTokens(context.Context, *models.User) (string, string, error) {
	return "access-token", "refresh-token", nil
}

func (s *recoveryTokenService) ValidateToken(_ context.Context, token string) (*models.Claims, error) {
	if token != "access-token" || s.isRevoked() {
		return nil, repositories.ErrResetTokenNotFound
	}
	return &models.Claims{UserID: 1, Email: recoveryEmail, TokenType: models.TokenTypeAccess}, nil
}

func (s *recoveryTokenService) RefreshAccessToken(context.Context, string) (string, error) {
	return "access-token", nil
}

func (s *recoveryTokenService) RevokeToken(context.Context, string) error { return nil }

// These tests exercise password recovery, which revokes by user rather than by
// session, so logout's path is a no-op here.
func (s *recoveryTokenService) RevokeSession(context.Context, *models.Claims) error { return nil }

func (s *recoveryTokenService) GetTokenMetadata(context.Context, string) (*models.TokenMetadata, error) {
	return nil, nil
}

func (s *recoveryTokenService) IsTokenRevoked(context.Context, string) (bool, error) {
	return s.isRevoked(), nil
}

func (s *recoveryTokenService) RevokeAllTokensForUser(context.Context, int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = true
	return nil
}

func (s *recoveryTokenService) CleanupExpiredTokens(context.Context) error { return nil }

func newRecoveryServer(t *testing.T) (http.Handler, *recoveryUserRepo, *recoveryTokenStore, *recoveryMailer, *recoveryTokenService) {
	t.Helper()

	repo := newRecoveryUserRepo(t)
	tokens := newRecoveryTokenStore()
	mailer := &recoveryMailer{}
	tokenService := &recoveryTokenService{}

	userService := services.New(repo)
	resetService := services.NewPasswordResetService(
		services.PasswordResetConfig{BaseURL: recoveryBaseURL, TokenLifetime: 15 * time.Minute},
		userService, repo, tokens, tokenService, mailer,
	)

	server := api.NewServer(nil, userService, tokenService, resetService)
	return server.Routes(), repo, tokens, mailer, tokenService
}

// waitForResetLink blocks until ForgotPassword's detached goroutine has sent,
// then returns the raw token from the emailed URL.
func waitForResetLink(t *testing.T, mailer *recoveryMailer, wantSends int) string {
	t.Helper()

	var link string
	require.Eventually(t, func() bool {
		var sends int
		link, sends = mailer.lastURL()
		return sends == wantSends
	}, 2*time.Second, 10*time.Millisecond, "reset link was never sent")

	parsed, err := url.Parse(link)
	require.NoError(t, err)

	rawToken := parsed.Query().Get("token")
	require.NotEmpty(t, rawToken)
	return rawToken
}

func TestPasswordRecoveryFlow(t *testing.T) {
	router, repo, tokens, mailer, tokenService := newRecoveryServer(t)
	originalPassword := repo.storedPassword()

	// The existing session works before the reset.
	before := request(t, router, http.MethodGet, "/me", "", "Bearer access-token")
	require.Equal(t, http.StatusOK, before.Code)

	forgot := request(t, router, http.MethodPost, "/password/forgot",
		`{"email":"`+recoveryEmail+`"}`, "")
	require.Equal(t, http.StatusAccepted, forgot.Code)
	require.NotContains(t, forgot.Body.String(), "token")

	rawToken := waitForResetLink(t, mailer, 1)

	// Only the hash is stored; the emailed value never reaches the database.
	sum := sha256.Sum256([]byte(rawToken))
	require.Equal(t, []string{hex.EncodeToString(sum[:])}, tokens.storedHashes())

	reset := request(t, router, http.MethodPost, "/password/reset",
		`{"token":"`+rawToken+`","new_password":"`+recoveryNewPassword+`"}`, "")
	require.Equal(t, http.StatusOK, reset.Code)
	// Recovery must not hand back a session.
	require.NotContains(t, reset.Body.String(), "access-token")

	// The password actually changed, and to the value that was submitted.
	updated := repo.storedPassword()
	require.NotEqual(t, originalPassword, updated)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(updated), []byte(recoveryNewPassword)))

	// Every existing session was revoked.
	require.True(t, tokenService.isRevoked())
	after := request(t, router, http.MethodGet, "/me", "", "Bearer access-token")
	require.Equal(t, http.StatusUnauthorized, after.Code)

	// The link is single use.
	replay := request(t, router, http.MethodPost, "/password/reset",
		`{"token":"`+rawToken+`","new_password":"An0therPass!"}`, "")
	require.Equal(t, http.StatusBadRequest, replay.Code)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(repo.storedPassword()), []byte(recoveryNewPassword)),
		"a replayed token must not change the password again")
}

func TestPasswordRecoveryDoesNotRevealAccounts(t *testing.T) {
	router, _, tokens, mailer, _ := newRecoveryServer(t)

	unknown := request(t, router, http.MethodPost, "/password/forgot",
		`{"email":"nobody@example.com"}`, "")
	known := request(t, router, http.MethodPost, "/password/forgot",
		`{"email":"`+recoveryEmail+`"}`, "")

	assert.Equal(t, http.StatusAccepted, unknown.Code)
	assert.Equal(t, unknown.Code, known.Code)
	assert.Equal(t, unknown.Body.String(), known.Body.String(),
		"responses must be identical for unknown and existing addresses")

	// Only the real account produced a link.
	waitForResetLink(t, mailer, 1)
	assert.Len(t, tokens.storedHashes(), 1)
}

func TestPasswordRecoveryRejectsExpiredToken(t *testing.T) {
	repo := newRecoveryUserRepo(t)
	tokens := newRecoveryTokenStore()
	mailer := &recoveryMailer{}
	tokenService := &recoveryTokenService{}

	userService := services.New(repo)
	resetService := services.NewPasswordResetService(
		// Already expired by the time the link is redeemed.
		services.PasswordResetConfig{BaseURL: recoveryBaseURL, TokenLifetime: -time.Minute},
		userService, repo, tokens, tokenService, mailer,
	)
	router := api.NewServer(nil, userService, tokenService, resetService).Routes()

	forgot := request(t, router, http.MethodPost, "/password/forgot",
		`{"email":"`+recoveryEmail+`"}`, "")
	require.Equal(t, http.StatusAccepted, forgot.Code)

	rawToken := waitForResetLink(t, mailer, 1)

	reset := request(t, router, http.MethodPost, "/password/reset",
		`{"token":"`+rawToken+`","new_password":"`+recoveryNewPassword+`"}`, "")

	// Identical to the response for a token that never existed.
	require.Equal(t, http.StatusBadRequest, reset.Code)
	require.Contains(t, reset.Body.String(), "invalid or expired reset token")
	require.False(t, tokenService.isRevoked(), "an expired token must not revoke sessions")
}

func TestAuthenticatedPasswordChangeRevokesSessions(t *testing.T) {
	router, repo, _, _, tokenService := newRecoveryServer(t)

	wrong := request(t, router, http.MethodPost, "/password/change",
		`{"current_password":"WrongPassw0rd!","new_password":"`+recoveryNewPassword+`"}`,
		"Bearer access-token")
	require.Equal(t, http.StatusUnauthorized, wrong.Code)
	require.False(t, tokenService.isRevoked(), "a failed attempt must not revoke sessions")

	changed := request(t, router, http.MethodPost, "/password/change",
		`{"current_password":"`+recoveryOldPassword+`","new_password":"`+recoveryNewPassword+`"}`,
		"Bearer access-token")
	require.Equal(t, http.StatusOK, changed.Code)

	require.NoError(t, bcrypt.CompareHashAndPassword(
		[]byte(repo.storedPassword()), []byte(recoveryNewPassword)))

	after := request(t, router, http.MethodGet, "/me", "", "Bearer access-token")
	require.Equal(t, http.StatusUnauthorized, after.Code)
}
