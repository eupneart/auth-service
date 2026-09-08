package services

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/eupneart/auth-service/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// Fakes
// ----------------------------------------------------------------------------

type fakeTokenStore struct {
	saved           []*models.TokenMetadata
	revokedIDs      []string
	updatedLastUsed []string
	revokedUsers    []int64
	cleanupCalls    int
	metadata        *models.TokenMetadata

	revoked       bool
	isRevokedErr  error
	saveErr       error
	saveErrAfter  int // saves that succeed before saveErr is returned
	revokeErr     error
	updateUsedErr error
	metadataErr   error
	revokeAllErr  error
	cleanupErr    error
}

func (f *fakeTokenStore) SaveTokenMetadata(_ context.Context, m *models.TokenMetadata) error {
	if f.saveErr != nil && len(f.saved) >= f.saveErrAfter {
		return f.saveErr
	}
	f.saved = append(f.saved, m)
	return nil
}
func (f *fakeTokenStore) GetTokenMetadata(context.Context, string) (*models.TokenMetadata, error) {
	return f.metadata, f.metadataErr
}
func (f *fakeTokenStore) IsTokenRevoked(context.Context, string) (bool, error) {
	return f.revoked, f.isRevokedErr
}
func (f *fakeTokenStore) RevokeToken(_ context.Context, id string) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revokedIDs = append(f.revokedIDs, id)
	return nil
}
func (f *fakeTokenStore) RevokeTokenByID(context.Context, string) error { return nil }
func (f *fakeTokenStore) RevokeAllTokensForUser(_ context.Context, userID int64) error {
	if f.revokeAllErr != nil {
		return f.revokeAllErr
	}
	f.revokedUsers = append(f.revokedUsers, userID)
	return nil
}
func (f *fakeTokenStore) UpdateLastUsed(_ context.Context, id string) error {
	if f.updateUsedErr != nil {
		return f.updateUsedErr
	}
	f.updatedLastUsed = append(f.updatedLastUsed, id)
	return nil
}
func (f *fakeTokenStore) CleanupExpiredTokens(context.Context) error {
	f.cleanupCalls++
	return f.cleanupErr
}
func (f *fakeTokenStore) GetAllTokensForUser(context.Context, string) ([]models.TokenMetadata, error) {
	return nil, nil
}

type fakeUserRepo struct {
	user   *models.User
	getErr error
}

func (f *fakeUserRepo) GetAll(context.Context) ([]*models.User, error) { return nil, nil }
func (f *fakeUserRepo) GetByID(context.Context, int64) (*models.User, error) {
	return f.user, f.getErr
}
func (f *fakeUserRepo) GetByEmail(context.Context, string) (*models.User, error) { return nil, nil }
func (f *fakeUserRepo) Update(context.Context, models.User) error                { return nil }
func (f *fakeUserRepo) UpdatePassword(context.Context, int64, string) error      { return nil }
func (f *fakeUserRepo) DeleteByID(context.Context, int64) error                  { return nil }
func (f *fakeUserRepo) Insert(context.Context, models.User) (int64, error)       { return 0, nil }

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

const testJWTSecret = "test-secret-value-not-for-production"

func newTestTokenService(store *fakeTokenStore, userRepo *fakeUserRepo) *tokenService {
	return &tokenService{
		config: TokenServiceConfig{
			JWTSecret:            testJWTSecret,
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 24 * time.Hour,
			Issuer:               "test-issuer",
		},
		userRepo: userRepo,
		store:    store,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func testUser() *models.User {
	return &models.User{ID: 42, Email: "user@example.com", Role: "user"}
}

// signClaims produces a signed JWT string for the given claims using an
// arbitrary secret. Used to build tampered/foreign tokens.
func signClaims(t *testing.T, claims *models.Claims, secret string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

func baseClaims(tokenType string, exp time.Time) *models.Claims {
	return &models.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "test-issuer",
			Subject:   "42",
			ID:        "token-id-1",
		},
		UserID:    42,
		Email:     "user@example.com",
		Role:      "user",
		TokenType: tokenType,
	}
}

// ----------------------------------------------------------------------------
// GenerateTokens
// ----------------------------------------------------------------------------

func TestTokenService_GenerateTokens_HappyPath(t *testing.T) {
	store := &fakeTokenStore{}
	svc := newTestTokenService(store, &fakeUserRepo{})

	access, refresh, err := svc.GenerateTokens(context.Background(), testUser())
	require.NoError(t, err)
	assert.NotEmpty(t, access)
	assert.NotEmpty(t, refresh)
	assert.Len(t, store.saved, 2, "both access and refresh metadata should be persisted")

	// Both tokens must parse and carry the expected identity.
	claims, err := svc.ValidateToken(context.Background(), access)
	require.NoError(t, err)
	assert.Equal(t, int64(42), claims.UserID)
	assert.Equal(t, models.TokenTypeAccess, claims.TokenType)
}

func TestTokenService_GenerateTokens_StoreError(t *testing.T) {
	store := &fakeTokenStore{saveErr: assert.AnError}
	svc := newTestTokenService(store, &fakeUserRepo{})

	_, _, err := svc.GenerateTokens(context.Background(), testUser())
	require.Error(t, err)
}

// ----------------------------------------------------------------------------
// ValidateToken
// ----------------------------------------------------------------------------

func TestTokenService_ValidateToken_Valid(t *testing.T) {
	store := &fakeTokenStore{}
	svc := newTestTokenService(store, &fakeUserRepo{})

	token := signClaims(t, baseClaims(models.TokenTypeAccess, time.Now().Add(time.Hour)), testJWTSecret)

	claims, err := svc.ValidateToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "token-id-1", claims.ID)
	assert.Equal(t, []string{"token-id-1"}, store.updatedLastUsed)
}

func TestTokenService_ValidateToken_ForeignSignature(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{}, &fakeUserRepo{})

	token := signClaims(t, baseClaims(models.TokenTypeAccess, time.Now().Add(time.Hour)), "a-different-secret")

	_, err := svc.ValidateToken(context.Background(), token)
	require.Error(t, err)
}

func TestTokenService_ValidateToken_Expired(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{}, &fakeUserRepo{})

	token := signClaims(t, baseClaims(models.TokenTypeAccess, time.Now().Add(-time.Hour)), testJWTSecret)

	_, err := svc.ValidateToken(context.Background(), token)
	require.Error(t, err)
}

func TestTokenService_ValidateToken_Revoked(t *testing.T) {
	store := &fakeTokenStore{revoked: true}
	svc := newTestTokenService(store, &fakeUserRepo{})

	token := signClaims(t, baseClaims(models.TokenTypeAccess, time.Now().Add(time.Hour)), testJWTSecret)

	_, err := svc.ValidateToken(context.Background(), token)
	require.ErrorIs(t, err, ErrTokenRevoked)
}

// ----------------------------------------------------------------------------
// RefreshAccessToken
// ----------------------------------------------------------------------------

func TestTokenService_RefreshAccessToken_HappyPath(t *testing.T) {
	store := &fakeTokenStore{}
	svc := newTestTokenService(store, &fakeUserRepo{user: testUser()})

	refresh := signClaims(t, baseClaims(models.TokenTypeRefresh, time.Now().Add(time.Hour)), testJWTSecret)

	access, err := svc.RefreshAccessToken(context.Background(), refresh)
	require.NoError(t, err)
	assert.NotEmpty(t, access)

	claims, err := svc.ValidateToken(context.Background(), access)
	require.NoError(t, err)
	assert.Equal(t, models.TokenTypeAccess, claims.TokenType)
	assert.Equal(t, int64(42), claims.UserID)
}

func TestTokenService_RefreshAccessToken_RejectsAccessToken(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{}, &fakeUserRepo{user: testUser()})

	access := signClaims(t, baseClaims(models.TokenTypeAccess, time.Now().Add(time.Hour)), testJWTSecret)

	_, err := svc.RefreshAccessToken(context.Background(), access)
	require.ErrorIs(t, err, ErrInvalidTokenType)
}

func TestTokenService_RefreshAccessToken_UserLookupError(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{}, &fakeUserRepo{getErr: assert.AnError})

	refresh := signClaims(t, baseClaims(models.TokenTypeRefresh, time.Now().Add(time.Hour)), testJWTSecret)

	_, err := svc.RefreshAccessToken(context.Background(), refresh)
	require.Error(t, err)
}

// ----------------------------------------------------------------------------
// RevokeToken
// ----------------------------------------------------------------------------

func TestTokenService_RevokeToken_CallsStore(t *testing.T) {
	store := &fakeTokenStore{}
	svc := newTestTokenService(store, &fakeUserRepo{})

	token := signClaims(t, baseClaims(models.TokenTypeAccess, time.Now().Add(time.Hour)), testJWTSecret)

	require.NoError(t, svc.RevokeToken(context.Background(), token))
	assert.Equal(t, []string{"token-id-1"}, store.revokedIDs)
}

func TestTokenService_RevokeToken_BadToken(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{}, &fakeUserRepo{})

	err := svc.RevokeToken(context.Background(), "not-a-jwt")
	require.Error(t, err)
}

// ----------------------------------------------------------------------------
// Store pass-throughs
// ----------------------------------------------------------------------------

func TestNewTokenService(t *testing.T) {
	store := &fakeTokenStore{}
	svc := NewTokenService(
		TokenServiceConfig{
			JWTSecret:            testJWTSecret,
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 24 * time.Hour,
			Issuer:               "test-issuer",
		},
		&fakeUserRepo{},
		store,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	require.NotNil(t, svc)
	require.NoError(t, svc.CleanupExpiredTokens(context.Background()))
	assert.Equal(t, 1, store.cleanupCalls)
}

func TestTokenService_GetTokenMetadata(t *testing.T) {
	store := &fakeTokenStore{metadata: &models.TokenMetadata{ID: "token-id-1", UserID: 42}}
	svc := newTestTokenService(store, &fakeUserRepo{})

	metadata, err := svc.GetTokenMetadata(context.Background(), "token-id-1")
	require.NoError(t, err)
	assert.Equal(t, "token-id-1", metadata.ID)
}

func TestTokenService_GetTokenMetadata_StoreError(t *testing.T) {
	store := &fakeTokenStore{metadataErr: assert.AnError}
	svc := newTestTokenService(store, &fakeUserRepo{})

	_, err := svc.GetTokenMetadata(context.Background(), "token-id-1")
	require.Error(t, err)
}

func TestTokenService_IsTokenRevoked(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{revoked: true}, &fakeUserRepo{})

	revoked, err := svc.IsTokenRevoked(context.Background(), "token-id-1")
	require.NoError(t, err)
	assert.True(t, revoked)
}

// A failed revocation lookup must not report the token as live.
func TestTokenService_IsTokenRevoked_StoreError(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{isRevokedErr: assert.AnError}, &fakeUserRepo{})

	revoked, err := svc.IsTokenRevoked(context.Background(), "token-id-1")
	require.Error(t, err)
	assert.False(t, revoked)
}

func TestTokenService_RevokeAllTokensForUser(t *testing.T) {
	store := &fakeTokenStore{}
	svc := newTestTokenService(store, &fakeUserRepo{})

	require.NoError(t, svc.RevokeAllTokensForUser(context.Background(), 42))
	assert.Equal(t, []int64{42}, store.revokedUsers)
}

func TestTokenService_RevokeAllTokensForUser_StoreError(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{revokeAllErr: assert.AnError}, &fakeUserRepo{})

	require.Error(t, svc.RevokeAllTokensForUser(context.Background(), 42))
}

func TestTokenService_CleanupExpiredTokens(t *testing.T) {
	store := &fakeTokenStore{}
	svc := newTestTokenService(store, &fakeUserRepo{})

	require.NoError(t, svc.CleanupExpiredTokens(context.Background()))
	assert.Equal(t, 1, store.cleanupCalls)
}

func TestTokenService_CleanupExpiredTokens_StoreError(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{cleanupErr: assert.AnError}, &fakeUserRepo{})

	require.Error(t, svc.CleanupExpiredTokens(context.Background()))
}

// ----------------------------------------------------------------------------
// Remaining error paths
// ----------------------------------------------------------------------------

// The access token is stored before the refresh token. If the second write
// fails the caller must get an error rather than a usable pair whose refresh
// half was never recorded.
func TestTokenService_GenerateTokens_RefreshMetadataStoreError(t *testing.T) {
	store := &fakeTokenStore{saveErr: assert.AnError, saveErrAfter: 1}
	svc := newTestTokenService(store, &fakeUserRepo{})

	access, refresh, err := svc.GenerateTokens(context.Background(), testUser())
	require.Error(t, err)
	assert.Empty(t, access)
	assert.Empty(t, refresh)
	assert.Len(t, store.saved, 1)
}

// A token presented with alg "none" must be rejected by the key function, not
// accepted as unsigned.
func TestTokenService_ValidateToken_RejectsNoneAlgorithm(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{}, &fakeUserRepo{})

	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims(models.TokenTypeAccess, time.Now().Add(time.Hour)))
	tokenStr, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = svc.ValidateToken(context.Background(), tokenStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
}

// If the revocation status cannot be read, validation must fail closed.
func TestTokenService_ValidateToken_RevocationCheckError(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{isRevokedErr: assert.AnError}, &fakeUserRepo{})

	token := signClaims(t, baseClaims(models.TokenTypeAccess, time.Now().Add(time.Hour)), testJWTSecret)

	_, err := svc.ValidateToken(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check token revocation status")
}

// Recording the last-used timestamp is bookkeeping. Failing it must not reject
// an otherwise valid token.
func TestTokenService_ValidateToken_SurvivesLastUsedFailure(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{updateUsedErr: assert.AnError}, &fakeUserRepo{})

	token := signClaims(t, baseClaims(models.TokenTypeAccess, time.Now().Add(time.Hour)), testJWTSecret)

	claims, err := svc.ValidateToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "token-id-1", claims.ID)
}

func TestTokenService_RefreshAccessToken_InvalidToken(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{}, &fakeUserRepo{user: testUser()})

	_, err := svc.RefreshAccessToken(context.Background(), "not-a-jwt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid refresh token")
}

func TestTokenService_RefreshAccessToken_StoreError(t *testing.T) {
	store := &fakeTokenStore{saveErr: assert.AnError}
	svc := newTestTokenService(store, &fakeUserRepo{user: testUser()})

	refresh := signClaims(t, baseClaims(models.TokenTypeRefresh, time.Now().Add(time.Hour)), testJWTSecret)

	access, err := svc.RefreshAccessToken(context.Background(), refresh)
	require.Error(t, err)
	assert.Empty(t, access)
}

func TestTokenService_RevokeToken_StoreError(t *testing.T) {
	svc := newTestTokenService(&fakeTokenStore{revokeErr: assert.AnError}, &fakeUserRepo{})

	token := signClaims(t, baseClaims(models.TokenTypeAccess, time.Now().Add(time.Hour)), testJWTSecret)

	require.Error(t, svc.RevokeToken(context.Background(), token))
}
