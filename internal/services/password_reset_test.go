package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eupneart/auth-service/internal/models"
	"github.com/eupneart/auth-service/internal/repositories"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const testPassword = "NewPassw0rd!"

// ---------------------------------------------------------------- fakes

// fakeResetTokenStore records calls against the shared ops slice so tests can
// assert the order of the password-change writes.
type fakeResetTokenStore struct {
	ops        *[]string
	created    *models.PasswordResetToken
	consumed   *models.PasswordResetToken
	consumeErr error
	createErr  error
}

func (f *fakeResetTokenStore) CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	*f.ops = append(*f.ops, "create")
	f.created = token
	return f.createErr
}

func (f *fakeResetTokenStore) ConsumePasswordResetToken(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error) {
	*f.ops = append(*f.ops, "consume:"+tokenHash)
	if f.consumeErr != nil {
		return nil, f.consumeErr
	}
	return f.consumed, nil
}

func (f *fakeResetTokenStore) InvalidatePasswordResetTokensForUser(ctx context.Context, userID int64) error {
	*f.ops = append(*f.ops, "invalidate")
	return nil
}

type fakeSessions struct {
	TokenService
	ops       *[]string
	revokeErr error
}

func (f *fakeSessions) RevokeAllTokensForUser(ctx context.Context, userID int64) error {
	*f.ops = append(*f.ops, "revoke")
	return f.revokeErr
}

type fakeMailer struct {
	ops       *[]string
	recipient string
	resetURL  string
	err       error
}

func (f *fakeMailer) SendPasswordReset(ctx context.Context, recipient, resetURL string) error {
	*f.ops = append(*f.ops, "send")
	f.recipient = recipient
	f.resetURL = resetURL
	return f.err
}

type resetFixture struct {
	service *PasswordResetService
	repo    *MockUserRepo
	tokens  *fakeResetTokenStore
	mailer  *fakeMailer
	ops     *[]string
}

func newResetFixture(t *testing.T) *resetFixture {
	t.Helper()

	ops := &[]string{}
	repo := new(MockUserRepo)
	tokens := &fakeResetTokenStore{ops: ops}
	mailer := &fakeMailer{ops: ops}

	repo.On("UpdatePassword", mock.Anything, mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { *ops = append(*ops, "updatePassword") }).
		Return(nil).Maybe()

	service := NewPasswordResetService(
		PasswordResetConfig{
			BaseURL:       "https://eupneart.com/reset-password",
			TokenLifetime: 15 * time.Minute,
		},
		New(repo),
		repo,
		tokens,
		&fakeSessions{ops: ops},
		mailer,
	)

	return &resetFixture{service: service, repo: repo, tokens: tokens, mailer: mailer, ops: ops}
}

func activeUser() *models.User {
	return &models.User{ID: 7, Email: "user@example.com", IsActive: true}
}

// ---------------------------------------------------------------- ordering

// The password update must be the last write. If it ran earlier, a later
// failure would leave a changed password with live sessions.
func TestPasswordResetService_ChangePasswordWriteOrder(t *testing.T) {
	f := newResetFixture(t)

	hashed, err := bcrypt.GenerateFromPassword([]byte("OldPassw0rd!"), bcrypt.MinCost)
	require.NoError(t, err)

	user := activeUser()
	user.Password = string(hashed)
	f.repo.On("GetByID", mock.Anything, int64(7)).Return(user, nil)

	require.NoError(t, f.service.ChangePassword(context.Background(), 7, "OldPassw0rd!", testPassword))
	assert.Equal(t, []string{"revoke", "invalidate", "updatePassword"}, *f.ops)
}

func TestPasswordResetService_PasswordNotUpdatedWhenRevokeFails(t *testing.T) {
	f := newResetFixture(t)
	f.service.sessions = &fakeSessions{ops: f.ops, revokeErr: errors.New("boom")}

	f.tokens.consumed = &models.PasswordResetToken{UserID: 7}

	err := f.service.ResetWithToken(context.Background(), "raw-token", testPassword)
	require.Error(t, err)
	assert.NotContains(t, *f.ops, "updatePassword")
}

// ---------------------------------------------------------------- RequestReset

func TestPasswordResetService_RequestResetStoresHashAndMailsRawToken(t *testing.T) {
	f := newResetFixture(t)
	f.repo.On("GetByEmail", mock.Anything, "user@example.com").Return(activeUser(), nil)

	require.NoError(t, f.service.RequestReset(context.Background(), "user@example.com"))

	require.NotNil(t, f.tokens.created)
	assert.Equal(t, int64(7), f.tokens.created.UserID)
	assert.True(t, f.tokens.created.ExpiresAt.After(time.Now()))

	raw := rawTokenFromURL(t, f.mailer.resetURL)
	assert.NotEmpty(t, raw)

	// The database must hold the hash, never the value that was emailed.
	assert.NotEqual(t, raw, f.tokens.created.TokenHash)
	sum := sha256.Sum256([]byte(raw))
	assert.Equal(t, hex.EncodeToString(sum[:]), f.tokens.created.TokenHash)
	assert.Len(t, f.tokens.created.TokenHash, 64)

	assert.Equal(t, "user@example.com", f.mailer.recipient)
	assert.True(t, strings.HasPrefix(f.mailer.resetURL, "https://eupneart.com/reset-password?token="))
}

func TestPasswordResetService_RequestResetIsSilentForUnknownAndInactive(t *testing.T) {
	tests := []struct {
		name string
		user *models.User
	}{
		{"unknown account", nil},
		{"inactive account", &models.User{ID: 7, Email: "user@example.com", IsActive: false}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newResetFixture(t)
			f.repo.On("GetByEmail", mock.Anything, "user@example.com").Return(tc.user, nil)

			// nil, not an error: the caller must not be able to tell these apart
			// from a delivered reset.
			require.NoError(t, f.service.RequestReset(context.Background(), "user@example.com"))
			assert.Empty(t, *f.ops)
			assert.Nil(t, f.tokens.created)
		})
	}
}

// ---------------------------------------------------------------- ResetWithToken

func TestPasswordResetService_ResetWithTokenHashesBeforeLookup(t *testing.T) {
	f := newResetFixture(t)
	f.tokens.consumed = &models.PasswordResetToken{UserID: 7}

	require.NoError(t, f.service.ResetWithToken(context.Background(), "raw-token", testPassword))

	sum := sha256.Sum256([]byte("raw-token"))
	assert.Contains(t, *f.ops, "consume:"+hex.EncodeToString(sum[:]))
	assert.Equal(t, []string{"consume:" + hex.EncodeToString(sum[:]), "revoke", "invalidate", "updatePassword"}, *f.ops)
}

// A rejected password must not burn the user's single-use link.
func TestPasswordResetService_ResetWithTokenRejectsWeakPasswordBeforeConsuming(t *testing.T) {
	f := newResetFixture(t)

	err := f.service.ResetWithToken(context.Background(), "raw-token", "weak")
	require.ErrorIs(t, err, ErrWeakPassword)
	assert.Empty(t, *f.ops)
}

func TestPasswordResetService_ResetWithTokenMapsNotFoundToInvalid(t *testing.T) {
	f := newResetFixture(t)
	f.tokens.consumeErr = repositories.ErrResetTokenNotFound

	err := f.service.ResetWithToken(context.Background(), "raw-token", testPassword)
	require.ErrorIs(t, err, ErrInvalidResetToken)
	assert.NotContains(t, *f.ops, "updatePassword")
}

func TestPasswordResetService_ResetWithTokenPropagatesRepositoryFailure(t *testing.T) {
	f := newResetFixture(t)
	f.tokens.consumeErr = errors.New("connection lost")

	err := f.service.ResetWithToken(context.Background(), "raw-token", testPassword)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrInvalidResetToken))
}

// ---------------------------------------------------------------- ChangePassword

func TestPasswordResetService_ChangePasswordRejectsWrongCurrentPassword(t *testing.T) {
	f := newResetFixture(t)

	hashed, err := bcrypt.GenerateFromPassword([]byte("OldPassw0rd!"), bcrypt.MinCost)
	require.NoError(t, err)

	user := activeUser()
	user.Password = string(hashed)
	f.repo.On("GetByID", mock.Anything, int64(7)).Return(user, nil)

	err = f.service.ChangePassword(context.Background(), 7, "WrongPassw0rd!", testPassword)
	require.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Empty(t, *f.ops)
}

func TestPasswordResetService_ChangePasswordRejectsWeakNewPassword(t *testing.T) {
	f := newResetFixture(t)

	err := f.service.ChangePassword(context.Background(), 7, "OldPassw0rd!", "weak")
	require.ErrorIs(t, err, ErrWeakPassword)
	assert.Empty(t, *f.ops)
}

// ---------------------------------------------------------------- helpers

func rawTokenFromURL(t *testing.T, resetURL string) string {
	t.Helper()

	parsed, err := url.Parse(resetURL)
	require.NoError(t, err)
	return parsed.Query().Get("token")
}
