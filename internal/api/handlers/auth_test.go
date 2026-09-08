package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/eupneart/auth-service/internal/api/middleware"
	"github.com/eupneart/auth-service/internal/models"
	"github.com/eupneart/auth-service/internal/repositories"
	"github.com/eupneart/auth-service/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// MockUserRepository mocks the UserRepoInterface
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) GetAll(ctx context.Context) ([]*models.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByID(ctx context.Context, id int64) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, u models.User) error {
	args := m.Called(ctx, u)
	return args.Error(0)
}

func (m *MockUserRepository) UpdatePassword(ctx context.Context, userID int64, hashedPassword string) error {
	args := m.Called(ctx, userID, hashedPassword)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteByID(ctx context.Context, id int64) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) Insert(ctx context.Context, u models.User) (int64, error) {
	args := m.Called(ctx, u)
	return args.Get(0).(int64), args.Error(1)
}

// MockTokenService mocks the TokenService interface
type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) GenerateTokens(ctx context.Context, user *models.User) (accessToken, refreshToken string, err error) {
	args := m.Called(ctx, user)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockTokenService) ValidateToken(ctx context.Context, tokenStr string) (*models.Claims, error) {
	args := m.Called(ctx, tokenStr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Claims), args.Error(1)
}

func (m *MockTokenService) RefreshAccessToken(ctx context.Context, refreshToken string) (string, error) {
	args := m.Called(ctx, refreshToken)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) RevokeToken(ctx context.Context, tokenStr string) error {
	args := m.Called(ctx, tokenStr)
	return args.Error(0)
}

func (m *MockTokenService) GetTokenMetadata(ctx context.Context, tokenID string) (*models.TokenMetadata, error) {
	args := m.Called(ctx, tokenID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TokenMetadata), args.Error(1)
}

func (m *MockTokenService) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	args := m.Called(ctx, tokenID)
	return args.Bool(0), args.Error(1)
}

func (m *MockTokenService) RevokeAllTokensForUser(ctx context.Context, userID int64) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockTokenService) CleanupExpiredTokens(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// Helper function to create request body
func createAuthRequest(email, password string) []byte {
	payload := map[string]string{
		"email":    email,
		"password": password,
	}
	body, _ := json.Marshal(payload)
	return body
}

// TestAuthHandler_Authenticate_InvalidEmailFormat tests authentication with invalid email format
func TestAuthHandler_Authenticate_InvalidEmailFormat(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.New(mockRepo)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(userService, mockTokenService, nil)

	testCases := []struct {
		name  string
		email string
	}{
		{"no at sign", "invalidemail"},
		{"no domain", "user@"},
		{"no local part", "@example.com"},
		{"whitespace only", "   "},
		{"special chars", "user@domain@example.com"},
		{"too short", "a@b"},
		{"no TLD", "user@domain"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/authenticate",
				bytes.NewReader(createAuthRequest(tc.email, "Password123!")))
			w := httptest.NewRecorder()

			handler.Authenticate(w, req)

			// Should return 400 Bad Request
			assert.Equal(t, http.StatusBadRequest, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)
			assert.True(t, response["error"].(bool))
			assert.Contains(t, response["message"].(string), "invalid email format")

			// Verify GetByEmail was NOT called (no database hit for invalid email)
			mockRepo.AssertNotCalled(t, "GetByEmail")
		})
	}
}

// TestAuthHandler_Authenticate_NilUser tests authentication when user is nil (not found)
func TestAuthHandler_Authenticate_NilUser(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.New(mockRepo)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(userService, mockTokenService, nil)

	// Mock GetByEmail returning nil (user not found)
	mockRepo.On("GetByEmail", mock.Anything, "notfound@example.com").Return(nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/authenticate",
		bytes.NewReader(createAuthRequest("notfound@example.com", "Password123!")))
	w := httptest.NewRecorder()

	handler.Authenticate(w, req)

	// Should return 401 Unauthorized
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response["error"].(bool))
	assert.Contains(t, response["message"].(string), "invalid credentials")

	// Verify GetByEmail was called
	mockRepo.AssertCalled(t, "GetByEmail", mock.Anything, "notfound@example.com")
}

// TestAuthHandler_Authenticate_ValidCredentials tests successful authentication
func TestAuthHandler_Authenticate_ValidCredentials(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.New(mockRepo)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(userService, mockTokenService, nil)

	// Create a test user with hashed password
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), 12)
	testUser := &models.User{
		ID:        1,
		Email:     "user@example.com",
		FirstName: "John",
		LastName:  "Doe",
		Password:  string(hashedPassword),
		Role:      "user",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Mock the service calls
	mockRepo.On("GetByEmail", mock.Anything, "user@example.com").Return(testUser, nil)
	mockRepo.On("Update", mock.Anything, mock.MatchedBy(func(u models.User) bool {
		return u.ID == testUser.ID && !u.LastLogin.IsZero()
	})).Return(nil)

	mockTokenService.On("GenerateTokens", mock.Anything, testUser).Return(
		"access_token_123",
		"refresh_token_456",
		nil,
	)

	req := httptest.NewRequest(http.MethodPost, "/authenticate",
		bytes.NewReader(createAuthRequest("user@example.com", "Password123!")))
	w := httptest.NewRecorder()

	handler.Authenticate(w, req)

	// Should return 200 OK
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.False(t, response["error"].(bool))
	assert.Contains(t, response["message"].(string), "Successfully authenticated")

	// Verify response contains tokens
	data := response["data"].(map[string]interface{})
	assert.Equal(t, "access_token_123", data["access_token"])
	assert.Equal(t, "refresh_token_456", data["refresh_token"])
	assert.Equal(t, "Bearer", data["token_type"])

	// Verify mocks were called
	mockRepo.AssertCalled(t, "GetByEmail", mock.Anything, "user@example.com")
	mockTokenService.AssertCalled(t, "GenerateTokens", mock.Anything, testUser)
}

// TestAuthHandler_Authenticate_MissingCredentials tests authentication with missing email/password
func TestAuthHandler_Authenticate_MissingCredentials(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.New(mockRepo)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(userService, mockTokenService, nil)

	testCases := []struct {
		name     string
		email    string
		password string
	}{
		{"missing email", "", "Password123!"},
		{"missing password", "user@example.com", ""},
		{"both missing", "", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/authenticate",
				bytes.NewReader(createAuthRequest(tc.email, tc.password)))
			w := httptest.NewRecorder()

			handler.Authenticate(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)
			assert.True(t, response["error"].(bool))
			assert.Contains(t, response["message"].(string), "required")

			// Verify database was not queried
			mockRepo.AssertNotCalled(t, "GetByEmail")
		})
	}
}

// TestAuthHandler_Authenticate_InactiveUser tests authentication for inactive users
func TestAuthHandler_Authenticate_InactiveUser(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.New(mockRepo)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(userService, mockTokenService, nil)

	inactiveUser := &models.User{
		ID:       2,
		Email:    "inactive@example.com",
		IsActive: false,
	}

	mockRepo.On("GetByEmail", mock.Anything, "inactive@example.com").Return(inactiveUser, nil)

	req := httptest.NewRequest(http.MethodPost, "/authenticate",
		bytes.NewReader(createAuthRequest("inactive@example.com", "Password123!")))
	w := httptest.NewRecorder()

	handler.Authenticate(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response["error"].(bool))
	assert.Contains(t, response["message"].(string), "deactivated")
}

// TestAuthHandler_Authenticate_InvalidPassword tests authentication with wrong password
func TestAuthHandler_Authenticate_InvalidPassword(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.New(mockRepo)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(userService, mockTokenService, nil)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("CorrectPassword123!"), 12)
	testUser := &models.User{
		ID:       3,
		Email:    "user@example.com",
		Password: string(hashedPassword),
		IsActive: true,
	}

	mockRepo.On("GetByEmail", mock.Anything, "user@example.com").Return(testUser, nil)

	req := httptest.NewRequest(http.MethodPost, "/authenticate",
		bytes.NewReader(createAuthRequest("user@example.com", "WrongPassword")))
	w := httptest.NewRecorder()

	handler.Authenticate(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response["error"].(bool))
	assert.Contains(t, response["message"].(string), "invalid credentials")

	// Verify tokens were NOT generated
	mockTokenService.AssertNotCalled(t, "GenerateTokens")
}

// TestAuthHandler_Authenticate_DatabaseError tests authentication when database query fails
func TestAuthHandler_Authenticate_DatabaseError(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.New(mockRepo)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(userService, mockTokenService, nil)

	mockRepo.On("GetByEmail", mock.Anything, "user@example.com").
		Return(nil, errors.New("database connection failed"))

	req := httptest.NewRequest(http.MethodPost, "/authenticate",
		bytes.NewReader(createAuthRequest("user@example.com", "Password123!")))
	w := httptest.NewRecorder()

	handler.Authenticate(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response["error"].(bool))
}

// TestAuthHandler_Authenticate_TokenGenerationError tests when token generation fails
func TestAuthHandler_Authenticate_TokenGenerationError(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.New(mockRepo)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(userService, mockTokenService, nil)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), 12)
	testUser := &models.User{
		ID:       4,
		Email:    "user@example.com",
		Password: string(hashedPassword),
		IsActive: true,
	}

	mockRepo.On("GetByEmail", mock.Anything, "user@example.com").Return(testUser, nil)
	mockTokenService.On("GenerateTokens", mock.Anything, testUser).
		Return("", "", errors.New("token generation failed"))

	req := httptest.NewRequest(http.MethodPost, "/authenticate",
		bytes.NewReader(createAuthRequest("user@example.com", "Password123!")))
	w := httptest.NewRecorder()

	handler.Authenticate(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response["error"].(bool))
	assert.Contains(t, response["message"].(string), "token")
}

// TestAuthHandler_Authenticate_LastLoginUpdateFailure tests that last login update failure doesn't break auth
func TestAuthHandler_Authenticate_LastLoginUpdateFailure(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := services.New(mockRepo)
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(userService, mockTokenService, nil)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), 12)
	testUser := &models.User{
		ID:       5,
		Email:    "user@example.com",
		Password: string(hashedPassword),
		IsActive: true,
	}

	mockRepo.On("GetByEmail", mock.Anything, "user@example.com").Return(testUser, nil)
	mockTokenService.On("GenerateTokens", mock.Anything, testUser).
		Return("access_token", "refresh_token", nil)
	// Simulate last login update failure
	mockRepo.On("Update", mock.Anything, mock.MatchedBy(func(u models.User) bool {
		return u.ID == testUser.ID && !u.LastLogin.IsZero()
	})).Return(errors.New("database error during update"))

	req := httptest.NewRequest(http.MethodPost, "/authenticate",
		bytes.NewReader(createAuthRequest("user@example.com", "Password123!")))
	w := httptest.NewRecorder()

	handler.Authenticate(w, req)

	// Should still return 200 OK (non-critical failure)
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.False(t, response["error"].(bool))
	assert.Contains(t, response["message"].(string), "authenticated")

	// Verify tokens were still generated
	mockTokenService.AssertCalled(t, "GenerateTokens", mock.Anything, testUser)
}

func TestAuthHandler_Refresh(t *testing.T) {
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(nil, mockTokenService, nil)
	mockTokenService.On("RefreshAccessToken", mock.Anything, "refresh-token").Return("new-access-token", nil)

	req := httptest.NewRequest(http.MethodPost, "/refresh",
		bytes.NewReader([]byte(`{"refresh_token":"refresh-token"}`)))
	w := httptest.NewRecorder()
	handler.Refresh(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"access_token": "new-access-token"`)
	mockTokenService.AssertExpectations(t)
}

func TestAuthHandler_ValidateInvalidTokenReturnsResult(t *testing.T) {
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(nil, mockTokenService, nil)
	mockTokenService.On("ValidateToken", mock.Anything, "bad-token").
		Return(nil, errors.New("token has been revoked"))

	req := httptest.NewRequest(http.MethodPost, "/validate",
		bytes.NewReader([]byte(`{"token":"bad-token"}`)))
	w := httptest.NewRecorder()
	handler.Validate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"valid": false`)
	mockTokenService.AssertExpectations(t)
}

func TestAuthHandler_Logout(t *testing.T) {
	mockTokenService := new(MockTokenService)
	handler := NewAuthHandler(nil, mockTokenService, nil)
	mockTokenService.On("ValidateToken", mock.Anything, "access-token").
		Return(&models.Claims{UserID: 42, TokenType: models.TokenTypeAccess}, nil)
	mockTokenService.On("RevokeToken", mock.Anything, "access-token").Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()
	middleware.Auth(mockTokenService)(http.HandlerFunc(handler.Logout)).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Successfully logged out")
	mockTokenService.AssertExpectations(t)
}

func TestAuthHandler_GetMeOmitsPassword(t *testing.T) {
	mockRepo := new(MockUserRepository)
	handler := NewAuthHandler(services.New(mockRepo), new(MockTokenService), nil)
	user := &models.User{
		ID:       42,
		Email:    "user@example.com",
		Password: "hashed-password",
		IsActive: true,
	}
	mockRepo.On("GetByID", mock.Anything, int64(42)).Return(user, nil)
	mockTokenService := new(MockTokenService)
	mockTokenService.On("ValidateToken", mock.Anything, "access-token").
		Return(&models.Claims{UserID: 42, TokenType: models.TokenTypeAccess}, nil)
	handler.TokenService = mockTokenService

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()
	middleware.Auth(mockTokenService)(http.HandlerFunc(handler.GetMe)).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"email": "user@example.com"`)
	assert.NotContains(t, w.Body.String(), "hashed-password")
	mockRepo.AssertExpectations(t)
}

func TestAuthHandler_RefreshErrors(t *testing.T) {
	testCases := []struct {
		name       string
		body       string
		serviceErr error
		status     int
	}{
		{"missing token", `{}`, nil, http.StatusBadRequest},
		{"malformed JSON", `{`, nil, http.StatusBadRequest},
		{"expired token", `{"refresh_token":"expired"}`, errors.New("token has expired"), http.StatusUnauthorized},
		{"revoked token", `{"refresh_token":"revoked"}`, errors.New("token has been revoked"), http.StatusUnauthorized},
		{"wrong token type", `{"refresh_token":"access-token"}`, errors.New("invalid token type"), http.StatusUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenService := new(MockTokenService)
			handler := NewAuthHandler(nil, tokenService, nil)
			if tc.serviceErr != nil {
				tokenService.On("RefreshAccessToken", mock.Anything, mock.AnythingOfType("string")).Return("", tc.serviceErr)
			}

			req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewBufferString(tc.body))
			w := httptest.NewRecorder()
			handler.Refresh(w, req)

			assert.Equal(t, tc.status, w.Code)
			if tc.serviceErr != nil {
				tokenService.AssertExpectations(t)
			}
		})
	}
}

func TestAuthHandler_ValidateValidToken(t *testing.T) {
	tokenService := new(MockTokenService)
	handler := NewAuthHandler(nil, tokenService, nil)
	tokenService.On("ValidateToken", mock.Anything, "valid-token").
		Return(&models.Claims{UserID: 1}, nil)

	req := httptest.NewRequest(http.MethodPost, "/validate",
		bytes.NewBufferString(`{"token":"valid-token"}`))
	w := httptest.NewRecorder()
	handler.Validate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"valid": true`)
	assert.Contains(t, w.Body.String(), `"user_id": 1`)
	tokenService.AssertExpectations(t)
}

func TestAuthHandler_ValidateInvalidTokenVariants(t *testing.T) {
	for _, token := range []string{"expired", "revoked"} {
		t.Run(token, func(t *testing.T) {
			tokenService := new(MockTokenService)
			handler := NewAuthHandler(nil, tokenService, nil)
			tokenService.On("ValidateToken", mock.Anything, token).
				Return(nil, errors.New("token is invalid"))

			req := httptest.NewRequest(http.MethodPost, "/validate",
				bytes.NewBufferString(`{"token":"`+token+`"}`))
			w := httptest.NewRecorder()
			handler.Validate(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), `"valid": false`)
			tokenService.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_LogoutRevocationFailure(t *testing.T) {
	tokenService := new(MockTokenService)
	handler := NewAuthHandler(nil, tokenService, nil)
	tokenService.On("ValidateToken", mock.Anything, "access-token").
		Return(&models.Claims{UserID: 1, TokenType: models.TokenTypeAccess}, nil)
	tokenService.On("RevokeToken", mock.Anything, "access-token").
		Return(errors.New("database unavailable"))

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()
	middleware.Auth(tokenService)(http.HandlerFunc(handler.Logout)).ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	tokenService.AssertExpectations(t)
}

func TestAuthHandler_GetMeInactiveUser(t *testing.T) {
	repo := new(MockUserRepository)
	handler := NewAuthHandler(services.New(repo), new(MockTokenService), nil)
	repo.On("GetByID", mock.Anything, int64(42)).
		Return(&models.User{ID: 42, IsActive: false}, nil)
	tokenService := new(MockTokenService)
	tokenService.On("ValidateToken", mock.Anything, "access-token").
		Return(&models.Claims{UserID: 42, TokenType: models.TokenTypeAccess}, nil)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()
	middleware.Auth(tokenService)(http.HandlerFunc(handler.GetMe)).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "inactive")
	repo.AssertExpectations(t)
}

func TestAuthHandler_GetMeMissingUser(t *testing.T) {
	repo := new(MockUserRepository)
	handler := NewAuthHandler(services.New(repo), new(MockTokenService), nil)
	repo.On("GetByID", mock.Anything, int64(42)).Return(nil, nil)
	tokenService := new(MockTokenService)
	tokenService.On("ValidateToken", mock.Anything, "access-token").
		Return(&models.Claims{UserID: 42, TokenType: models.TokenTypeAccess}, nil)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()
	middleware.Auth(tokenService)(http.HandlerFunc(handler.GetMe)).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------- ChangePassword

// fakeResetTokenStore records created tokens and returns a configurable result
// from Consume, so both the happy path and the unusable-token path are testable.
type fakeResetTokenStore struct {
	mu         sync.Mutex
	created    []*models.PasswordResetToken
	consumed   *models.PasswordResetToken
	consumeErr error
}

func (f *fakeResetTokenStore) CreatePasswordResetToken(_ context.Context, token *models.PasswordResetToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, token)
	return nil
}

func (f *fakeResetTokenStore) ConsumePasswordResetToken(context.Context, string) (*models.PasswordResetToken, error) {
	if f.consumeErr != nil {
		return nil, f.consumeErr
	}
	return f.consumed, nil
}

func (f *fakeResetTokenStore) InvalidatePasswordResetTokensForUser(context.Context, int64) error {
	return nil
}

func (f *fakeResetTokenStore) createdCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.created)
}

// fakeResetMailer is written to from the detached goroutine ForgotPassword
// starts, so every field is guarded.
type fakeResetMailer struct {
	mu        sync.Mutex
	recipient string
	resetURL  string
	sends     int
}

func (f *fakeResetMailer) SendPasswordReset(_ context.Context, recipient, resetURL string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recipient = recipient
	f.resetURL = resetURL
	f.sends++
	return nil
}

func (f *fakeResetMailer) snapshot() (recipient, resetURL string, sends int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.recipient, f.resetURL, f.sends
}

// newChangePasswordHandler builds a handler over a real PasswordResetService so
// the orchestration runs; only the repositories and mailer are stubbed.
func newPasswordHandler(repo *MockUserRepository, tokenService *MockTokenService, tokens *fakeResetTokenStore, mailer *fakeResetMailer) *AuthHandler {
	userService := services.New(repo)
	resetService := services.NewPasswordResetService(
		services.PasswordResetConfig{
			BaseURL:       "https://example.com/reset-password",
			TokenLifetime: 15 * time.Minute,
		},
		userService,
		repo,
		tokens,
		tokenService,
		mailer,
	)
	return NewAuthHandler(userService, tokenService, resetService)
}

func newChangePasswordHandler(repo *MockUserRepository, tokenService *MockTokenService) *AuthHandler {
	return newPasswordHandler(repo, tokenService,
		&fakeResetTokenStore{consumeErr: repositories.ErrResetTokenNotFound},
		&fakeResetMailer{})
}

func changePasswordRequest(t *testing.T, handler *AuthHandler, tokenService *MockTokenService, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/password/change", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()
	middleware.Auth(tokenService)(http.HandlerFunc(handler.ChangePassword)).ServeHTTP(w, req)
	return w
}

func userWithPassword(t *testing.T, plain string) *models.User {
	t.Helper()

	hashed, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.MinCost)
	require.NoError(t, err)
	return &models.User{ID: 42, Email: "user@example.com", Password: string(hashed), IsActive: true}
}

func TestAuthHandler_ChangePasswordSuccess(t *testing.T) {
	repo := new(MockUserRepository)
	tokenService := new(MockTokenService)
	tokenService.On("ValidateToken", mock.Anything, "access-token").
		Return(&models.Claims{UserID: 42, TokenType: models.TokenTypeAccess}, nil)
	repo.On("GetByID", mock.Anything, int64(42)).Return(userWithPassword(t, "OldPassw0rd!"), nil)
	tokenService.On("RevokeAllTokensForUser", mock.Anything, int64(42)).Return(nil)
	repo.On("UpdatePassword", mock.Anything, int64(42), mock.Anything).Return(nil)

	handler := newChangePasswordHandler(repo, tokenService)
	w := changePasswordRequest(t, handler, tokenService,
		`{"current_password":"OldPassw0rd!","new_password":"NewPassw0rd!"}`)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), "NewPassw0rd!")
	repo.AssertExpectations(t)
	tokenService.AssertExpectations(t)
}

func TestAuthHandler_ChangePasswordWrongCurrentPassword(t *testing.T) {
	repo := new(MockUserRepository)
	tokenService := new(MockTokenService)
	tokenService.On("ValidateToken", mock.Anything, "access-token").
		Return(&models.Claims{UserID: 42, TokenType: models.TokenTypeAccess}, nil)
	repo.On("GetByID", mock.Anything, int64(42)).Return(userWithPassword(t, "OldPassw0rd!"), nil)

	handler := newChangePasswordHandler(repo, tokenService)
	w := changePasswordRequest(t, handler, tokenService,
		`{"current_password":"WrongPassw0rd!","new_password":"NewPassw0rd!"}`)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	// Neither the password nor the sessions may be touched on a failed attempt.
	repo.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
	tokenService.AssertNotCalled(t, "RevokeAllTokensForUser", mock.Anything, mock.Anything)
}

func TestAuthHandler_ChangePasswordRejectsWeakNewPassword(t *testing.T) {
	repo := new(MockUserRepository)
	tokenService := new(MockTokenService)
	tokenService.On("ValidateToken", mock.Anything, "access-token").
		Return(&models.Claims{UserID: 42, TokenType: models.TokenTypeAccess}, nil)

	handler := newChangePasswordHandler(repo, tokenService)
	w := changePasswordRequest(t, handler, tokenService,
		`{"current_password":"OldPassw0rd!","new_password":"weak"}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	repo.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
}

func TestAuthHandler_ChangePasswordMissingFields(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{"missing current password", `{"new_password":"NewPassw0rd!"}`},
		{"missing new password", `{"current_password":"OldPassw0rd!"}`},
		{"empty body", `{}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := new(MockUserRepository)
			tokenService := new(MockTokenService)
			tokenService.On("ValidateToken", mock.Anything, "access-token").
				Return(&models.Claims{UserID: 42, TokenType: models.TokenTypeAccess}, nil)

			handler := newChangePasswordHandler(repo, tokenService)
			w := changePasswordRequest(t, handler, tokenService, tc.body)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			repo.AssertNotCalled(t, "GetByID", mock.Anything, mock.Anything)
		})
	}
}

func TestAuthHandler_ChangePasswordRequiresAuthentication(t *testing.T) {
	repo := new(MockUserRepository)
	tokenService := new(MockTokenService)
	handler := newChangePasswordHandler(repo, tokenService)

	req := httptest.NewRequest(http.MethodPost, "/password/change",
		bytes.NewBufferString(`{"current_password":"OldPassw0rd!","new_password":"NewPassw0rd!"}`))
	w := httptest.NewRecorder()
	middleware.Auth(tokenService)(http.HandlerFunc(handler.ChangePassword)).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	repo.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
}

// ------------------------------------------------- ForgotPassword / ResetPassword

func forgotPasswordRequest(handler *AuthHandler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/password/forgot", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	handler.ForgotPassword(w, req)
	return w
}

func resetPasswordRequest(handler *AuthHandler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/password/reset", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	handler.ResetPassword(w, req)
	return w
}

// Unknown, inactive and active addresses must be indistinguishable in status
// code and body.
func TestAuthHandler_ForgotPasswordResponseIsUniform(t *testing.T) {
	testCases := []struct {
		name string
		user *models.User
	}{
		{"unknown account", nil},
		{"inactive account", &models.User{ID: 42, Email: "user@example.com", IsActive: false}},
		{"active account", &models.User{ID: 42, Email: "user@example.com", IsActive: true}},
	}

	var bodies []string
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := new(MockUserRepository)
			repo.On("GetByEmail", mock.Anything, "user@example.com").Return(tc.user, nil)
			handler := newPasswordHandler(repo, new(MockTokenService), &fakeResetTokenStore{}, &fakeResetMailer{})

			w := forgotPasswordRequest(handler, `{"email":"user@example.com"}`)

			assert.Equal(t, http.StatusAccepted, w.Code)
			assert.Contains(t, w.Body.String(), forgotPasswordMessage)
			bodies = append(bodies, w.Body.String())
		})
	}

	for _, body := range bodies {
		assert.Equal(t, bodies[0], body, "responses must not vary with account state")
	}
}

func TestAuthHandler_ForgotPasswordSendsLinkOnlyForActiveAccount(t *testing.T) {
	testCases := []struct {
		name      string
		user      *models.User
		wantSends int
	}{
		{"active account receives a link", &models.User{ID: 42, Email: "user@example.com", IsActive: true}, 1},
		{"inactive account receives nothing", &models.User{ID: 42, Email: "user@example.com", IsActive: false}, 0},
		{"unknown account receives nothing", nil, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := new(MockUserRepository)
			repo.On("GetByEmail", mock.Anything, "user@example.com").Return(tc.user, nil)
			tokens := &fakeResetTokenStore{}
			mailer := &fakeResetMailer{}
			handler := newPasswordHandler(repo, new(MockTokenService), tokens, mailer)

			require.Equal(t, http.StatusAccepted,
				forgotPasswordRequest(handler, `{"email":"user@example.com"}`).Code)

			// The work runs on a goroutine the handler does not wait for.
			assert.Eventually(t, func() bool {
				_, _, sends := mailer.snapshot()
				return sends == tc.wantSends && tokens.createdCount() == tc.wantSends
			}, time.Second, 10*time.Millisecond)

			if tc.wantSends > 0 {
				recipient, resetURL, _ := mailer.snapshot()
				assert.Equal(t, "user@example.com", recipient)
				assert.Contains(t, resetURL, "https://example.com/reset-password?token=")
			}
		})
	}
}

func TestAuthHandler_ForgotPasswordRejectsInvalidEmail(t *testing.T) {
	repo := new(MockUserRepository)
	handler := newPasswordHandler(repo, new(MockTokenService), &fakeResetTokenStore{}, &fakeResetMailer{})

	w := forgotPasswordRequest(handler, `{"email":"not-an-email"}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	repo.AssertNotCalled(t, "GetByEmail", mock.Anything, mock.Anything)
}

// Repeated requests for one address stop producing mail, while the response
// stays identical.
func TestAuthHandler_ForgotPasswordThrottlesPerEmail(t *testing.T) {
	repo := new(MockUserRepository)
	repo.On("GetByEmail", mock.Anything, "user@example.com").
		Return(&models.User{ID: 42, Email: "user@example.com", IsActive: true}, nil)
	tokens := &fakeResetTokenStore{}
	mailer := &fakeResetMailer{}
	handler := newPasswordHandler(repo, new(MockTokenService), tokens, mailer)

	const attempts = 8
	for range attempts {
		assert.Equal(t, http.StatusAccepted,
			forgotPasswordRequest(handler, `{"email":"user@example.com"}`).Code)
	}

	assert.Eventually(t, func() bool {
		_, _, sends := mailer.snapshot()
		return sends > 0 && sends < attempts
	}, time.Second, 10*time.Millisecond)
}

func TestAuthHandler_ResetPasswordSuccess(t *testing.T) {
	repo := new(MockUserRepository)
	tokenService := new(MockTokenService)
	tokenService.On("RevokeAllTokensForUser", mock.Anything, int64(42)).Return(nil)
	repo.On("UpdatePassword", mock.Anything, int64(42), mock.Anything).Return(nil)

	tokens := &fakeResetTokenStore{consumed: &models.PasswordResetToken{ID: 1, UserID: 42}}
	handler := newPasswordHandler(repo, tokenService, tokens, &fakeResetMailer{})

	w := resetPasswordRequest(handler, `{"token":"raw-token","new_password":"NewPassw0rd!"}`)

	assert.Equal(t, http.StatusOK, w.Code)
	// Recovery must not hand back a session; the user signs in again.
	assert.NotContains(t, w.Body.String(), "access_token")
	assert.NotContains(t, w.Body.String(), "NewPassw0rd!")
	repo.AssertExpectations(t)
	tokenService.AssertExpectations(t)
}

func TestAuthHandler_ResetPasswordRejectsUnusableToken(t *testing.T) {
	repo := new(MockUserRepository)
	tokenService := new(MockTokenService)
	tokens := &fakeResetTokenStore{consumeErr: repositories.ErrResetTokenNotFound}
	handler := newPasswordHandler(repo, tokenService, tokens, &fakeResetMailer{})

	w := resetPasswordRequest(handler, `{"token":"raw-token","new_password":"NewPassw0rd!"}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid or expired reset token")
	repo.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
	tokenService.AssertNotCalled(t, "RevokeAllTokensForUser", mock.Anything, mock.Anything)
}

func TestAuthHandler_ResetPasswordRejectsWeakPassword(t *testing.T) {
	repo := new(MockUserRepository)
	tokens := &fakeResetTokenStore{consumed: &models.PasswordResetToken{ID: 1, UserID: 42}}
	handler := newPasswordHandler(repo, new(MockTokenService), tokens, &fakeResetMailer{})

	w := resetPasswordRequest(handler, `{"token":"raw-token","new_password":"weak"}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	repo.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
}

func TestAuthHandler_ResetPasswordMissingFields(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{"missing token", `{"new_password":"NewPassw0rd!"}`},
		{"missing password", `{"token":"raw-token"}`},
		{"empty body", `{}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := new(MockUserRepository)
			handler := newPasswordHandler(repo, new(MockTokenService), &fakeResetTokenStore{}, &fakeResetMailer{})

			w := resetPasswordRequest(handler, tc.body)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			repo.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// ---------------------------------------------------------------- Register

const validRegistration = `{"first_name":"John","last_name":"Doe","email":"user@example.com","password":"NewPassw0rd!"}`

func newRegisterHandler(repo *MockUserRepository, tokenService *MockTokenService) *AuthHandler {
	return NewAuthHandler(services.New(repo), tokenService, nil)
}

func registerRequest(handler *AuthHandler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	handler.Register(w, req)
	return w
}

func TestAuthHandler_RegisterMalformedJSON(t *testing.T) {
	handler := newRegisterHandler(new(MockUserRepository), new(MockTokenService))

	w := registerRequest(handler, `{"email":`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_RegisterRejectsInvalidInput(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{"missing first name", `{"first_name":"","last_name":"Doe","email":"user@example.com","password":"NewPassw0rd!"}`},
		{"missing last name", `{"first_name":"John","last_name":"","email":"user@example.com","password":"NewPassw0rd!"}`},
		{"missing email", `{"first_name":"John","last_name":"Doe","email":"","password":"NewPassw0rd!"}`},
		{"missing password", `{"first_name":"John","last_name":"Doe","email":"user@example.com","password":""}`},
		{"invalid email", `{"first_name":"John","last_name":"Doe","email":"not-an-email","password":"NewPassw0rd!"}`},
		{"weak password", `{"first_name":"John","last_name":"Doe","email":"user@example.com","password":"password"}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := new(MockUserRepository)
			handler := newRegisterHandler(repo, new(MockTokenService))

			w := registerRequest(handler, tc.body)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			repo.AssertNotCalled(t, "Insert", mock.Anything, mock.Anything)
		})
	}
}

func TestAuthHandler_RegisterRejectsExistingEmail(t *testing.T) {
	repo := new(MockUserRepository)
	repo.On("GetByEmail", mock.Anything, "user@example.com").
		Return(&models.User{ID: 7, Email: "user@example.com"}, nil)
	handler := newRegisterHandler(repo, new(MockTokenService))

	w := registerRequest(handler, validRegistration)

	assert.Equal(t, http.StatusConflict, w.Code)
	repo.AssertNotCalled(t, "Insert", mock.Anything, mock.Anything)
}

func TestAuthHandler_RegisterInsertFailure(t *testing.T) {
	repo := new(MockUserRepository)
	repo.On("GetByEmail", mock.Anything, "user@example.com").Return(nil, nil)
	repo.On("Insert", mock.Anything, mock.AnythingOfType("models.User")).
		Return(int64(0), assert.AnError)
	handler := newRegisterHandler(repo, new(MockTokenService))

	w := registerRequest(handler, validRegistration)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	// The repository error must not reach the client.
	assert.Contains(t, w.Body.String(), "failed to create user account")
	assert.NotContains(t, w.Body.String(), assert.AnError.Error())
}

func TestAuthHandler_RegisterLookupFailureAfterInsert(t *testing.T) {
	repo := new(MockUserRepository)
	repo.On("GetByEmail", mock.Anything, "user@example.com").Return(nil, nil)
	repo.On("Insert", mock.Anything, mock.AnythingOfType("models.User")).Return(int64(7), nil)
	repo.On("GetByID", mock.Anything, int64(7)).Return(nil, assert.AnError)
	handler := newRegisterHandler(repo, new(MockTokenService))

	w := registerRequest(handler, validRegistration)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to complete user registration")
}

func TestAuthHandler_RegisterMissingUserAfterInsert(t *testing.T) {
	repo := new(MockUserRepository)
	repo.On("GetByEmail", mock.Anything, "user@example.com").Return(nil, nil)
	repo.On("Insert", mock.Anything, mock.AnythingOfType("models.User")).Return(int64(7), nil)
	repo.On("GetByID", mock.Anything, int64(7)).Return(nil, nil)
	handler := newRegisterHandler(repo, new(MockTokenService))

	w := registerRequest(handler, validRegistration)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to complete user registration")
}

// Token generation is auto-login, not part of registration. If it fails the
// account still exists, so the request succeeds and the client is told to log
// in rather than being handed a half-built session.
func TestAuthHandler_RegisterSucceedsWithoutAutoLogin(t *testing.T) {
	repo := new(MockUserRepository)
	repo.On("GetByEmail", mock.Anything, "user@example.com").Return(nil, nil)
	repo.On("Insert", mock.Anything, mock.AnythingOfType("models.User")).Return(int64(7), nil)
	repo.On("GetByID", mock.Anything, int64(7)).
		Return(&models.User{ID: 7, Email: "user@example.com"}, nil)

	tokenService := new(MockTokenService)
	tokenService.On("GenerateTokens", mock.Anything, mock.Anything).
		Return("", "", assert.AnError)

	w := registerRequest(newRegisterHandler(repo, tokenService), validRegistration)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "Please log in")
	assert.Contains(t, w.Body.String(), "user_id")
	assert.NotContains(t, w.Body.String(), "access_token")
	tokenService.AssertExpectations(t)
}

func TestAuthHandler_RegisterSuccess(t *testing.T) {
	repo := new(MockUserRepository)
	repo.On("GetByEmail", mock.Anything, "user@example.com").Return(nil, nil)
	repo.On("Insert", mock.Anything, mock.AnythingOfType("models.User")).Return(int64(7), nil)
	repo.On("GetByID", mock.Anything, int64(7)).
		Return(&models.User{ID: 7, Email: "user@example.com"}, nil)

	tokenService := new(MockTokenService)
	tokenService.On("GenerateTokens", mock.Anything, mock.Anything).
		Return("access-token", "refresh-token", nil)

	w := registerRequest(newRegisterHandler(repo, tokenService), validRegistration)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "access-token")
	assert.Contains(t, w.Body.String(), "refresh-token")
	assert.NotContains(t, w.Body.String(), "NewPassw0rd!")
	repo.AssertExpectations(t)
	tokenService.AssertExpectations(t)
}

// The password must never be persisted in the clear.
func TestAuthHandler_RegisterHashesPasswordBeforeInsert(t *testing.T) {
	repo := new(MockUserRepository)
	repo.On("GetByEmail", mock.Anything, "user@example.com").Return(nil, nil)
	repo.On("Insert", mock.Anything, mock.AnythingOfType("models.User")).
		Run(func(args mock.Arguments) {
			stored := args.Get(1).(models.User)
			assert.NotEqual(t, "NewPassw0rd!", stored.Password)
			assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored.Password), []byte("NewPassw0rd!")))
		}).
		Return(int64(7), nil)
	repo.On("GetByID", mock.Anything, int64(7)).
		Return(&models.User{ID: 7, Email: "user@example.com"}, nil)

	tokenService := new(MockTokenService)
	tokenService.On("GenerateTokens", mock.Anything, mock.Anything).
		Return("access-token", "refresh-token", nil)

	w := registerRequest(newRegisterHandler(repo, tokenService), validRegistration)

	assert.Equal(t, http.StatusCreated, w.Code)
	repo.AssertExpectations(t)
}
