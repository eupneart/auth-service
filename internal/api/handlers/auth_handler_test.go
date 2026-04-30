package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eupneart/auth-service/internal/models"
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
	handler := NewAuthHandler(userService, mockTokenService)

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
	handler := NewAuthHandler(userService, mockTokenService)

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
	handler := NewAuthHandler(userService, mockTokenService)

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
	handler := NewAuthHandler(userService, mockTokenService)

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
	handler := NewAuthHandler(userService, mockTokenService)

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
	handler := NewAuthHandler(userService, mockTokenService)

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
	handler := NewAuthHandler(userService, mockTokenService)

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
	handler := NewAuthHandler(userService, mockTokenService)

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
	handler := NewAuthHandler(userService, mockTokenService)

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
