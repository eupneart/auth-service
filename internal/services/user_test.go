package services

import (
	"context"
	"testing"

	"github.com/eupneart/auth-service/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestUserService_GetAll(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := New(mockRepo)

	ctx := context.Background()
	expectedUsers := []*models.User{
		{ID: int64(1), Email: "test1@example.com"},
		{ID: int64(2), Email: "test2@example.com"},
	}

	mockRepo.On("GetAll", mock.Anything).Return(expectedUsers, nil)

	users, err := service.GetAll(ctx)

	assert.NoError(t, err)
	assert.Equal(t, expectedUsers, users)
	mockRepo.AssertCalled(t, "GetAll", mock.Anything)
}

func TestUserService_GetByID(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := New(mockRepo)

	ctx := context.Background()

	// Test with valid ID
	expectedUser := &models.User{ID: int64(1), Email: "test@example.com"}
	mockRepo.On("GetByID", mock.Anything, int64(1)).Return(expectedUser, nil)

	user, err := service.GetByID(ctx, 1)
	assert.NoError(t, err)
	assert.Equal(t, expectedUser, user)
	mockRepo.AssertCalled(t, "GetByID", mock.Anything, int64(1))

	// Test with invalid ID (zero value)
	_, err = service.GetByID(ctx, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user ID must be provided")
}

func TestUserService_GetByEmail(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := New(mockRepo)

	ctx := context.Background()

	// Test with valid email
	expectedUser := &models.User{Email: "test@example.com"}
	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(expectedUser, nil)

	user, err := service.GetByEmail(ctx, "test@example.com")
	assert.NoError(t, err)
	assert.Equal(t, expectedUser, user)
	mockRepo.AssertCalled(t, "GetByEmail", mock.Anything, "test@example.com")

	// Test with empty email
	_, err = service.GetByEmail(ctx, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user email must be provided")
}

func TestUserService_Update(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := New(mockRepo)

	ctx := context.Background()

	// Test with valid user
	userToUpdate := models.User{ID: 1, Email: "updated@example.com"}
	mockRepo.On("Update", mock.Anything, userToUpdate).Return(nil)

	err := service.Update(ctx, userToUpdate)
	assert.NoError(t, err)
	mockRepo.AssertCalled(t, "Update", mock.Anything, userToUpdate)

	// Test with invalid user (zero ID)
	invalidUser := models.User{Email: "no-id@example.com"}
	err = service.Update(ctx, invalidUser)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user ID must be provided")
}

func TestUserService_DeleteByID(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := New(mockRepo)

	ctx := context.Background()

	// Test with valid ID
	mockRepo.On("DeleteByID", mock.Anything, int64(1)).Return(nil)
	err := service.DeleteByID(ctx, 1)
	assert.NoError(t, err)
	mockRepo.AssertCalled(t, "DeleteByID", mock.Anything, int64(1))

	// Test with invalid ID
	err = service.DeleteByID(ctx, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user ID must be provided")
}

func TestUserService_Insert(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := New(mockRepo)

	ctx := context.Background()

	// Test user insertion
	newUser := models.User{Email: "new@example.com", Password: "testpassword"}
	expectedID := int64(1)

	mockRepo.On("Insert", mock.Anything, mock.AnythingOfType("models.User")).
		Return(expectedID, nil).
		Run(func(args mock.Arguments) {
			// Verify the password is hashed
			insertedUser := args.Get(1).(models.User)
			assert.NotEqual(t, newUser.Password, insertedUser.Password, "Password should be hashed")
			// Verify bcrypt hash is valid
			err := bcrypt.CompareHashAndPassword([]byte(insertedUser.Password), []byte(newUser.Password))
			assert.NoError(t, err, "Bcrypt hash should be valid")
		})

	id, err := service.Insert(ctx, newUser)
	assert.NoError(t, err)
	assert.Equal(t, expectedID, id)
	mockRepo.AssertCalled(t, "Insert", mock.Anything, mock.AnythingOfType("models.User"))
}

func TestUserService_ResetPassword(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := New(mockRepo)

	ctx := context.Background()

	// Test password reset. Password must satisfy utils.IsValidPassword.
	plainPassword := "NewPassw0rd!"
	user := &models.User{ID: 1, Password: plainPassword}

	mockRepo.On("UpdatePassword", mock.Anything, int64(1), mock.AnythingOfType("string")).
		Return(nil).
		Run(func(args mock.Arguments) {
			hashed := args.Get(2).(string)

			assert.NotEqual(t, plainPassword, hashed, "Password should be hashed")

			// Verify bcrypt hash is valid
			err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plainPassword))
			assert.NoError(t, err, "Bcrypt hash should be valid")
		})

	err := service.ResetPassword(ctx, user)
	assert.NoError(t, err)
	mockRepo.AssertCalled(t, "UpdatePassword", mock.Anything, int64(1), mock.AnythingOfType("string"))
	mockRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
}

func TestUserService_ResetPassword_EmptyPassword(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := New(mockRepo)

	ctx := context.Background()
	user := &models.User{ID: 1, Password: ""}

	err := service.ResetPassword(ctx, user)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password cannot be empty")
	mockRepo.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
}

func TestUserService_ResetPassword_WeakPassword(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := New(mockRepo)

	ctx := context.Background()
	// Non-empty but fails strength requirements (no upper/digit/special).
	user := &models.User{ID: 1, Password: "weakpassword"}

	err := service.ResetPassword(ctx, user)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "strength requirements")
	mockRepo.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
}

func TestUserService_ResetPassword_ZeroID(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := New(mockRepo)

	ctx := context.Background()
	user := &models.User{ID: 0, Password: "NewPassw0rd!"}

	err := service.ResetPassword(ctx, user)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user ID must be provided")
	mockRepo.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
}

func TestUserService_PasswordMatches(t *testing.T) {
	service := New(nil) // No repo needed for this test

	// Generate a bcrypt hash of a known password
	plainTextPassword := "testpassword"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(plainTextPassword), 12)

	// Test cases
	testCases := []struct {
		name           string
		inputPassword  string
		storedPassword string
		expectedMatch  bool
		expectError    bool
	}{
		{
			name:           "Matching Password",
			inputPassword:  plainTextPassword,
			storedPassword: string(hashedPassword),
			expectedMatch:  true,
			expectError:    false,
		},
		{
			name:           "Non-Matching Password",
			inputPassword:  "wrongpassword",
			storedPassword: string(hashedPassword),
			expectedMatch:  false,
			expectError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := &models.User{
				ID:       1,
				Password: tc.storedPassword,
			}

			match, err := service.PasswordMatches(user, tc.inputPassword)

			assert.Equal(t, tc.expectedMatch, match)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Repository error paths
// ----------------------------------------------------------------------------

// bcryptMaxInputPassword is longer than bcrypt's 72-byte input limit but still
// within the 128 characters IsValidPassword accepts, so it reaches the hash call
// and fails there.
const bcryptMaxInputPassword = "Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!"

func TestUserService_GetAll_RepoError(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockRepo.On("GetAll", mock.Anything).Return(([]*models.User)(nil), assert.AnError)

	users, err := New(mockRepo).GetAll(context.Background())

	assert.Error(t, err)
	assert.Nil(t, users)
}

func TestUserService_GetByID_RepoError(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockRepo.On("GetByID", mock.Anything, int64(42)).Return((*models.User)(nil), assert.AnError)

	user, err := New(mockRepo).GetByID(context.Background(), 42)

	assert.Error(t, err)
	assert.Nil(t, user)
}

// A repository that reports no error but no user must not be turned into a
// non-nil user by the service.
func TestUserService_GetByID_NilUser(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockRepo.On("GetByID", mock.Anything, int64(42)).Return((*models.User)(nil), nil)

	user, err := New(mockRepo).GetByID(context.Background(), 42)

	assert.NoError(t, err)
	assert.Nil(t, user)
}

func TestUserService_GetByEmail_RepoError(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockRepo.On("GetByEmail", mock.Anything, "user@example.com").
		Return((*models.User)(nil), assert.AnError)

	user, err := New(mockRepo).GetByEmail(context.Background(), "user@example.com")

	assert.Error(t, err)
	assert.Nil(t, user)
}

func TestUserService_Update_RepoError(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockRepo.On("Update", mock.Anything, mock.AnythingOfType("models.User")).Return(assert.AnError)

	err := New(mockRepo).Update(context.Background(), models.User{
		ID: 42, Email: "user@example.com", FirstName: "John", LastName: "Doe",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update user")
}

func TestUserService_DeleteByID_RepoError(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockRepo.On("DeleteByID", mock.Anything, int64(42)).Return(assert.AnError)

	assert.Error(t, New(mockRepo).DeleteByID(context.Background(), 42))
}

func TestUserService_Insert_RepoError(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockRepo.On("Insert", mock.Anything, mock.AnythingOfType("models.User")).
		Return(int64(0), assert.AnError)

	id, err := New(mockRepo).Insert(context.Background(), models.User{
		Email: "user@example.com", Password: "NewPassw0rd!",
	})

	assert.Error(t, err)
	assert.Zero(t, id)
}

func TestUserService_Insert_PasswordTooLongToHash(t *testing.T) {
	mockRepo := new(MockUserRepo)

	id, err := New(mockRepo).Insert(context.Background(), models.User{
		Email: "user@example.com", Password: bcryptMaxInputPassword,
	})

	assert.Error(t, err)
	assert.Zero(t, id)
	assert.Contains(t, err.Error(), "encrypting password")
	mockRepo.AssertNotCalled(t, "Insert", mock.Anything, mock.Anything)
}

func TestUserService_ResetPassword_NilUser(t *testing.T) {
	err := New(new(MockUserRepo)).ResetPassword(context.Background(), nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user cannot be nil")
}

func TestUserService_ResetPassword_RepoError(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockRepo.On("UpdatePassword", mock.Anything, int64(42), mock.Anything).Return(assert.AnError)

	err := New(mockRepo).ResetPassword(context.Background(), &models.User{
		ID: 42, Password: "NewPassw0rd!",
	})

	assert.Error(t, err)
}

func TestUserService_ResetPassword_PasswordTooLongToHash(t *testing.T) {
	mockRepo := new(MockUserRepo)

	err := New(mockRepo).ResetPassword(context.Background(), &models.User{
		ID: 42, Password: bcryptMaxInputPassword,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to hash password")
	mockRepo.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
}

// A stored value that is not a bcrypt hash is an error, not a mismatch: it must
// not be reported as a plain wrong password.
func TestUserService_PasswordMatches_MalformedHash(t *testing.T) {
	matches, err := New(new(MockUserRepo)).PasswordMatches(
		&models.User{ID: 42, Password: "not-a-bcrypt-hash"}, "NewPassw0rd!")

	assert.Error(t, err)
	assert.False(t, matches)
}

// MockUserRepo is a mock implementation of the UserRepoInterface
type MockUserRepo struct {
	mock.Mock
}

func (m *MockUserRepo) GetAll(ctx context.Context) ([]*models.User, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockUserRepo) GetByID(ctx context.Context, id int64) (*models.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepo) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepo) Update(ctx context.Context, user models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepo) UpdatePassword(ctx context.Context, userID int64, hashedPassword string) error {
	args := m.Called(ctx, userID, hashedPassword)
	return args.Error(0)
}

func (m *MockUserRepo) DeleteByID(ctx context.Context, id int64) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepo) Insert(ctx context.Context, user models.User) (int64, error) {
	args := m.Called(ctx, user)
	return args.Get(0).(int64), args.Error(1)
}
