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
		{ID: 1, Email: "test1@example.com"},
		{ID: 2, Email: "test2@example.com"},
	}

	mockRepo.On("GetAll", mock.Anything).Return(expectedUsers, nil)

	users, err := service.GetAll(ctx)

	assert.NoError(t, err)
	assert.Equal(t, expectedUsers, users)
	mockRepo.AssertCalled(t, "GetAll", mock.Anything)
}

func TestUserService_GetById(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := New(mockRepo)

	ctx := context.Background()

	// Test with valid ID
	expectedUser := &models.User{ID: 1, Email: "test@example.com"}
	mockRepo.On("GetById", mock.Anything, 1).Return(expectedUser, nil)

	user, err := service.GetById(ctx, 1)
	assert.NoError(t, err)
	assert.Equal(t, expectedUser, user)
	mockRepo.AssertCalled(t, "GetById", mock.Anything, 1)

	// Test with invalid ID (zero value)
	_, err = service.GetById(ctx, 0)
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
	mockRepo.On("DeleteByID", mock.Anything, 1).Return(nil)
	err := service.DeleteByID(ctx, 1)
	assert.NoError(t, err)
	mockRepo.AssertCalled(t, "DeleteByID", mock.Anything, 1)

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
	expectedID := 1

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

	// Test password reset
	user := &models.User{ID: 1, Password: "newpassword"}

	mockRepo.On("Update", mock.Anything, mock.AnythingOfType("models.User")).
		Return(nil).
		Run(func(args mock.Arguments) {
			// Verify the password is hashed
			updatedUser := args.Get(1).(models.User)

			assert.NotEqual(t, user.Password, updatedUser.Password, "Password should be hashed")

			// Verify bcrypt hash is valid
			err := bcrypt.CompareHashAndPassword([]byte(updatedUser.Password), []byte(user.Password))
			assert.NoError(t, err, "Bcrypt hash should be valid")
		})

	err := service.ResetPassword(ctx, user)
	assert.NoError(t, err)
	mockRepo.AssertCalled(t, "Update", mock.Anything, mock.AnythingOfType("models.User"))
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

// MockUserRepo is a mock implementation of the UserRepoInterface
type MockUserRepo struct {
	mock.Mock
}

func (m *MockUserRepo) GetAll(ctx context.Context) ([]*models.User, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockUserRepo) GetById(ctx context.Context, id int) (*models.User, error) {
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

func (m *MockUserRepo) DeleteByID(ctx context.Context, id int) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepo) Insert(ctx context.Context, user models.User) (int, error) {
	args := m.Called(ctx, user)
	return args.Int(0), args.Error(1)
}
