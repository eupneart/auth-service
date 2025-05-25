package repositories

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/eupneart/auth-service/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
    RoleUser  = "user"
    RoleAdmin = "admin"
)

func TestUserRepo_GetAll(t *testing.T) {
	// Mock DB setup
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := New(db)

	// Mock rows returned by the database
	rows := sqlmock.NewRows([]string{
		"id", "email", "first_name", "last_name", "password", 
		"role", "is_active", "created_at", "updated_at", "last_login",
	}).
		AddRow(1, "test@example.com", "John", "Doe", "password", RoleUser, true, time.Now(), time.Now(), time.Now()).
		AddRow(2, "test2@example.com", "Jane", "Doe", "password", RoleUser, true, time.Now(), time.Now(), time.Now())

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT id, email, first_name, last_name, password, role, is_active, created_at, updated_at, last_login FROM users ORDER BY last_name`)).
		WillReturnRows(rows)

	// Call method
	users, err := repo.GetAll(context.Background())

	// Assertions
	require.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, 1, users[0].ID)
	assert.Equal(t, "test@example.com", users[0].Email)
	assert.Equal(t, "John", users[0].FirstName)
	assert.Equal(t, "Doe", users[0].LastName)
	assert.Equal(t, RoleUser, users[0].Role)
	assert.True(t, users[0].IsActive)
}

func TestUserRepo_GetById(t *testing.T) {
	// Mock DB setup
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := New(db)

	// Mock row returned by the database
	row := sqlmock.NewRows([]string{
		"id", "email", "first_name", "last_name", "password", 
		"role", "is_active", "created_at", "updated_at", "last_login",
	}).
		AddRow(1, "test@example.com", "John", "Doe", "password", RoleUser, true, time.Now(), time.Now(), time.Now())

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT id, email, first_name, last_name, password, role, is_active, created_at, updated_at, last_login FROM users WHERE id = $1`)).
		WithArgs(1).
		WillReturnRows(row)

	// Call method
	user, err := repo.GetById(context.Background(), 1)

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, 1, user.ID)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "John", user.FirstName)
	assert.Equal(t, "Doe", user.LastName)
	assert.Equal(t, RoleUser, user.Role)
	assert.True(t, user.IsActive)
}

func TestUserRepo_GetByEmail(t *testing.T) {
	// Mock DB setup
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := New(db)

	// Mock row returned by the database
	row := sqlmock.NewRows([]string{
		"id", "email", "first_name", "last_name", "password", 
		"role", "is_active", "created_at", "updated_at", "last_login",
	}).
		AddRow(1, "test@example.com", "John", "Doe", "password", RoleUser, true, time.Now(), time.Now(), time.Now())

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT id, email, first_name, last_name, password, role, is_active, created_at, updated_at, last_login FROM users WHERE email = $1`)).
		WithArgs("test@example.com").
		WillReturnRows(row)

	// Call method
	user, err := repo.GetByEmail(context.Background(), "test@example.com")

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, 1, user.ID)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "John", user.FirstName)
	assert.Equal(t, "Doe", user.LastName)
	assert.Equal(t, RoleUser, user.Role)
	assert.True(t, user.IsActive)
}

func TestUserRepo_Update(t *testing.T) {
	// Mock DB setup
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := New(db)

	// Mock user data
	user := models.User{
		ID:        1,
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
		Role:      RoleUser,
		IsActive:  true,
		LastLogin: time.Now(),
	}

	// Expectations
	mock.ExpectExec(`UPDATE users SET email = \$1, first_name = \$2, last_name = \$3, role = \$4, is_active = \$5, last_login = \$6, updated_at = \$7 WHERE id = \$8`).
		WithArgs(
			user.Email,
			user.FirstName,
			user.LastName,
			user.Role,
			user.IsActive,
			sqlmock.AnyArg(), // last_login
			sqlmock.AnyArg(), // updated_at
			user.ID,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Call method
	err = repo.Update(context.Background(), user)

	// Assertions
	require.NoError(t, err)
}

func TestUserRepo_Update_PartialFields(t *testing.T) {
	// Test updating only some fields
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := New(db)

	// Mock user data - only email and first_name set
	user := models.User{
		ID:        1,
		Email:     "newemail@example.com",
		FirstName: "UpdatedName",
		// Other fields empty/zero values
	}

	// Expectations
	mock.ExpectExec(`UPDATE users SET email = \$1, first_name = \$2, is_active = \$3, updated_at = \$4 WHERE id = \$5`).
		WithArgs(
			user.Email,
			user.FirstName,
			user.IsActive, // false (zero value)
			sqlmock.AnyArg(), // updated_at
			user.ID,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Call method
	err = repo.Update(context.Background(), user)

	// Assertions
	require.NoError(t, err)
}

func TestUserRepo_DeleteByID(t *testing.T) {
	// Mock DB setup
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := New(db)

	// Expectations
	mock.ExpectExec(regexp.QuoteMeta(
		`DELETE FROM users WHERE id = $1`)).
		WithArgs(1).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Call method
	err = repo.DeleteByID(context.Background(), 1)

	// Assertions
	require.NoError(t, err)
}

func TestUserRepo_Insert(t *testing.T) {
	// Setup sqlmock
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	// Create a UserRepo instance with the mock DB
	userRepo := &UserRepo{
		DB: db,
	}

	// Mocked data
	mockUser := models.User{
		Email:     "test@example.com",
		FirstName: "Test",
		LastName:  "User",
		Password:  "hashed_password",
		Role:      RoleUser,
		IsActive:  true,
	}

	// Expected values
	mockID := 123

	// Prepare mock query
	mock.ExpectQuery(`INSERT INTO users \(email, first_name, last_name, password, role, is_active, created_at, updated_at, last_login\) VALUES \(\$1, \$2, \$3, \$4, \$5, \$6, \$7, \$8, \$9\) RETURNING id`).
		WithArgs(
			mockUser.Email,
			mockUser.FirstName,
			mockUser.LastName,
			mockUser.Password,
			mockUser.Role,
			mockUser.IsActive,
			sqlmock.AnyArg(), // created_at
			sqlmock.AnyArg(), // updated_at
			sqlmock.AnyArg(), // last_login
		).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(mockID))

	// Execute the function
	ctx := context.Background()
	insertedID, err := userRepo.Insert(ctx, mockUser)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, mockID, insertedID)

	// Ensure all expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_Update_WithAdminRole(t *testing.T) {
	// Additional test to verify admin role updates work correctly
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := New(db)

	// Mock user data with admin role
	user := models.User{
		ID:       1,
		Email:    "admin@example.com",
		Role:     RoleAdmin,
		IsActive: true,
	}

	// Expectations
	mock.ExpectExec(`UPDATE users SET email = \$1, role = \$2, is_active = \$3, updated_at = \$4 WHERE id = \$5`).
		WithArgs(
			user.Email,
			user.Role,
			user.IsActive,
			sqlmock.AnyArg(), // updated_at
			user.ID,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Call method
	err = repo.Update(context.Background(), user)

	// Assertions
	require.NoError(t, err)
}
