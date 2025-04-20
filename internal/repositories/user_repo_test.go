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

func TestUserRepo_GetAll(t *testing.T) {
	// Mock DB setup
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := New(db)

	// Mock rows returned by the database
	rows := sqlmock.NewRows([]string{"id", "email", "first_name", "last_name", "password", "user_active", "created_at", "updated_at"}).
		AddRow(1, "test@example.com", "John", "Doe", "password", 1, time.Now(), time.Now()).
		AddRow(2, "test2@example.com", "Jane", "Doe", "password", 1, time.Now(), time.Now())

	// Expectations
	mock.ExpectQuery(`SELECT id, email, first_name, last_name, password, user_active, created_at, updated_at FROM users`).
		WillReturnRows(rows)

	// Call method
	users, err := repo.GetAll(context.Background())

	// Assertions
	require.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, 1, users[0].ID)
	assert.Equal(t, "test@example.com", users[0].Email)
}

func TestUserRepo_GetById(t *testing.T) {
	// Mock DB setup
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := New(db)

	// Mock row returned by the database
	row := sqlmock.NewRows([]string{"id", "email", "first_name", "last_name", "password", "user_active", "created_at", "updated_at"}).
		AddRow(1, "test@example.com", "John", "Doe", "password", 1, time.Now(), time.Now())

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT id, email, first_name, last_name, password, user_active, created_at, updated_at FROM users WHERE id = $1`)).
		WithArgs(1).
		WillReturnRows(row)

	// Call method
	user, err := repo.GetById(context.Background(), 1)

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, 1, user.ID)
	assert.Equal(t, "test@example.com", user.Email)
}

func TestUserRepo_GetByEmail(t *testing.T) {
	// Mock DB setup
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := New(db)

	// Mock row returned by the database
	row := sqlmock.NewRows([]string{"id", "email", "first_name", "last_name", "password", "user_active", "created_at", "updated_at"}).
		AddRow(1, "test@example.com", "John", "Doe", "password", 1, time.Now(), time.Now())

	// Expectations
	mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT id, email, first_name, last_name, password, user_active, created_at, updated_at FROM users WHERE email = $1`)).
		WithArgs("test@example.com").
		WillReturnRows(row)

	// Call method
	user, err := repo.GetByEmail(context.Background(), "test@example.com")

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, 1, user.ID)
	assert.Equal(t, "test@example.com", user.Email)
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
		Active:    nil,
	}

	// Expectations
	mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE users SET email = $1, first_name = $2, last_name = $3, updated_at = $4 WHERE id = $5`)).
		WithArgs(
			user.Email,
			user.FirstName,
			user.LastName,
			sqlmock.AnyArg(),
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
		Active:    nil,
	}

	// Expected values
	mockID := 123

	// Prepare mock query
	mock.ExpectQuery(`INSERT INTO users`).
		WithArgs(
			mockUser.Email,
			mockUser.FirstName,
			mockUser.LastName,
			mockUser.Password,
			mockUser.Active,
			sqlmock.AnyArg(), // created_at
			sqlmock.AnyArg(), // updated_at
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
