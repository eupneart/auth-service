package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/mayart-ai/auth-service/internal/models"
)

type UserRepo struct {
	DB *sql.DB
}

func New(db *sql.DB) *UserRepo {
	return &UserRepo{DB: db}
}

// GetAll returns a slice of all users, sorted by last name
func (r *UserRepo) GetAll(ctx context.Context) ([]*models.User, error) {
	// SQL query
	query := `SELECT id, email, first_name, last_name, password, user_active, created_at, updated_at
	          FROM users ORDER BY last_name`

	// Execute query
	rows, err := r.DB.QueryContext(ctx, query)
	if err != nil {
    return nil, fmt.Errorf("querying all users: %w", err)
	}
	defer rows.Close()

  return scanUsers(rows)
}

// GetById returns one user by id
func (r *UserRepo) GetById(ctx context.Context, id int) (*models.User, error) {
  query := `SELECT id, email, first_name, last_name, password, user_active, created_at, updated_at FROM users WHERE id = $1`

	var user models.User
	row := r.DB.QueryRowContext(ctx, query, id)

	err := scanUser(row, &user)
	if err != nil {
    return nil, fmt.Errorf("querying user by id: %w", err)
	}

	return &user, nil
}

// GetByEmail returns one user by email
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `SELECT id, email, first_name, last_name, password, user_active, created_at, updated_at FROM users WHERE email = $1`

	var user models.User
	row := r.DB.QueryRowContext(ctx, query, email)

	err := scanUser(row, &user)
	if err != nil {
    return nil, fmt.Errorf("querying user by email: %w", err)
	}

	return &user, nil
}

// Update one user in the database, using the user information
func (r *UserRepo) Update(ctx context.Context, u models.User) error {
	type field struct {
		name  string      // Column name in the database
		value interface{} // Value to be updated
		isSet bool        // Whether the field should be included in the query
	}

	// Define the fields to be updated
	fields := []field{
		{"email", u.Email, u.Email != ""},
		{"first_name", u.FirstName, u.FirstName != ""},
		{"last_name", u.LastName, u.LastName != ""},
		{"user_active", u.Active, u.Active != nil},
	}

	// Base query
	query := "UPDATE users SET"
	args := []interface{}{} // empty slice of any values
	counter := 1

	// Dynamically build the query
	for _, f := range fields {
		if f.isSet {
			query += fmt.Sprintf(" %s = $%d,", f.name, counter)
			args = append(args, f.value)
			counter++
		}
	}

	// Always update the `updated_at` field
	query += fmt.Sprintf(" updated_at = $%d", counter)
	args = append(args, time.Now())
	counter++

	// Add the WHERE clause
	query += fmt.Sprintf(" WHERE id = $%d", counter)
	args = append(args, u.ID)

	// Execute the query
	_, err := r.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("updating user: %w", err)
	}

	return nil
}

// DeleteByID one user from the database, by ID
func (r *UserRepo) DeleteByID(ctx context.Context, id int) error {
	stmt := `DELETE FROM users WHERE id = $1`

	_, err := r.DB.ExecContext(ctx, stmt, id)
	if err != nil {
    return fmt.Errorf("deleting user by id: %w", err)
	}

	return nil
}

// Insert a single user into the DB
func (r *UserRepo) Insert(ctx context.Context, u models.User) (int, error) {
	// sql statement
	stmt := `INSERT INTO users (email, first_name, last_name, password, user_active, created_at, updated_at) 
  VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

	// execute sql statement
	var newId int
  err := r.DB.QueryRowContext(ctx, stmt,
		u.Email,
		u.FirstName,
		u.LastName,
		u.Password,
		u.Active,
		time.Now(),
		time.Now(),
	).Scan(&newId)

	if err != nil {
    return 0, fmt.Errorf("inserting user: %w", err)
	}

	return newId, nil
}

//========================= Helper functions ============================

// scanUsers is a helper function to scan multiple rows into a slice of User structs.
func scanUsers(rows *sql.Rows) ([]*models.User, error) {
  var users []*models.User
	for rows.Next() {
		var user models.User
		// Scan the current row into the user struct
		if err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.FirstName,
			&user.LastName,
			&user.Password,
			&user.Active,
			&user.CreatedAt,
			&user.UpdatedAt,
		); err != nil {
			return nil, err
		}
		// Append the scanned user to the slice
		users = append(users, &user)
	}

	// Check if there was any error while iterating through the rows
	if err := rows.Err(); err != nil {
    return nil, fmt.Errorf("scanning users: %w", err)
	}

  return users, nil
}

// scanUser is a helper function to scan a single row into a User struct.
func scanUser(row *sql.Row, user *models.User) error {
	return row.Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.Password,
		&user.Active,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
}
