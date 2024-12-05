package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadEnv_ValidEnvVars(t *testing.T) {
	// Set the environment variables for this test
	os.Setenv("DB_HOST", "testhost")
	os.Setenv("DB_PORT", "5433")
	os.Setenv("DB_USER", "testuser")
	os.Setenv("DB_PASS", "testpass")
	os.Setenv("DB_NAME", "testdb")
	os.Setenv("JWT_SECRET", "testsecret")
	os.Setenv("APP_PORT", "9090")

	// Load the environment
	LoadEnv()

	// Assert that the values are correctly loaded into the AppConfig
	assert.Equal(t, "testhost", AppConfig.DBHost)
	assert.Equal(t, "5433", AppConfig.DBPort)
	assert.Equal(t, "testuser", AppConfig.DBUser)
	assert.Equal(t, "testpass", AppConfig.DBPassword)
	assert.Equal(t, "testdb", AppConfig.DBName)
	assert.Equal(t, "testsecret", AppConfig.JWTSecret)
	assert.Equal(t, "9090", AppConfig.AppPort)
}

func TestLoadEnv_DefaultValues(t *testing.T) {
	// Clear any existing environment variables before the test
	os.Unsetenv("DB_HOST")
	os.Unsetenv("DB_PORT")
	os.Unsetenv("DB_USER")
	os.Unsetenv("DB_PASS")
	os.Unsetenv("DB_NAME")
	os.Unsetenv("JWT_SECRET")
	os.Unsetenv("APP_PORT")

	// Load environment variables (which should fall back to defaults)
  LoadEnv()

	// Assert that the default values are used
	assert.Equal(t, "localhost", AppConfig.DBHost)
	assert.Equal(t, "5432", AppConfig.DBPort)
	assert.Equal(t, "postgres", AppConfig.DBUser)
	assert.Equal(t, "", AppConfig.DBPassword)
	assert.Equal(t, "auth_db", AppConfig.DBName)
	assert.Equal(t, "defaultsecret", AppConfig.JWTSecret)
	assert.Equal(t, "8080", AppConfig.AppPort)
}

func TestLoadEnv_MissingEnvFile(t *testing.T) {
	// Clear any existing environment variables to simulate the missing .env file scenario
	os.Unsetenv("APP_ENV")

	// Load environment variables
	LoadEnv()

	// Check if default environment variables are used since no .env file is present
	assert.Equal(t, "localhost", AppConfig.DBHost)
	assert.Equal(t, "5432", AppConfig.DBPort)
	assert.Equal(t, "postgres", AppConfig.DBUser)
	assert.Equal(t, "", AppConfig.DBPassword)
	assert.Equal(t, "auth_db", AppConfig.DBName)
	assert.Equal(t, "defaultsecret", AppConfig.JWTSecret)
	assert.Equal(t, "8080", AppConfig.AppPort)
}
