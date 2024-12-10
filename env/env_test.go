package env

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
	assert.Equal(t, "testhost", Config.DBHost)
	assert.Equal(t, "5433", Config.DBPort)
	assert.Equal(t, "testuser", Config.DBUser)
	assert.Equal(t, "testpass", Config.DBPassword)
	assert.Equal(t, "testdb", Config.DBName)
	assert.Equal(t, "testsecret", Config.JWTSecret)
	assert.Equal(t, "9090", Config.AppPort)
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
	assert.Equal(t, "localhost", Config.DBHost)
	assert.Equal(t, "5432", Config.DBPort)
	assert.Equal(t, "postgres", Config.DBUser)
	assert.Equal(t, "", Config.DBPassword)
	assert.Equal(t, "auth_db", Config.DBName)
	assert.Equal(t, "defaultsecret", Config.JWTSecret)
	assert.Equal(t, "8080", Config.AppPort)
}

func TestLoadEnv_MissingEnvFile(t *testing.T) {
	// Clear any existing environment variables to simulate the missing .env file scenario
	os.Unsetenv("APP_ENV")

	// Load environment variables
	LoadEnv()

	// Check if default environment variables are used since no .env file is present
	assert.Equal(t, "localhost", Config.DBHost)
	assert.Equal(t, "5432", Config.DBPort)
	assert.Equal(t, "postgres", Config.DBUser)
	assert.Equal(t, "", Config.DBPassword)
	assert.Equal(t, "auth_db", Config.DBName)
	assert.Equal(t, "defaultsecret", Config.JWTSecret)
	assert.Equal(t, "8080", Config.AppPort)
}
