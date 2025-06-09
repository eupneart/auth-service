package env

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoadEnv_ValidEnvVars(t *testing.T) {
	// Set the environment variables for this test
	os.Setenv("DB_HOST", "testhost")
	os.Setenv("DB_PORT", "5433")
	os.Setenv("DB_USER", "testuser")
	os.Setenv("DB_PASSWORD", "testpass") // Updated from DB_PASS
	os.Setenv("DB_NAME", "testdb")
	os.Setenv("JWT_SECRET", "testsecret")
	os.Setenv("JWT_ISSUER", "test-issuer")
	os.Setenv("APP_PORT", "9090")
	os.Setenv("APP_ENV", "testing")

	// Load the environment
	LoadEnv()

	// Assert that the values are correctly loaded into the Config
	assert.Equal(t, "testhost", Config.DBHost)
	assert.Equal(t, "5433", Config.DBPort)
	assert.Equal(t, "testuser", Config.DBUser)
	assert.Equal(t, "testpass", Config.DBPassword)
	assert.Equal(t, "testdb", Config.DBName)
	assert.Equal(t, "testsecret", Config.JWTSecret)
	assert.Equal(t, "test-issuer", Config.JWTIssuer)
	assert.Equal(t, "9090", Config.AppPort)
	assert.Equal(t, "testing", Config.AppEnv)

	// Clean up after test
	cleanupEnvVars()
}

func TestLoadEnv_DefaultValues(t *testing.T) {
	// Clear any existing environment variables before the test
	cleanupEnvVars()

	// Load environment variables (which should fall back to defaults)
	LoadEnv()

	// Assert that the default values are used
	assert.Equal(t, "localhost", Config.DBHost)
	assert.Equal(t, "5432", Config.DBPort)
	assert.Equal(t, "postgres", Config.DBUser)
	assert.Equal(t, "", Config.DBPassword)
	assert.Equal(t, "auth_db", Config.DBName)
	assert.Equal(t, "defaultsecret", Config.JWTSecret)
	assert.Equal(t, "eupneart-auth-service", Config.JWTIssuer)
	assert.Equal(t, "8080", Config.AppPort)
	assert.Equal(t, "development", Config.AppEnv)
}

func TestLoadEnv_MissingEnvFile(t *testing.T) {
	// Clear any existing environment variables to simulate the missing .env file scenario
	cleanupEnvVars()

	// Load environment variables
	LoadEnv()

	// Check if default environment variables are used since no .env file is present
	assert.Equal(t, "localhost", Config.DBHost)
	assert.Equal(t, "5432", Config.DBPort)
	assert.Equal(t, "postgres", Config.DBUser)
	assert.Equal(t, "", Config.DBPassword)
	assert.Equal(t, "auth_db", Config.DBName)
	assert.Equal(t, "defaultsecret", Config.JWTSecret)
	assert.Equal(t, "eupneart-auth-service", Config.JWTIssuer)
	assert.Equal(t, "8080", Config.AppPort)
	assert.Equal(t, "development", Config.AppEnv)
}

func TestLoadEnv_EnvironmentSpecificFiles(t *testing.T) {
	// Test that different APP_ENV values attempt to load different .env files
	
	// Set APP_ENV to production
	os.Setenv("APP_ENV", "production")
	os.Setenv("DB_HOST", "prod-host")
	
	// Load environment (will try to load .env.production but fall back to env vars)
	LoadEnv()
	
	assert.Equal(t, "production", Config.AppEnv)
	assert.Equal(t, "prod-host", Config.DBHost)
	
	// Clean up
	cleanupEnvVars()
}

func TestGetEnvAsInt_ValidInteger(t *testing.T) {
	os.Setenv("TEST_INT", "42")
	
	result := GetEnvAsInt("TEST_INT", 10)
	assert.Equal(t, 42, result)
	
	os.Unsetenv("TEST_INT")
}

func TestGetEnvAsInt_InvalidInteger(t *testing.T) {
	os.Setenv("TEST_INT", "not-a-number")
	
	result := GetEnvAsInt("TEST_INT", 10)
	assert.Equal(t, 10, result) // Should return default value
	
	os.Unsetenv("TEST_INT")
}

func TestGetEnvAsInt_MissingEnvVar(t *testing.T) {
	os.Unsetenv("MISSING_INT")
	
	result := GetEnvAsInt("MISSING_INT", 25)
	assert.Equal(t, 25, result) // Should return default value
}

func TestGetEnvAsDuration_ValidDuration(t *testing.T) {
	os.Setenv("TEST_DURATION", "30m")
	
	result := GetEnvAsDuration("TEST_DURATION", "15m")
	expected, _ := time.ParseDuration("30m")
	assert.Equal(t, expected, result)
	
	os.Unsetenv("TEST_DURATION")
}

func TestGetEnvAsDuration_InvalidDuration(t *testing.T) {
	os.Setenv("TEST_DURATION", "invalid-duration")
	
	result := GetEnvAsDuration("TEST_DURATION", "15m")
	expected, _ := time.ParseDuration("15m")
	assert.Equal(t, expected, result) // Should return default value
	
	os.Unsetenv("TEST_DURATION")
}

func TestGetEnvAsDuration_MissingEnvVar(t *testing.T) {
	os.Unsetenv("MISSING_DURATION")
	
	result := GetEnvAsDuration("MISSING_DURATION", "1h")
	expected, _ := time.ParseDuration("1h")
	assert.Equal(t, expected, result) // Should return default value
}

func TestIsProduction(t *testing.T) {
	// Test production environment
	os.Setenv("APP_ENV", "production")
	LoadEnv()
	assert.True(t, IsProduction())
	assert.False(t, IsDevelopment())
	
	// Test development environment
	os.Setenv("APP_ENV", "development")
	LoadEnv()
	assert.False(t, IsProduction())
	assert.True(t, IsDevelopment())
	
	// Test other environment
	os.Setenv("APP_ENV", "testing")
	LoadEnv()
	assert.False(t, IsProduction())
	assert.False(t, IsDevelopment())
	
	cleanupEnvVars()
}

func TestIsDevelopment(t *testing.T) {
	// Test development environment
	os.Setenv("APP_ENV", "development")
	LoadEnv()
	assert.True(t, IsDevelopment())
	
	// Test non-development environment
	os.Setenv("APP_ENV", "production")
	LoadEnv()
	assert.False(t, IsDevelopment())
	
	cleanupEnvVars()
}

func TestConfigPersistence(t *testing.T) {
	// Test that Config is properly set and accessible globally
	os.Setenv("DB_HOST", "test-persistence")
	LoadEnv()
	
	// Config should be accessible globally
	assert.NotNil(t, Config)
	assert.Equal(t, "test-persistence", Config.DBHost)
	
	cleanupEnvVars()
}

func TestJWTConfiguration(t *testing.T) {
	// Test JWT-specific configuration
	os.Setenv("JWT_SECRET", "super-secret-key")
	os.Setenv("JWT_ISSUER", "test-auth-service")
	
	LoadEnv()
	
	assert.Equal(t, "super-secret-key", Config.JWTSecret)
	assert.Equal(t, "test-auth-service", Config.JWTIssuer)
	
	cleanupEnvVars()
}

// Helper function to clean up environment variables after tests
func cleanupEnvVars() {
	envVars := []string{
		"DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME",
		"JWT_SECRET", "JWT_ISSUER", "APP_PORT", "APP_ENV",
		"TEST_INT", "TEST_DURATION", "MISSING_INT", "MISSING_DURATION",
	}
	
	for _, envVar := range envVars {
		os.Unsetenv(envVar)
	}
	
	// Reset Config to nil to ensure clean state
	Config = nil
}

// Benchmark tests for performance
func BenchmarkLoadEnv(b *testing.B) {
	// Set up some environment variables
	os.Setenv("DB_HOST", "benchmark-host")
	os.Setenv("JWT_SECRET", "benchmark-secret")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		LoadEnv()
	}
	
	// Cleanup
	os.Unsetenv("DB_HOST")
	os.Unsetenv("JWT_SECRET")
}

func BenchmarkGetEnvAsInt(b *testing.B) {
	os.Setenv("BENCHMARK_INT", "42")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetEnvAsInt("BENCHMARK_INT", 10)
	}
	
	os.Unsetenv("BENCHMARK_INT")
}

func BenchmarkGetEnvAsDuration(b *testing.B) {
	os.Setenv("BENCHMARK_DURATION", "30m")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetEnvAsDuration("BENCHMARK_DURATION", "15m")
	}
	
	os.Unsetenv("BENCHMARK_DURATION")
}
