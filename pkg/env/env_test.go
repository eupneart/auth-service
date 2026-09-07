package env

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoadEnv_ValidEnvVars(t *testing.T) {
	// Clean before test
	cleanupEnvVars()
	defer cleanupEnvVars()
	
	// Set the environment variables for this test
	t.Setenv("DB_HOST", "testhost")
	t.Setenv("DB_PORT", "5433")
	t.Setenv("DB_USER", "testuser")
	t.Setenv("DB_PASSWORD", "testpass") // Updated from DB_PASS
	t.Setenv("DB_NAME", "testdb")
	t.Setenv("JWT_SECRET", "testsecret")
	t.Setenv("JWT_ISSUER", "test-issuer")
	t.Setenv("APP_PORT", "9090")
	t.Setenv("APP_ENV", "testing")

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
}

func TestLoadEnv_DefaultValues(t *testing.T) {
	// Clean before test
	cleanupEnvVars()
	defer cleanupEnvVars()
	
	t.Setenv("APP_ENV", "development")

	// Load environment variables (which should fall back to defaults)
	LoadEnv()

	// Assert that the default values are used
	assert.Equal(t, "localhost", Config.DBHost)
	assert.Equal(t, "5432", Config.DBPort)
	assert.Equal(t, "postgres", Config.DBUser)
	assert.Equal(t, "", Config.DBPassword)
	assert.Equal(t, "auth_db", Config.DBName)
	// JWT_SECRET should be auto-generated in development, not a default
	assert.NotEmpty(t, Config.JWTSecret)
	assert.NotEqual(t, "defaultsecret", Config.JWTSecret)
	assert.Equal(t, "eupneart-auth-service", Config.JWTIssuer)
	assert.Equal(t, "8080", Config.AppPort)
	assert.Equal(t, "development", Config.AppEnv)
}

func TestLoadEnv_MissingEnvFile(t *testing.T) {
	// Clean before test
	cleanupEnvVars()
	defer cleanupEnvVars()
	
	t.Setenv("APP_ENV", "development")

	// Load environment variables
	LoadEnv()

	// Check if default environment variables are used since no .env file is present
	assert.Equal(t, "localhost", Config.DBHost)
	assert.Equal(t, "5432", Config.DBPort)
	assert.Equal(t, "postgres", Config.DBUser)
	assert.Equal(t, "", Config.DBPassword)
	assert.Equal(t, "auth_db", Config.DBName)
	// JWT_SECRET should be auto-generated in development
	assert.NotEmpty(t, Config.JWTSecret)
	assert.NotEqual(t, "defaultsecret", Config.JWTSecret)
	assert.Equal(t, "eupneart-auth-service", Config.JWTIssuer)
	assert.Equal(t, "8080", Config.AppPort)
	assert.Equal(t, "development", Config.AppEnv)
}

func TestLoadEnv_EnvironmentSpecificFiles(t *testing.T) {
	// Clean before test
	cleanupEnvVars()
	defer cleanupEnvVars()
	
	// Test that different APP_ENV values attempt to load different .env files
	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_HOST", "prod-host")
	t.Setenv("DB_PASSWORD", "prod-pass")
	t.Setenv("DB_NAME", "prod-db")
	t.Setenv("JWT_SECRET", "test-secret")
	setProductionMailVars(t)

	// Load environment (will try to load .env.production but fall back to env vars)
	LoadEnv()
	
	assert.Equal(t, "production", Config.AppEnv)
	assert.Equal(t, "prod-host", Config.DBHost)
	assert.Equal(t, "prod-pass", Config.DBPassword)
	assert.Equal(t, "prod-db", Config.DBName)
}

func TestLoadEnv_DevelopmentAutoGeneratesSecret(t *testing.T) {
	// Clean before test
	cleanupEnvVars()
	defer cleanupEnvVars()
	
	// This test verifies that development environment auto-generates JWT_SECRET
	t.Setenv("APP_ENV", "development")
	
	LoadEnv()
	
	// Verify JWT_SECRET is generated and not empty
	assert.NotEmpty(t, Config.JWTSecret)
	assert.NotEqual(t, "defaultsecret", Config.JWTSecret)
	// Base64 encoded 32 bytes should be around 43-44 characters
	assert.Greater(t, len(Config.JWTSecret), 30)
}

func TestLoadEnv_DevelopmentWithProvidedSecret(t *testing.T) {
	// Clean before test
	cleanupEnvVars()
	defer cleanupEnvVars()
	
	// This test verifies that provided JWT_SECRET is used in development
	t.Setenv("APP_ENV", "development")
	t.Setenv("JWT_SECRET", "my-custom-secret")
	
	LoadEnv()
	
	// Verify provided secret is used
	assert.Equal(t, "my-custom-secret", Config.JWTSecret)
}

func TestLoadEnv_ProductionRequiredVars(t *testing.T) {
	// Clean before test
	cleanupEnvVars()
	defer cleanupEnvVars()
	
	// Test production environment with all required variables set
	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_HOST", "prod-db-host")
	t.Setenv("DB_PASSWORD", "prod-db-password")
	t.Setenv("DB_NAME", "prod-db-name")
	t.Setenv("JWT_SECRET", "prod-jwt-secret")
	setProductionMailVars(t)

	LoadEnv()

	// Verify required vars are loaded
	assert.Equal(t, "prod-db-host", Config.DBHost)
	assert.Equal(t, "prod-db-password", Config.DBPassword)
	assert.Equal(t, "prod-db-name", Config.DBName)
	assert.Equal(t, "prod-jwt-secret", Config.JWTSecret)
	// Optional vars still get defaults
	assert.Equal(t, "5432", Config.DBPort)
	assert.Equal(t, "postgres", Config.DBUser)
}

func TestLoadEnv_ProductionWithOptionalDefaults(t *testing.T) {
	// Clean before test
	cleanupEnvVars()
	defer cleanupEnvVars()
	
	// Test production environment with only required variables
	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_HOST", "prod-host")
	t.Setenv("DB_PASSWORD", "prod-pass")
	t.Setenv("DB_NAME", "prod-db")
	t.Setenv("JWT_SECRET", "prod-secret")
	setProductionMailVars(t)
	// Do NOT set DB_PORT and DB_USER - should use defaults

	LoadEnv()

	// Verify defaults are used for optional vars
	assert.Equal(t, "5432", Config.DBPort)
	assert.Equal(t, "postgres", Config.DBUser)
	assert.Equal(t, "8080", Config.AppPort)
	assert.Equal(t, "eupneart-auth-service", Config.JWTIssuer)
}

func TestGetEnvAsInt_ValidInteger(t *testing.T) {
	t.Setenv("TEST_INT", "42")
	
	result := GetEnvAsInt("TEST_INT", 10)
	assert.Equal(t, 42, result)
}

func TestGetEnvAsInt_InvalidInteger(t *testing.T) {
	t.Setenv("TEST_INT", "not-a-number")
	
	result := GetEnvAsInt("TEST_INT", 10)
	assert.Equal(t, 10, result) // Should return default value
}

func TestGetEnvAsInt_MissingEnvVar(t *testing.T) {
	os.Unsetenv("MISSING_INT")
	
	result := GetEnvAsInt("MISSING_INT", 25)
	assert.Equal(t, 25, result) // Should return default value
}

func TestGetEnvAsDuration_ValidDuration(t *testing.T) {
	t.Setenv("TEST_DURATION", "30m")
	
	result := GetEnvAsDuration("TEST_DURATION", "15m")
	expected, _ := time.ParseDuration("30m")
	assert.Equal(t, expected, result)
}

func TestGetEnvAsDuration_InvalidDuration(t *testing.T) {
	t.Setenv("TEST_DURATION", "invalid-duration")
	
	result := GetEnvAsDuration("TEST_DURATION", "15m")
	expected, _ := time.ParseDuration("15m")
	assert.Equal(t, expected, result) // Should return default value
}

func TestGetEnvAsDuration_MissingEnvVar(t *testing.T) {
	os.Unsetenv("MISSING_DURATION")
	
	result := GetEnvAsDuration("MISSING_DURATION", "1h")
	expected, _ := time.ParseDuration("1h")
	assert.Equal(t, expected, result) // Should return default value
}

func TestIsProduction(t *testing.T) {
	defer cleanupEnvVars()
	
	// Test production environment
	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_HOST", "prod-host")
	t.Setenv("DB_PASSWORD", "prod-pass")
	t.Setenv("DB_NAME", "prod-db")
	t.Setenv("JWT_SECRET", "prod-secret")
	setProductionMailVars(t)
	LoadEnv()
	assert.True(t, IsProduction())
	assert.False(t, IsDevelopment())
	
	// Test development environment
	cleanupEnvVars()
	t.Setenv("APP_ENV", "development")
	LoadEnv()
	assert.False(t, IsProduction())
	assert.True(t, IsDevelopment())
	
	// Test other environment
	cleanupEnvVars()
	t.Setenv("APP_ENV", "testing")
	LoadEnv()
	assert.False(t, IsProduction())
	assert.False(t, IsDevelopment())
}

func TestIsDevelopment(t *testing.T) {
	defer cleanupEnvVars()
	
	// Test development environment
	t.Setenv("APP_ENV", "development")
	LoadEnv()
	assert.True(t, IsDevelopment())
	
	// Test non-development environment
	cleanupEnvVars()
	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_HOST", "prod-host")
	t.Setenv("DB_PASSWORD", "prod-pass")
	t.Setenv("DB_NAME", "prod-db")
	t.Setenv("JWT_SECRET", "prod-secret")
	setProductionMailVars(t)
	LoadEnv()
	assert.False(t, IsDevelopment())
}

func TestConfigPersistence(t *testing.T) {
	// Clean before test
	cleanupEnvVars()
	defer cleanupEnvVars()
	
	// Test that Config is properly set and accessible globally
	t.Setenv("DB_HOST", "test-persistence")
	t.Setenv("APP_ENV", "development")
	LoadEnv()
	
	// Config should be accessible globally
	assert.NotNil(t, Config)
	assert.Equal(t, "test-persistence", Config.DBHost)
}

func TestJWTConfiguration(t *testing.T) {
	// Clean before test
	cleanupEnvVars()
	defer cleanupEnvVars()
	
	// Test JWT-specific configuration
	t.Setenv("JWT_SECRET", "super-secret-key")
	t.Setenv("JWT_ISSUER", "test-auth-service")
	t.Setenv("APP_ENV", "development")
	
	LoadEnv()
	
	assert.Equal(t, "super-secret-key", Config.JWTSecret)
	assert.Equal(t, "test-auth-service", Config.JWTIssuer)
}

// Helper function to clean up environment variables after tests
// setProductionMailVars sets the password-reset and SMTP variables that
// production requires, so tests exercising other production settings do not
// trip the fail-fast check.
func setProductionMailVars(t *testing.T) {
	t.Helper()

	t.Setenv("PASSWORD_RESET_BASE_URL", "https://eupneart.com/reset-password")
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_USERNAME", "mailer")
	t.Setenv("SMTP_PASSWORD", "mailer-pass")
	t.Setenv("SMTP_FROM", "no-reply@eupneart.com")
}

func cleanupEnvVars() {
	envVars := []string{
		"DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME",
		"JWT_SECRET", "JWT_ISSUER", "APP_PORT", "APP_ENV",
		"TEST_INT", "TEST_DURATION", "MISSING_INT", "MISSING_DURATION",
		"PASSWORD_RESET_BASE_URL",
		"SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM",
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
	b.Setenv("DB_HOST", "benchmark-host")
	b.Setenv("JWT_SECRET", "benchmark-secret")
	b.Setenv("APP_ENV", "development")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		LoadEnv()
	}
}

func BenchmarkGetEnvAsInt(b *testing.B) {
	b.Setenv("BENCHMARK_INT", "42")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetEnvAsInt("BENCHMARK_INT", 10)
	}
}

func BenchmarkGetEnvAsDuration(b *testing.B) {
	b.Setenv("BENCHMARK_DURATION", "30m")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetEnvAsDuration("BENCHMARK_DURATION", "15m")
	}
}
