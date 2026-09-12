package env

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type EnvConfig struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	JWTSecret  string
	JWTIssuer  string
	AppPort    string
	AppEnv     string

	// PasswordResetBaseURL is the page reset links point at. Configuration is
	// the only source: building it from a request header would allow reset-link
	// poisoning.
	PasswordResetBaseURL string

	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
}

var Config *EnvConfig

// LoadEnv reads the configuration into Config and returns it.
//
// It reports missing or unusable configuration as an error rather than exiting,
// so the caller decides how to report the failure and the failure paths stay
// testable.
func LoadEnv() (*EnvConfig, error) {
	// Load .env file dynamically based on APP_ENV
	envFile := ".env"
	if appEnv, exists := os.LookupEnv("APP_ENV"); exists {
		envFile = fmt.Sprintf(".env.%s", appEnv)
	}
	if err := godotenv.Load(envFile); err != nil {
		slog.Info("No env file found, using system environment variables", "file", envFile)
	}

	// Determine app environment
	appEnv := getEnv("APP_ENV", "development")
	isProduction := appEnv == "production"

	// Load configuration based on environment
	var (
		dbHost     string
		dbPort     string
		dbUser     string
		dbPassword string
		dbName     string
		jwtSecret  string

		passwordResetBaseURL string
		smtpHost             string
		smtpPort             string
		smtpUsername         string
		smtpPassword         string
		smtpFrom             string
	)

	if isProduction {
		// Production: require critical variables
		var required requiredEnv
		dbHost = required.get("DB_HOST")
		dbPassword = required.get("DB_PASSWORD")
		dbName = required.get("DB_NAME")
		jwtSecret = required.get("JWT_SECRET")
		// Optional with defaults in production
		dbPort = getEnv("DB_PORT", "5432")
		dbUser = getEnv("DB_USER", "postgres")

		// Password reset needs a real sender in production; the development
		// file mailer would leave live reset links on disk.
		passwordResetBaseURL = required.get("PASSWORD_RESET_BASE_URL")
		smtpHost = required.get("SMTP_HOST")
		smtpPort = getEnv("SMTP_PORT", "587")
		smtpUsername = required.get("SMTP_USERNAME")
		smtpPassword = required.get("SMTP_PASSWORD")
		smtpFrom = required.get("SMTP_FROM")

		if err := required.err(); err != nil {
			return nil, err
		}
	} else {
		// Development: all optional with defaults, except JWT_SECRET (auto-generate if missing)
		dbHost = getEnv("DB_HOST", "localhost")
		dbPort = getEnv("DB_PORT", "5432")
		dbUser = getEnv("DB_USER", "postgres")
		dbPassword = getEnv("DB_PASSWORD", "")
		dbName = getEnv("DB_NAME", "auth_db")

		// Auto-generate random secret for development if not set
		jwtSecret = getEnv("JWT_SECRET", "")
		if jwtSecret == "" {
			secret, err := generateRandomSecret(32)
			if err != nil {
				return nil, fmt.Errorf("generating development JWT secret: %w", err)
			}
			jwtSecret = secret
			slog.Info("Generated random JWT secret for development")
		}

		passwordResetBaseURL = getEnv("PASSWORD_RESET_BASE_URL", "http://localhost:4200/reset-password")
		smtpHost = getEnv("SMTP_HOST", "")
		smtpPort = getEnv("SMTP_PORT", "587")
		smtpUsername = getEnv("SMTP_USERNAME", "")
		smtpPassword = getEnv("SMTP_PASSWORD", "")
		smtpFrom = getEnv("SMTP_FROM", "no-reply@localhost")
	}

	Config = &EnvConfig{
		DBHost:     dbHost,
		DBPort:     dbPort,
		DBUser:     dbUser,
		DBPassword: dbPassword,
		DBName:     dbName,
		JWTSecret:  jwtSecret,
		JWTIssuer:  getEnv("JWT_ISSUER", "eupneart-auth-service"),
		AppPort:    getEnv("APP_PORT", "8080"),
		AppEnv:     appEnv,

		PasswordResetBaseURL: passwordResetBaseURL,
		SMTPHost:             smtpHost,
		SMTPPort:             smtpPort,
		SMTPUsername:         smtpUsername,
		SMTPPassword:         smtpPassword,
		SMTPFrom:             smtpFrom,
	}

	return Config, nil
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// requiredEnv collects the names of the required variables that are missing, so
// that a misconfigured deployment is told about all of them at once instead of
// one per restart.
type requiredEnv struct {
	missing []string
}

// get returns the value of a required environment variable, recording the key
// as missing when it is unset or empty.
func (r *requiredEnv) get(key string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return value
	}
	r.missing = append(r.missing, key)
	return ""
}

// err reports every key recorded as missing, or nil when none were.
func (r *requiredEnv) err() error {
	if len(r.missing) == 0 {
		return nil
	}
	return fmt.Errorf("required environment variables not set: %s", strings.Join(r.missing, ", "))
}

// generateRandomSecret generates a cryptographically secure random secret
func generateRandomSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// GetEnvAsInt gets an environment variable as integer with fallback
func GetEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, strconv.Itoa(defaultValue))
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		slog.Warn("Invalid integer for environment variable, using default",
			"key", key, "value", valueStr, "default", defaultValue)
		return defaultValue
	}
	return value
}

// GetEnvAsDuration gets an environment variable as duration with fallback
func GetEnvAsDuration(key, defaultValue string) time.Duration {
	valueStr := getEnv(key, defaultValue)
	duration, err := time.ParseDuration(valueStr)
	if err != nil {
		slog.Warn("Invalid duration for environment variable, using default",
			"key", key, "value", valueStr, "default", defaultValue)
		duration, _ = time.ParseDuration(defaultValue)
	}
	return duration
}

// IsProduction returns true if running in production environment
func IsProduction() bool {
	return Config.AppEnv == "production"
}

// IsDevelopment returns true if running in development environment
func IsDevelopment() bool {
	return Config.AppEnv == "development"
}

func (c *EnvConfig) ToDSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		c.DBHost,
		c.DBPort,
		c.DBUser,
		c.DBPassword,
		c.DBName,
	)
}
