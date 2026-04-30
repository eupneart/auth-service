package env

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strconv"
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
}

var Config *EnvConfig

// Initialize AppConfig by loading environment variables
func LoadEnv() *EnvConfig {
	// Load .env file dynamically based on APP_ENV
	envFile := ".env"
	if appEnv, exists := os.LookupEnv("APP_ENV"); exists {
		envFile = fmt.Sprintf(".env.%s", appEnv)
	}
	err := godotenv.Load(envFile)
	if err != nil {
		log.Printf("[INFO] No %s file found, using system environment variables", envFile)
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
	)

	if isProduction {
		// Production: require critical variables
		dbHost = getEnvRequired("DB_HOST")
		dbPassword = getEnvRequired("DB_PASSWORD")
		dbName = getEnvRequired("DB_NAME")
		jwtSecret = getEnvRequired("JWT_SECRET")
		// Optional with defaults in production
		dbPort = getEnv("DB_PORT", "5432")
		dbUser = getEnv("DB_USER", "postgres")
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
			jwtSecret = generateRandomSecret(32)
			log.Printf("[INFO] Generated random JWT secret for development")
		}
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
	}

	return Config
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvRequired retrieves a required environment variable
// Fails fast if the variable is not set (typically used for production)
func getEnvRequired(key string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return value
	}
	log.Fatalf("required environment variable %s is not set", key)
	return ""
}

// generateRandomSecret generates a cryptographically secure random secret
func generateRandomSecret(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("failed to generate random secret: %v", err)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

// GetEnvAsInt gets an environment variable as integer with fallback
func GetEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, strconv.Itoa(defaultValue))
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		log.Printf("[WARN] Invalid integer for %s: %s, using default: %d", key, valueStr, defaultValue)
		return defaultValue
	}
	return value
}

// GetEnvAsDuration gets an environment variable as duration with fallback
func GetEnvAsDuration(key, defaultValue string) time.Duration {
	valueStr := getEnv(key, defaultValue)
	duration, err := time.ParseDuration(valueStr)
	if err != nil {
		log.Printf("[WARN] Invalid duration for %s: %s, using default: %s", key, valueStr, defaultValue)
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
