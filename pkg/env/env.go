package env

import (
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

	Config = &EnvConfig{
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBUser:     getEnv("DB_USER", "postgres"),
		DBPassword: getEnv("DB_PASSWORD", ""), // Fixed: was DB_PASS, should be DB_PASSWORD
		DBName:     getEnv("DB_NAME", "auth_db"),
		JWTSecret:  getEnv("JWT_SECRET", "defaultsecret"),
		JWTIssuer:  getEnv("JWT_ISSUER", "eupneart-auth-service"),
		AppPort:    getEnv("APP_PORT", "8080"),
		AppEnv:     getEnv("APP_ENV", "development"),
	}

  log.Print(Config)

	return Config
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
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
