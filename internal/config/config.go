package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
  DBHost     string
  DBPort     string
  DBUser     string
  DBPassword string
  DBName     string
  JWTSecret  string
  AppPort    string
}

var AppConfig *Config

// Initialize AppConfig by loading environment variables
func LoadEnv() {
  // Load .env file dynamically based on APP_ENV
	envFile := ".env"
	if appEnv, exists := os.LookupEnv("APP_ENV"); exists {
		envFile = fmt.Sprintf(".env.%s", appEnv)
	}

	err := godotenv.Load(envFile)
	if err != nil {
		log.Printf("[INFO] No %s file found, using system environment variables", envFile)
	}

  AppConfig = &Config{
    DBHost:     getEnv("DB_HOST", "localhost"),
    DBPort:     getEnv("DB_PORT", "5432"),
    DBUser:     getEnv("DB_USER", "postgres"),
    DBPassword: getEnv("DB_PASS", ""),
    DBName:     getEnv("DB_NAME", "auth_db"),
    JWTSecret:  getEnv("JWT_SECRET", "defaultsecret"),
    AppPort:    getEnv("APP_PORT", "8080"),
  } 
}

func getEnv(key, defaultValue string) string {
  if value, exists := os.LookupEnv(key); exists {
    return value
  }

  return defaultValue
}
