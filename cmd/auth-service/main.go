package main

import (
	"database/sql"
	"log"

	"github.com/mayart-ai/auth-service/config"
)

type Config struct {
  DB *sql.DB
  settings *config.Config
}

func main() {
  // Initialize configuration
  config.LoadEnv()

	// Access configurations
	log.Printf("Starting server on port %s", config.AppConfig.AppPort)
	log.Printf("Connecting to database %s:%s", config.AppConfig.DBHost, config.AppConfig.DBPort)

}
