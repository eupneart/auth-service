package main

import (
	"log"

	"github.com/mayart-ai/auth-service/internal/config"
)

func main() {
  // Initialize configuration
	config.LoadEnv()

	// Access configurations
	log.Printf("Starting server on port %s", config.AppConfig.AppPort)
	log.Printf("Connecting to database %s:%s", config.AppConfig.DBHost, config.AppConfig.DBPort)
}
