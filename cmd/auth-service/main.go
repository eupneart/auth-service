package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/mayart-ai/auth-service/db"
	"github.com/mayart-ai/auth-service/env"
	"github.com/mayart-ai/auth-service/internal/config"
	"github.com/mayart-ai/auth-service/internal/repositories"
	"github.com/mayart-ai/auth-service/internal/services"
)

const webPort = "80"

func main() {
  // Initialize configuration
  env.LoadEnv()
  	log.Println("Starting authentication service")

	// Connect to DB
	conn := db.ConnectToDB()
	if conn == nil {
		log.Panic("Can't connect to Postgres!")
	}

  // Initialize the userRepo
  userRepo := repositories.New(conn)

	// Set up config
	app := config.New(env.Config, services.New(userRepo))

  // Server definition
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", webPort),
		Handler: app.Routes(),
	}

  // Exec server
	err := srv.ListenAndServe()
	if err != nil {
		log.Panic(err)
	}

	// Access configurations
	log.Printf("Starting server on port %s", env.Config.AppPort)
	log.Printf("Connecting to database %s:%s", env.Config.DBHost, env.Config.DBPort)
}
