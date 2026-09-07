package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/eupneart/auth-service/internal/api"
	"github.com/eupneart/auth-service/internal/db"
	"github.com/eupneart/auth-service/internal/repositories"
	"github.com/eupneart/auth-service/internal/services"
	"github.com/eupneart/auth-service/pkg/env"
	_ "github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v4"
	_ "github.com/jackc/pgx/v4/stdlib"
)

func main() {
	// Initialize configuration using your env utility
	cfg := env.LoadEnv()

	// Initialize structured logger with appropriate level
	logLevel := slog.LevelInfo
	if env.IsDevelopment() {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	logger.Info("Starting authentication service",
		slog.String("app_env", cfg.AppEnv),
		slog.String("app_port", cfg.AppPort))

	// Connect to DB
	conn := db.ConnectToDB(cfg)
	if conn == nil {
		logger.Error("Can't connect to Postgres!")
		log.Panic("Can't connect to Postgres!")
	}
	logger.Info("Successfully connected to database")

	// Initialize repositories
	userRepo := repositories.NewUserRepo(conn)
	tokenRepo := repositories.NewTokenRepo(conn)

	// Create TokenService configuration using .env.* cfg
	tokenConfig := services.TokenServiceConfig{
		JWTSecret: cfg.JWTSecret,
		Issuer:    cfg.JWTIssuer,
		// Get token durations from environment with sensible defaults
		AccessTokenDuration:  env.GetEnvAsDuration("JWT_ACCESS_TOKEN_DURATION", "15m"),
		RefreshTokenDuration: env.GetEnvAsDuration("JWT_REFRESH_TOKEN_DURATION", "168h"), // 7 days
	}

	// Create services
	userService := services.New(userRepo)
	tokenService := services.NewTokenService(tokenConfig, userRepo, tokenRepo, logger)

	logger.Info("Services initialized successfully")

	// Periodically purge expired token metadata. Best-effort: this goroutine
	// runs for the lifetime of the process.
	cleanupInterval := env.GetEnvAsDuration("TOKEN_CLEANUP_INTERVAL", "1h")
	go func() {
		runCleanup := func() {
			if err := tokenService.CleanupExpiredTokens(context.Background()); err != nil {
				logger.Error("expired token cleanup failed", slog.String("error", err.Error()))
			}
		}
		runCleanup()
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			runCleanup()
		}
	}()
	logger.Info("Expired token cleanup scheduled", slog.Duration("interval", cleanupInterval))

	// Create the API server
	server := api.NewServer(cfg, userService, tokenService)

	// Log configuration (be careful not to log sensitive data)
	logger.Info("Server configuration",
		slog.String("port", cfg.AppPort),
		slog.String("db_host", cfg.DBHost),
		slog.String("db_port", cfg.DBPort),
		slog.String("db_name", cfg.DBName),
		slog.String("jwt_issuer", cfg.JWTIssuer),
		slog.Duration("access_token_duration", tokenConfig.AccessTokenDuration),
		slog.Duration("refresh_token_duration", tokenConfig.RefreshTokenDuration),
		slog.Bool("is_production", env.IsProduction()))

	// Define the http server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.AppPort),
		Handler:      server.Routes(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	logger.Info("HTTP server starting",
		slog.String("address", srv.Addr),
		slog.String("version", "1.0.0"))

	err := srv.ListenAndServe()
	if err != nil {
		logger.Error("Server failed to start", slog.String("error", err.Error()))
		log.Panic(err)
	}
}
