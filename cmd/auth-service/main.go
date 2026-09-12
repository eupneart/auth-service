package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/eupneart/auth-service/internal/api"
	"github.com/eupneart/auth-service/internal/db"
	"github.com/eupneart/auth-service/internal/logging"
	"github.com/eupneart/auth-service/internal/mail"
	"github.com/eupneart/auth-service/internal/repositories"
	"github.com/eupneart/auth-service/internal/services"
	"github.com/eupneart/auth-service/pkg/env"
	_ "github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v4"
	_ "github.com/jackc/pgx/v4/stdlib"
)

// devResetMailbox collects reset links outside production. The .log suffix is
// already covered by .gitignore.
const devResetMailbox = ".reset-links.log"

func main() {
	// The logger is built before the configuration is read so that a failure to
	// read it is reported on the same JSON stream as everything else. The level
	// is only known afterwards, so it is held in a LevelVar and raised once the
	// environment is known.
	var logLevel slog.LevelVar
	logger := slog.New(logging.NewHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: &logLevel,
	})))
	slog.SetDefault(logger)

	// Initialize configuration using your env utility
	cfg, err := env.LoadEnv()
	if err != nil {
		logger.Error("Failed to load configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if env.IsDevelopment() {
		logLevel.Set(slog.LevelDebug)
	}

	logger.Info("Starting authentication service",
		slog.String("app_env", cfg.AppEnv),
		slog.String("app_port", cfg.AppPort))

	// Connect to DB
	conn := db.ConnectToDB(cfg)
	if conn == nil {
		logger.Error("Can't connect to Postgres!")
		os.Exit(1)
	}
	logger.Info("Successfully connected to database")

	// Initialize repositories
	userRepo := repositories.NewUserRepo(conn)
	tokenRepo := repositories.NewTokenRepo(conn)
	passwordResetRepo := repositories.NewPasswordResetTokenRepo(conn)

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

	// Production sends real email; development appends links to a local file so
	// the flow is testable without pretending delivery happened.
	var resetMailer services.PasswordResetMailer
	if env.IsProduction() {
		resetMailer = mail.NewSMTPMailer(mail.SMTPConfig{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
		})
	} else {
		resetMailer = mail.NewFileMailer(devResetMailbox)
		logger.Warn("Using development file mailer for password resets",
			slog.String("path", devResetMailbox))
	}

	passwordResetConfig := services.PasswordResetConfig{
		BaseURL:       cfg.PasswordResetBaseURL,
		TokenLifetime: env.GetEnvAsDuration("PASSWORD_RESET_TOKEN_LIFETIME", "15m"),
	}
	passwordResetService := services.NewPasswordResetService(
		passwordResetConfig,
		userService,
		userRepo,
		passwordResetRepo,
		tokenService,
		resetMailer,
	)

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
	server := api.NewServer(cfg, userService, tokenService, passwordResetService)

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

	if err := srv.ListenAndServe(); err != nil {
		logger.Error("Server failed to start", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
