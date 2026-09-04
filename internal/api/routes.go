package api

import (
	"net/http"

	"github.com/eupneart/auth-service/internal/api/handlers"
	authmiddleware "github.com/eupneart/auth-service/internal/api/middleware"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func (s *Server) Routes() http.Handler {
	mux := chi.NewRouter()

	// specify who is allowed to connect (cors policy)
	mux.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://eupneart.com", "http://localhost:4200", "http://localhost:8080"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	mux.Use(chimiddleware.Heartbeat("/ping"))

	// create auth handler with both UserService and TokenService
	authHandler := handlers.NewAuthHandler(s.UserService, s.TokenService)

	mux.Post("/authenticate", authHandler.Authenticate)
	mux.Post("/register", authHandler.Register)
	mux.Post("/refresh", authHandler.Refresh)
	mux.Post("/validate", authHandler.Validate)

	authMiddleware := authmiddleware.Auth(s.TokenService)
	protectedRoutes := mux.With(authMiddleware)
	protectedRoutes.Post("/logout", authHandler.Logout)
	protectedRoutes.Get("/me", authHandler.GetMe)

	return mux
}
