package api

import (
	"net/http"

	"github.com/eupneart/auth-service/internal/api/handlers"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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

  mux.Use(middleware.Heartbeat("/ping"))

  // create auth handler
  authHandler := handlers.NewAuthHandler(s.UserService) 

  mux.Post("/authenticate", authHandler.Authenticate)
  mux.Post("/register", authHandler.Register)
  
  return mux
}

