package api

import (
	"net/http"

	"github.com/eupneart/auth-service/internal/services"
	"github.com/eupneart/auth-service/pkg/env"
)

type Server struct {
  Settings *env.EnvConfig
  UserService *services.UserService
  TokenService services.TokenService
}

func NewServer(settings *env.EnvConfig, userService *services.UserService, tokenService services.TokenService) *Server {
  return &Server{
    Settings: settings,
    UserService: userService,
    TokenService: tokenService,
  }
}

func (s *Server) ServeHttp(w http.ResponseWriter, r *http.Request) {
  s.Routes().ServeHTTP(w, r)
} 
