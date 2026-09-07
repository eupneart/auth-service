package api

import (
	"net/http"
	"time"

	"github.com/eupneart/auth-service/internal/services"
	"github.com/eupneart/auth-service/pkg/env"
	"github.com/eupneart/auth-service/pkg/ratelimit"
)

// Password recovery is unauthenticated, so it is limited per source address to
// blunt enumeration sweeps and mail flooding.
const (
	passwordRequestsPerIP = 10
	passwordRequestWindow = time.Minute
)

type Server struct {
	Settings             *env.EnvConfig
	UserService          *services.UserService
	TokenService         services.TokenService
	PasswordResetService *services.PasswordResetService

	// Held on the server, not built in Routes, so the counters survive for the
	// process rather than resetting whenever routes are constructed.
	passwordLimiter *ratelimit.Limiter
}

func NewServer(settings *env.EnvConfig, userService *services.UserService, tokenService services.TokenService, passwordResetService *services.PasswordResetService) *Server {
	return &Server{
		Settings:             settings,
		UserService:          userService,
		TokenService:         tokenService,
		PasswordResetService: passwordResetService,
		passwordLimiter:      ratelimit.New(passwordRequestsPerIP, passwordRequestWindow),
	}
}

func (s *Server) ServeHttp(w http.ResponseWriter, r *http.Request) {
	s.Routes().ServeHTTP(w, r)
}
