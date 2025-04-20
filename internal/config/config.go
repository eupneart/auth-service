package config

import (
	"github.com/eupneart/auth-service/env"
	"github.com/eupneart/auth-service/internal/services"
)

type Config struct {
  Settings *env.EnvConfig
  UserService *services.UserService
}

func New(settings *env.EnvConfig, userService *services.UserService) *Config {
	return &Config{
		Settings:    settings,
		UserService: userService,
	}
}
