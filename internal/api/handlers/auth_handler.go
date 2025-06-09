package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/eupneart/auth-service/internal/models"
	"github.com/eupneart/auth-service/internal/services"
	"github.com/eupneart/auth-service/utils"
)

type AuthHandler struct {
	UserService  *services.UserService
	TokenService services.TokenService
}

func NewAuthHandler(userService *services.UserService, tokenService services.TokenService) *AuthHandler {
	return &AuthHandler{
		UserService:  userService,
		TokenService: tokenService,
	}
}

func (h *AuthHandler) Authenticate(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := utils.ReadJSON(w, r, &requestPayload)
	if err != nil {
		slog.Error("failed to read JSON payload for authentication",
			"error", err,
			"method", "AuthHandler.Authenticate",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	// Validate input
	if requestPayload.Email == "" || requestPayload.Password == "" {
		slog.Warn("authentication attempt with missing credentials",
			"method", "AuthHandler.Authenticate",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("email and password are required"), http.StatusBadRequest)
		return
	}

	// validate the user against the database
	user, err := h.UserService.GetByEmail(context.Background(), requestPayload.Email)
	if err != nil {
		slog.Error("failed to get user by email during authentication",
			"error", err,
			"email", requestPayload.Email,
			"method", "AuthHandler.Authenticate",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("invalid credentials"), http.StatusUnauthorized)
		return
	}

	// Check if user is active
	if !user.IsActive {
		slog.Warn("authentication attempt for inactive user",
			"email", requestPayload.Email,
			"user_id", user.ID,
			"method", "AuthHandler.Authenticate",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("account is deactivated"), http.StatusUnauthorized)
		return
	}

	valid, err := h.UserService.PasswordMatches(user, requestPayload.Password)
	if err != nil {
		slog.Error("error checking password during authentication",
			"error", err,
			"email", requestPayload.Email,
			"method", "AuthHandler.Authenticate",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("invalid credentials"), http.StatusUnauthorized)
		return
	}

	if !valid {
		slog.Warn("invalid password attempt",
			"email", requestPayload.Email,
			"method", "AuthHandler.Authenticate",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("invalid credentials"), http.StatusUnauthorized)
		return
	}

	// Generate JWT tokens
	accessToken, refreshToken, err := h.TokenService.GenerateTokens(context.Background(), user)
	if err != nil {
		slog.Error("failed to generate tokens during authentication",
			"error", err,
			"email", user.Email,
			"user_id", user.ID,
			"method", "AuthHandler.Authenticate",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("failed to generate authentication tokens"), http.StatusInternalServerError)
		return
	}

	// Update user's last login timestamp
	user.LastLogin = time.Now()
	if err := h.UserService.Update(context.Background(), *user); err != nil {
		// Log error but don't fail the authentication
		slog.Warn("failed to update last login time",
			"error", err,
			"user_id", user.ID,
			"method", "AuthHandler.Authenticate")
	}

	slog.Info("user authenticated successfully",
		"email", user.Email,
		"user_id", user.ID,
		"method", "AuthHandler.Authenticate",
		"remote_addr", r.RemoteAddr)

	// Create token response following OAuth2/JWT standards
	tokenResponse := models.TokenResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		TokenType:        models.DefaultTokenType,
		ExpiresIn:        int64(models.DefaultAccessTokenLifetime.Seconds()),
		RefreshExpiresIn: int64(models.DefaultRefreshTokenLifetime.Seconds()),
	}

	// Create response payload
	payload := utils.JsonResponse{
		Error:   false,
		Message: fmt.Sprintf("Successfully authenticated user %s", user.Email),
		Data:    tokenResponse,
	}

	_ = utils.WriteJSON(w, payload, http.StatusOK)
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Password  string `json:"password"`
	}

	err := utils.ReadJSON(w, r, &requestPayload)
	if err != nil {
		slog.Error("failed to read JSON payload for registration",
			"error", err,
			"method", "AuthHandler.Register",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	// Validate input
	err = utils.ValidateRegistrationInput(
		requestPayload.FirstName,
		requestPayload.LastName,
		requestPayload.Email,
		requestPayload.Password,
	)
	if err != nil {
		slog.Warn("registration validation failed",
			"error", err.Error(),
			"method", "AuthHandler.Register",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	// Check if user already exists
	existingUser, err := h.UserService.GetByEmail(context.Background(), requestPayload.Email)
	if err == nil && existingUser != nil {
		slog.Warn("registration attempt with existing email",
			"email", requestPayload.Email,
			"method", "AuthHandler.Register",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("user with this email already exists"), http.StatusConflict)
		return
	}

	// Create user model
	usr := models.User{
		FirstName: requestPayload.FirstName,
		LastName:  requestPayload.LastName,
		Email:     requestPayload.Email,
		Password:  requestPayload.Password,
		Role:      "user", // Default role
		IsActive:  true,
	}

	newUserID, err := h.UserService.Insert(context.Background(), usr)
	if err != nil {
		slog.Error("failed to insert new user during registration",
			"error", err,
			"email", usr.Email,
			"first_name", usr.FirstName,
			"last_name", usr.LastName,
			"method", "AuthHandler.Register",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("failed to create user account"), http.StatusInternalServerError)
		return
	}

	// Get the created user to generate tokens
	newUser, err := h.UserService.GetByID(context.Background(), newUserID)
	if err != nil {
		slog.Error("failed to retrieve newly created user",
			"error", err,
			"user_id", newUserID,
			"method", "AuthHandler.Register",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("failed to complete user registration"), http.StatusInternalServerError)
		return
	}

	// Generate JWT tokens for the new user (auto-login after registration)
	accessToken, refreshToken, err := h.TokenService.GenerateTokens(context.Background(), newUser)
	if err != nil {
		slog.Error("failed to generate tokens during registration",
			"error", err,
			"email", newUser.Email,
			"user_id", newUser.ID,
			"method", "AuthHandler.Register",
			"remote_addr", r.RemoteAddr)
		// Don't fail registration, just log the user in manually later
		slog.Info("new user registered successfully (without auto-login)",
			"email", usr.Email,
			"user_id", newUserID,
			"first_name", usr.FirstName,
			"last_name", usr.LastName,
			"method", "AuthHandler.Register",
			"remote_addr", r.RemoteAddr)

		payload := utils.JsonResponse{
			Error:   false,
			Message: fmt.Sprintf("User registered successfully with email %s. Please log in.", usr.Email),
			Data:    map[string]interface{}{"user_id": newUserID},
		}
		_ = utils.WriteJSON(w, payload, http.StatusCreated)
		return
	}

	slog.Info("new user registered and authenticated successfully",
		"email", usr.Email,
		"user_id", newUserID,
		"first_name", usr.FirstName,
		"last_name", usr.LastName,
		"method", "AuthHandler.Register",
		"remote_addr", r.RemoteAddr)

	// Create token response for auto-login
	tokenResponse := models.TokenResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		TokenType:        models.DefaultTokenType,
		ExpiresIn:        int64(models.DefaultAccessTokenLifetime.Seconds()),
		RefreshExpiresIn: int64(models.DefaultRefreshTokenLifetime.Seconds()),
	}

	// Create response payload
	payload := utils.JsonResponse{
		Error:   false,
		Message: fmt.Sprintf("User registered and authenticated successfully with email %s", usr.Email),
		Data:    tokenResponse,
	}

	_ = utils.WriteJSON(w, payload, http.StatusCreated)
}
