package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	
	"github.com/eupneart/auth-service/internal/models"
	"github.com/eupneart/auth-service/internal/services"
	"github.com/eupneart/auth-service/utils"
)

type AuthHandler struct {
	UserService *services.UserService 
}

func NewAuthHandler(userService *services.UserService) *AuthHandler {
	return &AuthHandler{
		UserService: userService,
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

	// validate the user against the database
	user, err := h.UserService.GetByEmail(context.Background(), requestPayload.Email)
	if err != nil {
		slog.Error("failed to get user by email during authentication",
			"error", err,
			"email", requestPayload.Email,
			"method", "AuthHandler.Authenticate",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	valid, err := h.UserService.PasswordMatches(user, requestPayload.Password)
	if err != nil {
		slog.Error("error checking password during authentication",
			"error", err,
			"email", requestPayload.Email,
			"method", "AuthHandler.Authenticate",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}
	
	if !valid {
		slog.Warn("invalid password attempt",
			"email", requestPayload.Email,
			"method", "AuthHandler.Authenticate",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	slog.Info("user authenticated successfully",
		"email", user.Email,
		"user_id", user.ID,
		"method", "AuthHandler.Authenticate",
		"remote_addr", r.RemoteAddr)

	payload := utils.JsonResponse{
		Error:   false,
		Message: fmt.Sprintf("Logged in user %s", user.Email),
		// Data: user,
	}
	_ = utils.WriteJSON(w, payload, http.StatusAccepted)
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

	// validate the user against the database
	usr := models.User{
		FirstName: requestPayload.FirstName,
		LastName:  requestPayload.LastName,
		Email:     requestPayload.Email,
		Password:  requestPayload.Password,
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
		utils.ErrorJSON(w, errors.New("error inserting new user"), http.StatusServiceUnavailable)
		return
	}

	slog.Info("new user registered successfully",
		"email", usr.Email,
		"user_id", newUserID,
		"first_name", usr.FirstName,
		"last_name", usr.LastName,
		"method", "AuthHandler.Register",
		"remote_addr", r.RemoteAddr)

	payload := utils.JsonResponse{
		Error:   false,
		Message: fmt.Sprintf("New user registered with email %s", usr.Email),
		// Data: user, // TODO: Token
	}
	_ = utils.WriteJSON(w, payload, http.StatusAccepted)
}
