package handlers

import (
	"context"
	"errors"
	"fmt"
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
		Email string `json:"email"`
		Password string `json:"password"`
	}

	err := utils.ReadJSON(w, r, &requestPayload)
	if err != nil {
		utils.ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	// validate the user against the database
	user, err := h.UserService.GetByEmail(context.Background(), requestPayload.Email)
	if err != nil {
		utils.ErrorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	valid, err := h.UserService.PasswordMatches(user, requestPayload.Password)
	if err != nil || !valid {
    utils.ErrorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	payload := utils.JsonResponse {
		Error: false,
		Message: fmt.Sprintf("Logged in user %s", user.Email),
		// Data: user,
	}

  _ = utils.WriteJSON(w, payload, http.StatusAccepted)
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
  var requestPayload struct {
		FirstName string `json:"first_name"`
		LastName string `json:"last_name"`
		Email string `json:"email"`
		Password string `json:"password"`
	}

	err := utils.ReadJSON(w, r, &requestPayload)
	if err != nil {
		utils.ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	// validate the user against the database
  usr := models.User{
    FirstName: requestPayload.FirstName,
    LastName: requestPayload.LastName,
    Email: requestPayload.Email,
    Password: requestPayload.Password,
    IsActive: true,
  }

	_, err = h.UserService.Insert(context.Background(), usr)
	if err != nil {
		utils.ErrorJSON(w, errors.New("error inserting new user"), http.StatusServiceUnavailable)
		return
	}

	payload := utils.JsonResponse {
		Error: false,
		Message: fmt.Sprintf("New user registered with email %s", usr.Email),
    // Data: user, // TODO: Token
	}

  _ = utils.WriteJSON(w, payload, http.StatusAccepted)

}
