package config

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/eupneart/auth-service/internal/models"
)

func (app *Config) Authenticate(w http.ResponseWriter, r *http.Request) {
  var requestPayload struct {
		Email string `json:"email"`
		Password string `json:"password"`
	}

	err := app.ReadJSON(w, r, &requestPayload)
	if err != nil {
		app.ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	// validate the user against the database
	user, err := app.UserService.GetByEmail(context.Background(), requestPayload.Email)
	if err != nil {
		app.ErrorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	valid, err := app.UserService.PasswordMatches(user, requestPayload.Password)
	if err != nil || !valid {
    app.ErrorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	payload := JsonResponse {
		Error: false,
		Message: fmt.Sprintf("Logged in user %s", user.Email),
		// Data: user,
	}

  _ = app.WriteJSON(w, payload, http.StatusAccepted)
}

func (app *Config) Register(w http.ResponseWriter, r *http.Request) {
  var requestPayload struct {
		FirstName string `json:"first_name"`
		LastName string `json:"last_name"`
		Email string `json:"email"`
		Password string `json:"password"`
	}

	err := app.ReadJSON(w, r, &requestPayload)
	if err != nil {
		app.ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	// validate the user against the database
  usr := models.User{
    FirstName: requestPayload.FirstName,
    LastName: requestPayload.LastName,
    Email: requestPayload.Email,
    Password: requestPayload.Password,
    Active: nil, // TODO
  }

	_, err = app.UserService.Insert(context.Background(), usr)
	if err != nil {
		app.ErrorJSON(w, errors.New("error inserting new user"), http.StatusServiceUnavailable)
		return
	}

	payload := JsonResponse {
		Error: false,
		Message: fmt.Sprintf("New user registered with email %s", usr.Email),
    // Data: user, // TODO: Token
	}

  _ = app.WriteJSON(w, payload, http.StatusAccepted)

}
