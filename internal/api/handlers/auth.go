package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/eupneart/auth-service/internal/api/middleware"
	"github.com/eupneart/auth-service/internal/models"
	"github.com/eupneart/auth-service/internal/services"
	"github.com/eupneart/auth-service/utils"
)

// forgotPasswordTimeout bounds the detached work started by ForgotPassword,
// which outlives the request context.
const forgotPasswordTimeout = 30 * time.Second

type AuthHandler struct {
	UserService          *services.UserService
	TokenService         services.TokenService
	PasswordResetService *services.PasswordResetService
}

func NewAuthHandler(userService *services.UserService, tokenService services.TokenService, passwordResetService *services.PasswordResetService) *AuthHandler {
	return &AuthHandler{
		UserService:          userService,
		TokenService:         tokenService,
		PasswordResetService: passwordResetService,
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

	// Validate email format
	if !utils.IsValidEmail(requestPayload.Email) {
		slog.Warn("authentication attempt with invalid email format",
			"email", requestPayload.Email,
			"method", "AuthHandler.Authenticate",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("invalid email format"), http.StatusBadRequest)
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

	if user == nil {
		slog.Error("retrieved user is nil",
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
		// Log error but don't fail the authentication (non-critical operation)
		slog.Error("failed to update last login time (non-critical)",
			"error", err,
			"user_id", user.ID,
			"email", user.Email,
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

	if newUser == nil {
		slog.Error("retrieved user is nil after creation",
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

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var requestPayload models.RefreshTokenRequest
	if err := utils.ReadJSON(w, r, &requestPayload); err != nil {
		utils.ErrorJSON(w, err, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(requestPayload.RefreshToken) == "" {
		utils.ErrorJSON(w, errors.New("refresh token required"), http.StatusBadRequest)
		return
	}

	accessToken, err := h.TokenService.RefreshAccessToken(r.Context(), requestPayload.RefreshToken)
	if err != nil {
		slog.Warn("token refresh failed", "error", err, "remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("invalid refresh token"), http.StatusUnauthorized)
		return
	}

	payload := utils.JsonResponse{
		Error:   false,
		Message: "Token refreshed successfully",
		Data: map[string]any{
			"access_token": accessToken,
			"token_type":   models.DefaultTokenType,
			"expires_in":   int64(models.DefaultAccessTokenLifetime.Seconds()),
		},
	}
	_ = utils.WriteJSON(w, payload, http.StatusOK)
}

func (h *AuthHandler) Validate(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		Token string `json:"token"`
	}
	if err := utils.ReadJSON(w, r, &requestPayload); err != nil {
		utils.ErrorJSON(w, err, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(requestPayload.Token) == "" {
		utils.ErrorJSON(w, errors.New("token required"), http.StatusBadRequest)
		return
	}

	claims, err := h.TokenService.ValidateToken(r.Context(), requestPayload.Token)
	if err != nil {
		payload := utils.JsonResponse{
			Error:   false,
			Message: "Token validation result",
			Data: models.TokenValidationResponse{
				Valid: false,
				Error: err.Error(),
			},
		}
		_ = utils.WriteJSON(w, payload, http.StatusOK)
		return
	}

	validationResponse := models.TokenValidationResponse{
		Valid:  true,
		Claims: claims,
	}
	if claims.ExpiresAt != nil {
		validationResponse.ExpiresAt = claims.ExpiresAt.Time
	}

	payload := utils.JsonResponse{
		Error:   false,
		Message: "Token is valid",
		Data:    validationResponse,
	}
	_ = utils.WriteJSON(w, payload, http.StatusOK)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	token, err := middleware.GetTokenFromContext(r)
	if err != nil {
		utils.ErrorJSON(w, err, http.StatusUnauthorized)
		return
	}

	if err := h.TokenService.RevokeToken(r.Context(), token); err != nil {
		slog.Error("failed to revoke token during logout", "error", err)
		utils.ErrorJSON(w, errors.New("failed to logout"), http.StatusInternalServerError)
		return
	}

	payload := utils.JsonResponse{Error: false, Message: "Successfully logged out"}
	_ = utils.WriteJSON(w, payload, http.StatusOK)
}

// forgotPasswordMessage is returned for every well-formed request, whether the
// address is unknown, inactive, or active. Callers must not be able to tell the
// cases apart.
const forgotPasswordMessage = "If an account exists for that address, a reset link has been sent."

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		Email string `json:"email"`
	}

	if err := utils.ReadJSON(w, r, &requestPayload); err != nil {
		utils.ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	// Format is client-checkable, so rejecting it leaks nothing about accounts.
	if !utils.IsValidEmail(requestPayload.Email) {
		utils.ErrorJSON(w, errors.New("invalid email format"), http.StatusBadRequest)
		return
	}

	// Responding before doing the work keeps the response time independent of
	// whether the account exists; otherwise the lookup, token insert and mail
	// send would make existing addresses measurably slower. The request context
	// is not reused because it is cancelled as soon as this handler returns.
	go func(email string) {
		// No HTTP middleware can recover a panic raised off the request
		// goroutine, so an unguarded one here would take down the process.
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.Error("password reset request panicked",
					"panic", recovered,
					"method", "AuthHandler.ForgotPassword")
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), forgotPasswordTimeout)
		defer cancel()

		if err := h.PasswordResetService.RequestReset(ctx, email); err != nil {
			slog.Error("failed to process password reset request",
				"error", err,
				"method", "AuthHandler.ForgotPassword")
		}
	}(requestPayload.Email)

	payload := utils.JsonResponse{Error: false, Message: forgotPasswordMessage}
	_ = utils.WriteJSON(w, payload, http.StatusAccepted)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}

	if err := utils.ReadJSON(w, r, &requestPayload); err != nil {
		utils.ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	if requestPayload.Token == "" || requestPayload.NewPassword == "" {
		utils.ErrorJSON(w, errors.New("token and new_password are required"), http.StatusBadRequest)
		return
	}

	err := h.PasswordResetService.ResetWithToken(r.Context(), requestPayload.Token, requestPayload.NewPassword)

	switch {
	case err == nil:
	case errors.Is(err, services.ErrWeakPassword):
		utils.ErrorJSON(w, err, http.StatusBadRequest)
		return
	case errors.Is(err, services.ErrInvalidResetToken):
		// Missing, expired and already-used tokens share this response so it
		// cannot be used to probe which links exist.
		slog.Warn("password reset attempted with an unusable token",
			"method", "AuthHandler.ResetPassword",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("invalid or expired reset token"), http.StatusBadRequest)
		return
	default:
		slog.Error("failed to reset password",
			"error", err,
			"method", "AuthHandler.ResetPassword")
		utils.ErrorJSON(w, errors.New("failed to reset password"), http.StatusInternalServerError)
		return
	}

	// No tokens are issued here: the user must sign in with the new password.
	payload := utils.JsonResponse{
		Error:   false,
		Message: "Password reset successfully. Please sign in with your new password.",
	}
	_ = utils.WriteJSON(w, payload, http.StatusOK)
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	// The user is taken from verified claims; a user ID in the body would let a
	// caller change someone else's password.
	claims := middleware.GetClaimsFromContext(r)
	if claims == nil {
		utils.ErrorJSON(w, errors.New("claims not found in context"), http.StatusUnauthorized)
		return
	}

	var requestPayload struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := utils.ReadJSON(w, r, &requestPayload); err != nil {
		slog.Error("failed to read JSON payload for password change",
			"error", err,
			"user_id", claims.UserID,
			"method", "AuthHandler.ChangePassword",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	if requestPayload.CurrentPassword == "" || requestPayload.NewPassword == "" {
		utils.ErrorJSON(w, errors.New("current_password and new_password are required"), http.StatusBadRequest)
		return
	}

	err := h.PasswordResetService.ChangePassword(r.Context(), claims.UserID,
		requestPayload.CurrentPassword, requestPayload.NewPassword)

	switch {
	case err == nil:
	case errors.Is(err, services.ErrWeakPassword):
		utils.ErrorJSON(w, err, http.StatusBadRequest)
		return
	case errors.Is(err, services.ErrInvalidCredentials):
		slog.Warn("password change attempt with incorrect current password",
			"user_id", claims.UserID,
			"method", "AuthHandler.ChangePassword",
			"remote_addr", r.RemoteAddr)
		utils.ErrorJSON(w, errors.New("current password is incorrect"), http.StatusUnauthorized)
		return
	default:
		slog.Error("failed to change password",
			"error", err,
			"user_id", claims.UserID,
			"method", "AuthHandler.ChangePassword")
		utils.ErrorJSON(w, errors.New("failed to change password"), http.StatusInternalServerError)
		return
	}

	slog.Info("password changed",
		"user_id", claims.UserID,
		"method", "AuthHandler.ChangePassword",
		"remote_addr", r.RemoteAddr)

	payload := utils.JsonResponse{
		Error:   false,
		Message: "Password changed successfully. All sessions have been signed out.",
	}
	_ = utils.WriteJSON(w, payload, http.StatusOK)
}

func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaimsFromContext(r)
	if claims == nil {
		utils.ErrorJSON(w, errors.New("claims not found in context"), http.StatusUnauthorized)
		return
	}

	user, err := h.UserService.GetByID(r.Context(), claims.UserID)
	if err != nil || user == nil {
		utils.ErrorJSON(w, errors.New("user not found"), http.StatusNotFound)
		return
	}
	if !user.IsActive {
		utils.ErrorJSON(w, errors.New("user account is inactive"), http.StatusUnauthorized)
		return
	}

	payload := utils.JsonResponse{
		Error:   false,
		Message: "User retrieved successfully",
		Data:    user,
	}
	_ = utils.WriteJSON(w, payload, http.StatusOK)
}
