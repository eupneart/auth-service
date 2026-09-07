package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/eupneart/auth-service/internal/models"
	"github.com/eupneart/auth-service/internal/repositories"
	"github.com/eupneart/auth-service/pkg/ratelimit"
	"github.com/eupneart/auth-service/utils"
)

var (
	ErrWeakPassword       = errors.New("password does not meet strength requirements")
	ErrInvalidResetToken  = errors.New("invalid password reset token")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// resetTokenBytes is the entropy of the opaque token handed to the user. The
// SHA-256 of its base64 encoding is what reaches the database, sized to the
// token_hash VARCHAR(64) column.
const resetTokenBytes = 32

// The resource protected here is the account holder's inbox, so the allowance
// is per address and independent of who asked. Source addresses are limited
// separately by the HTTP middleware.
const (
	resetRequestsPerEmail = 3
	resetRequestWindow    = 15 * time.Minute
)

type PasswordResetConfig struct {
	// BaseURL is the page that receives the token. It comes from configuration
	// only; deriving it from a request header would let an attacker redirect
	// reset links to a host they control.
	BaseURL       string
	TokenLifetime time.Duration
}

type PasswordResetService struct {
	config       PasswordResetConfig
	userService  *UserService
	userRepo     repositories.UserRepoInterface
	tokens       repositories.PasswordResetTokenStore
	sessions     TokenService
	mailer       PasswordResetMailer
	emailLimiter *ratelimit.Limiter
}

func NewPasswordResetService(
	config PasswordResetConfig,
	userService *UserService,
	userRepo repositories.UserRepoInterface,
	tokens repositories.PasswordResetTokenStore,
	sessions TokenService,
	mailer PasswordResetMailer,
) *PasswordResetService {
	return &PasswordResetService{
		config:       config,
		userService:  userService,
		userRepo:     userRepo,
		tokens:       tokens,
		sessions:     sessions,
		mailer:       mailer,
		emailLimiter: ratelimit.New(resetRequestsPerEmail, resetRequestWindow),
	}
}

// RequestReset issues a reset link for email when it belongs to an active
// account. Unknown and inactive addresses return nil rather than an error, so
// callers cannot distinguish them and neither can their clients. A non-nil
// error means the request genuinely failed, never that the account is absent.
func (s *PasswordResetService) RequestReset(ctx context.Context, email string) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		slog.Error("failed to look up user for password reset",
			"error", err,
			"method", "PasswordResetService.RequestReset")
		return fmt.Errorf("looking up user: %w", err)
	}

	if user == nil || !user.IsActive {
		slog.Info("password reset requested for unknown or inactive account",
			"method", "PasswordResetService.RequestReset")
		return nil
	}

	// Checked only once the account is known to exist, so the limiter's key
	// space stays bounded by real accounts rather than by attacker input.
	if !s.emailLimiter.Allow(user.Email) {
		slog.Warn("password reset requests throttled for account",
			"user_id", user.ID,
			"method", "PasswordResetService.RequestReset")
		return nil
	}

	rawToken, tokenHash, err := generateResetToken()
	if err != nil {
		return fmt.Errorf("generating reset token: %w", err)
	}

	token := &models.PasswordResetToken{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(s.config.TokenLifetime),
	}
	if err := s.tokens.CreatePasswordResetToken(ctx, token); err != nil {
		return fmt.Errorf("storing reset token: %w", err)
	}

	if err := s.mailer.SendPasswordReset(ctx, user.Email, s.resetURL(rawToken)); err != nil {
		slog.Error("failed to send password reset email",
			"error", err,
			"user_id", user.ID,
			"method", "PasswordResetService.RequestReset")
		return fmt.Errorf("sending reset link: %w", err)
	}

	slog.Info("password reset link sent",
		"user_id", user.ID,
		"method", "PasswordResetService.RequestReset")

	return nil
}

// ResetWithToken completes the forgotten-password flow. Missing, expired, and
// already-used tokens all surface as ErrInvalidResetToken so responses cannot
// distinguish them.
func (s *PasswordResetService) ResetWithToken(ctx context.Context, rawToken, newPassword string) error {
	// Checked before the token is consumed so a rejected password does not burn
	// the user's single-use link.
	if !utils.IsValidPassword(newPassword) {
		return ErrWeakPassword
	}

	if rawToken == "" {
		return ErrInvalidResetToken
	}

	token, err := s.tokens.ConsumePasswordResetToken(ctx, hashResetToken(rawToken))
	if err != nil {
		if errors.Is(err, repositories.ErrResetTokenNotFound) {
			return ErrInvalidResetToken
		}
		return fmt.Errorf("consuming reset token: %w", err)
	}

	return s.applyNewPassword(ctx, token.UserID, newPassword)
}

// ChangePassword completes the authenticated flow. userID must come from
// verified token claims, never from the request body.
func (s *PasswordResetService) ChangePassword(ctx context.Context, userID int64, currentPassword, newPassword string) error {
	if userID == 0 {
		return fmt.Errorf("user ID must be provided")
	}

	if !utils.IsValidPassword(newPassword) {
		return ErrWeakPassword
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("looking up user: %w", err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	matches, err := s.userService.PasswordMatches(user, currentPassword)
	if err != nil {
		return fmt.Errorf("verifying current password: %w", err)
	}
	if !matches {
		return ErrInvalidCredentials
	}

	return s.applyNewPassword(ctx, userID, newPassword)
}

// applyNewPassword performs the three writes of a password change in a fixed
// order, aborting on the first failure. There is no enclosing transaction, so
// the order is what carries the guarantee: updating the password last makes the
// dangerous partial state — new password accepted while old sessions stay
// valid — unreachable. Every earlier failure leaves the old password intact.
func (s *PasswordResetService) applyNewPassword(ctx context.Context, userID int64, newPassword string) error {
	if err := s.sessions.RevokeAllTokensForUser(ctx, userID); err != nil {
		return fmt.Errorf("revoking sessions: %w", err)
	}

	if err := s.tokens.InvalidatePasswordResetTokensForUser(ctx, userID); err != nil {
		return fmt.Errorf("invalidating outstanding reset tokens: %w", err)
	}

	if err := s.userService.ResetPassword(ctx, &models.User{ID: userID, Password: newPassword}); err != nil {
		return fmt.Errorf("updating password: %w", err)
	}

	slog.Info("password changed and sessions revoked",
		"user_id", userID,
		"method", "PasswordResetService.applyNewPassword")

	return nil
}

// ========================= Helper functions ============================

func (s *PasswordResetService) resetURL(rawToken string) string {
	return fmt.Sprintf("%s?token=%s",
		strings.TrimRight(s.config.BaseURL, "/?"),
		url.QueryEscape(rawToken))
}

// generateResetToken returns the opaque token to email and the hash to store.
// The raw value exists only in the caller's memory and the outgoing message.
func generateResetToken() (rawToken, tokenHash string, err error) {
	buf := make([]byte, resetTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}

	rawToken = base64.RawURLEncoding.EncodeToString(buf)
	return rawToken, hashResetToken(rawToken), nil
}

func hashResetToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}
