package models

import "time"

// PasswordResetToken is a one-time credential for the forgotten-password flow.
// Only the SHA-256 hash of the opaque token is persisted; the raw token is
// emailed to the user and never stored.
type PasswordResetToken struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"user_id"`
	TokenHash  string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}
