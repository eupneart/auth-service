package mail

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileMailerWritesRecipientAndURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailbox.txt")

	require.NoError(t, NewFileMailer(path).SendPasswordReset(
		context.Background(), "user@example.com", "https://app.example.com/reset-password?token=raw-token"))

	contents, err := os.ReadFile(path)
	require.NoError(t, err)

	fields := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\t")
	require.Len(t, fields, 3)

	_, err = time.Parse(time.RFC3339, fields[0])
	assert.NoError(t, err)
	assert.Equal(t, "user@example.com", fields[1])
	assert.Equal(t, "https://app.example.com/reset-password?token=raw-token", fields[2])
}

func TestFileMailerAppendsToExistingMailbox(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailbox.txt")
	mailer := NewFileMailer(path)

	require.NoError(t, mailer.SendPasswordReset(context.Background(), "first@example.com", "https://app.example.com/a"))
	require.NoError(t, mailer.SendPasswordReset(context.Background(), "second@example.com", "https://app.example.com/b"))

	contents, err := os.ReadFile(path)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "first@example.com")
	assert.Contains(t, lines[1], "second@example.com")
}

// The mailbox holds live reset links, so it must not be readable by other users
// on the machine.
func TestFileMailerCreatesMailboxUnreadableByOthers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailbox.txt")

	require.NoError(t, NewFileMailer(path).SendPasswordReset(
		context.Background(), "user@example.com", "https://app.example.com/reset"))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestFileMailerReportsOpenFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-directory", "mailbox.txt")

	err := NewFileMailer(path).SendPasswordReset(
		context.Background(), "user@example.com", "https://app.example.com/reset")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "opening dev mailbox")
}
