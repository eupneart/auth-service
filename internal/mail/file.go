package mail

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// FileMailer appends reset links to a local file instead of sending email, so
// the recovery flow can be exercised in development. It must never be used in
// production: the file holds live credentials in plain text.
type FileMailer struct {
	path string
	mu   sync.Mutex
}

func NewFileMailer(path string) *FileMailer {
	return &FileMailer{path: path}
}

func (m *FileMailer) SendPasswordReset(ctx context.Context, recipient, resetURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	f, err := os.OpenFile(m.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening dev mailbox: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "%s\t%s\t%s\n", time.Now().Format(time.RFC3339), recipient, resetURL); err != nil {
		return fmt.Errorf("writing dev mailbox: %w", err)
	}

	return nil
}
