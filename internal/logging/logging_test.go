package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(NewHandler(slog.NewJSONHandler(&buf, nil))), &buf
}

func loggedRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))
	return record
}

func TestHandlerRecordsCorrelationIDFromContext(t *testing.T) {
	logger, buf := testLogger()

	logger.InfoContext(WithCorrelationID(context.Background(), "probe-abc-123"), "hello")

	assert.Equal(t, "probe-abc-123", loggedRecord(t, buf)[CorrelationIDAttr])
}

func TestHandlerOmitsAttributeWithoutCorrelationID(t *testing.T) {
	logger, buf := testLogger()

	logger.InfoContext(context.Background(), "hello")

	assert.NotContains(t, loggedRecord(t, buf), CorrelationIDAttr)
}

// A logger derived with With must keep stamping the id: slog.Logger.With calls
// through to Handler.WithAttrs, which would otherwise return the unwrapped
// handler.
func TestHandlerSurvivesDerivedLoggers(t *testing.T) {
	logger, buf := testLogger()

	logger.With("component", "auth").
		InfoContext(WithCorrelationID(context.Background(), "probe-abc-123"), "hello")

	record := loggedRecord(t, buf)
	assert.Equal(t, "probe-abc-123", record[CorrelationIDAttr])
	assert.Equal(t, "auth", record["component"])
}

func TestSanitize(t *testing.T) {
	atLimit := strings.Repeat("a", maxCorrelationIDLen)

	testCases := []struct {
		name string
		id   string
		want string
	}{
		{"accepts a gateway id", "probe-abc-123", "probe-abc-123"},
		{"accepts a uuid", "9f1c2b3a-4d5e-6f70-8a9b-0c1d2e3f4a5b", "9f1c2b3a-4d5e-6f70-8a9b-0c1d2e3f4a5b"},
		{"accepts dots and underscores", "svc.gateway_01", "svc.gateway_01"},
		{"accepts the maximum length", atLimit, atLimit},
		{"rejects empty", "", ""},
		{"rejects over the maximum length", atLimit + "a", ""},
		{"rejects newlines", "abc\nforged entry", ""},
		{"rejects spaces", "abc 123", ""},
		{"rejects quotes", `abc"123`, ""},
		{"rejects non-ascii", "abcé", ""},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Sanitize(tc.id))
		})
	}
}
