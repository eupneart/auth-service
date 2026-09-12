package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// captureDefaultLogger redirects the package-level slog logger, which Logging
// writes to, and restores it when the test ends.
func captureDefaultLogger(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	return &buf
}

// completionRecord returns the "request completed" entry written by Logging.
func completionRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()

	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if record["msg"] == "request completed" {
			return record
		}
	}

	t.Fatal("no \"request completed\" record was logged")
	return nil
}

func TestResponseWriterCapturesStatusAndSize(t *testing.T) {
	recorder := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: recorder, statusCode: http.StatusOK}

	rw.WriteHeader(http.StatusTeapot)
	first, err := rw.Write([]byte("hello "))
	assert.NoError(t, err)
	second, err := rw.Write([]byte("world"))
	assert.NoError(t, err)

	assert.Equal(t, http.StatusTeapot, rw.statusCode)
	assert.Equal(t, 6, first)
	assert.Equal(t, 5, second)
	assert.Equal(t, 11, rw.size)
	assert.Equal(t, http.StatusTeapot, recorder.Code)
	assert.Equal(t, "hello world", recorder.Body.String())
}

func TestLoggingRecordsRequestAndResponse(t *testing.T) {
	buf := captureDefaultLogger(t)

	handler := Logging(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("body"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	record := completionRecord(t, buf)
	assert.Equal(t, "INFO", record["level"])
	assert.Equal(t, http.MethodGet, record["method"])
	assert.EqualValues(t, http.StatusOK, record["status"])
	assert.EqualValues(t, 4, record["response_size"])
	assert.Contains(t, buf.String(), "incoming request")
}

// A handler that never calls WriteHeader still returns 200, so the wrapper has
// to report that rather than a zero status.
func TestLoggingReportsOKWhenHandlerNeverWritesHeader(t *testing.T) {
	buf := captureDefaultLogger(t)

	handler := Logging(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ping", nil))

	assert.EqualValues(t, http.StatusOK, completionRecord(t, buf)["status"])
}

func TestLoggingLevelFollowsStatusCode(t *testing.T) {
	testCases := []struct {
		name   string
		status int
		level  string
	}{
		{"success is info", http.StatusOK, "INFO"},
		{"redirect is info", http.StatusFound, "INFO"},
		{"client error is warn", http.StatusUnauthorized, "WARN"},
		{"last client error is warn", http.StatusUnavailableForLegalReasons, "WARN"},
		{"server error is error", http.StatusInternalServerError, "ERROR"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureDefaultLogger(t)

			handler := Logging(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ping", nil))

			record := completionRecord(t, buf)
			assert.Equal(t, tc.level, record["level"])
			assert.EqualValues(t, tc.status, record["status"])
		})
	}
}
