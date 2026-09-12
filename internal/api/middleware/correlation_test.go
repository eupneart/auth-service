package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eupneart/auth-service/internal/logging"
	"github.com/stretchr/testify/assert"
)

// correlationIDReaching serves req through the middleware and reports the id
// that reached the wrapped handler.
func correlationIDReaching(t *testing.T, req *http.Request) (string, *httptest.ResponseRecorder) {
	t.Helper()

	var seen string
	handler := CorrelationID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = logging.CorrelationIDFromContext(r.Context())
	}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return seen, w
}

func TestCorrelationIDUsesCallerSuppliedHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/authenticate", nil)
	req.Header.Set(CorrelationIDHeader, "probe-abc-123")

	seen, w := correlationIDReaching(t, req)

	assert.Equal(t, "probe-abc-123", seen)
	assert.Equal(t, "probe-abc-123", w.Header().Get(CorrelationIDHeader))
}

func TestCorrelationIDGeneratesWhenHeaderAbsent(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/authenticate", nil)

	seen, w := correlationIDReaching(t, req)

	assert.NotEmpty(t, seen)
	assert.Equal(t, seen, w.Header().Get(CorrelationIDHeader))
}

// A malformed id must never reach the logs verbatim, so it is replaced rather
// than passed through or dropped.
func TestCorrelationIDReplacesMalformedHeader(t *testing.T) {
	for name, header := range map[string]string{
		"forged entry": `abc" ,"level":"ERROR`,
		"over length":  strings.Repeat("a", 129),
		"empty":        "",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/authenticate", nil)
			req.Header.Set(CorrelationIDHeader, header)

			seen, w := correlationIDReaching(t, req)

			assert.NotEmpty(t, seen)
			assert.NotEqual(t, header, seen)
			assert.Equal(t, seen, w.Header().Get(CorrelationIDHeader))
		})
	}
}
