package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAllowedOriginsDefaultsToLocalhost(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "")

	assert.Equal(t, []string{
		"http://localhost:3000",
		"http://localhost:4200",
		"http://localhost:8080",
	}, getAllowedOrigins())
}

func TestGetAllowedOriginsReadsEnvironment(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com,https://admin.example.com")

	assert.Equal(t, []string{"https://app.example.com", "https://admin.example.com"}, getAllowedOrigins())
}

func TestIsOriginAllowed(t *testing.T) {
	allowed := []string{"https://app.example.com", " https://admin.example.com "}

	testCases := []struct {
		name   string
		origin string
		want   bool
	}{
		{"exact match", "https://app.example.com", true},
		{"entry padded with whitespace", "https://admin.example.com", true},
		{"origin not in the list", "https://evil.example.com", false},
		{"empty origin", "", false},
		{"prefix of an allowed origin", "https://app.example.co", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isOriginAllowed(tc.origin, allowed))
		})
	}
}

func TestCORSEchoesAllowedOrigin(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com")

	handler := CORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

// An origin outside the configured list must not be echoed back, otherwise the
// browser would treat any site as same-origin for credentialed requests.
func TestCORSOmitsOriginHeaderForUnknownOrigin(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com")

	handler := CORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}

func TestCORSSetsStaticHeaders(t *testing.T) {
	handler := CORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "GET, POST, PUT, DELETE, OPTIONS, PATCH", w.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type, Authorization, X-Requested-With", w.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "86400", w.Header().Get("Access-Control-Max-Age"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSAnswersPreflightWithoutCallingNext(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com")

	handlerCalled := false
	handler := CORS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handlerCalled = true
	}))

	req := httptest.NewRequest(http.MethodOptions, "/register", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, handlerCalled)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
}
