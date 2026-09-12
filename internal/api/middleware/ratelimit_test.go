package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eupneart/auth-service/pkg/ratelimit"
	"github.com/stretchr/testify/assert"
)

func TestRateLimitAllowsRequestsUnderTheLimit(t *testing.T) {
	handler := RateLimit(ratelimit.New(2, time.Minute))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/password/forgot", nil)
		req.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	}
}

func TestRateLimitRejectsOnceTheLimitIsReached(t *testing.T) {
	handlerCalls := 0
	handler := RateLimit(ratelimit.New(1, time.Minute))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalls++
		w.WriteHeader(http.StatusNoContent)
	}))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/password/forgot", nil)
		req.RemoteAddr = "192.0.2.1:1234"
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	req := httptest.NewRequest(http.MethodPost, "/password/forgot", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "too many requests")
	assert.Equal(t, 1, handlerCalls)
}

// Clients are keyed by host, so a client cannot reset its allowance by opening a
// new connection from a different source port.
func TestRateLimitKeysByHostIgnoringPort(t *testing.T) {
	handler := RateLimit(ratelimit.New(1, time.Minute))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRequest(http.MethodPost, "/password/forgot", nil)
	first.RemoteAddr = "192.0.2.1:1111"
	firstResponse := httptest.NewRecorder()
	handler.ServeHTTP(firstResponse, first)

	second := httptest.NewRequest(http.MethodPost, "/password/forgot", nil)
	second.RemoteAddr = "192.0.2.1:2222"
	secondResponse := httptest.NewRecorder()
	handler.ServeHTTP(secondResponse, second)

	assert.Equal(t, http.StatusNoContent, firstResponse.Code)
	assert.Equal(t, http.StatusTooManyRequests, secondResponse.Code)
}

// X-Forwarded-For is attacker-controlled and deliberately not consulted, so it
// must not create a separate allowance.
func TestRateLimitIgnoresForwardedForHeader(t *testing.T) {
	handler := RateLimit(ratelimit.New(1, time.Minute))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRequest(http.MethodPost, "/password/forgot", nil)
	first.RemoteAddr = "192.0.2.1:1111"
	handler.ServeHTTP(httptest.NewRecorder(), first)

	second := httptest.NewRequest(http.MethodPost, "/password/forgot", nil)
	second.RemoteAddr = "192.0.2.1:1111"
	second.Header.Set("X-Forwarded-For", "198.51.100.7")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, second)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestRateLimitSeparatesDistinctHosts(t *testing.T) {
	handler := RateLimit(ratelimit.New(1, time.Minute))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRequest(http.MethodPost, "/password/forgot", nil)
	first.RemoteAddr = "192.0.2.1:1111"
	firstResponse := httptest.NewRecorder()
	handler.ServeHTTP(firstResponse, first)

	second := httptest.NewRequest(http.MethodPost, "/password/forgot", nil)
	second.RemoteAddr = "192.0.2.2:1111"
	secondResponse := httptest.NewRecorder()
	handler.ServeHTTP(secondResponse, second)

	assert.Equal(t, http.StatusNoContent, firstResponse.Code)
	assert.Equal(t, http.StatusNoContent, secondResponse.Code)
}

func TestClientKey(t *testing.T) {
	testCases := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"host and port", "192.0.2.1:1234", "192.0.2.1"},
		{"ipv6 host and port", "[2001:db8::1]:1234", "2001:db8::1"},
		{"no port falls back to the raw address", "192.0.2.1", "192.0.2.1"},
		{"empty address", "", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ping", nil)
			req.RemoteAddr = tc.remoteAddr

			assert.Equal(t, tc.want, clientKey(req))
		})
	}
}
