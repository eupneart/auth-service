package middleware

import (
	"log/slog"
	"net"
	"net/http"

	"github.com/eupneart/auth-service/pkg/ratelimit"
)

// RateLimit rejects requests from a source address that has exceeded the
// limiter's allowance.
//
// Clients are keyed by RemoteAddr rather than X-Forwarded-For: that header is
// set by the caller and there is no trusted-proxy configuration here, so
// honouring it would let an attacker reset their own counter at will. Behind a
// reverse proxy this therefore limits per proxy, and the proxy should carry its
// own per-client limit.
func RateLimit(limiter *ratelimit.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow(clientKey(r)) {
				slog.Warn("rate limit exceeded",
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr)
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
