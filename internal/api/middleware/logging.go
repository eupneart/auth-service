package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// ResponseWriter wraps http.ResponseWriter to capture status code and response size
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// Logging middleware logs HTTP requests and responses
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// Wrap the response writer to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Log request
		slog.DebugContext(r.Context(), "incoming request",
			"method", r.Method,
			"path", r.RequestURI,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent())

		// Call the next handler
		next.ServeHTTP(rw, r)

		// Calculate duration
		duration := time.Since(startTime)

		// Log response
		level := slog.LevelInfo
		if rw.statusCode >= 400 && rw.statusCode < 500 {
			level = slog.LevelWarn
		} else if rw.statusCode >= 500 {
			level = slog.LevelError
		}

		slog.Log(r.Context(), level, "request completed",
			"method", r.Method,
			"path", r.RequestURI,
			"status", rw.statusCode,
			"duration_ms", duration.Milliseconds(),
			"response_size", rw.size,
			"remote_addr", r.RemoteAddr)
	})
}
