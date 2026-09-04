package middleware

import (
	"net/http"
	"os"
	"strings"
)

// CORS configures Cross-Origin Resource Sharing
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get allowed origins from environment or use defaults
		allowedOrigins := getAllowedOrigins()

		origin := r.Header.Get("Origin")
		if isOriginAllowed(origin, allowedOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getAllowedOrigins returns the list of allowed origins from environment
func getAllowedOrigins() []string {
	originsStr := os.Getenv("CORS_ALLOWED_ORIGINS")
	if originsStr == "" {
		// Default to localhost origins for development
		return []string{
			"http://localhost:3000",
			"http://localhost:4200",
			"http://localhost:8080",
		}
	}
	return strings.Split(originsStr, ",")
}

// isOriginAllowed checks if the given origin is in the allowed list
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	if origin == "" {
		return false
	}

	for _, allowed := range allowedOrigins {
		if strings.TrimSpace(allowed) == origin {
			return true
		}
	}
	return false
}
