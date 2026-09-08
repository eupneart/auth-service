package middleware

import (
	"net/http"

	"github.com/eupneart/auth-service/internal/logging"
	"github.com/google/uuid"
)

// CorrelationIDHeader carries the correlation id on both the request and the
// response.
const CorrelationIDHeader = "X-Request-Id"

// CorrelationID puts a correlation id into the request context so that every log
// record emitted while serving the request carries it.
//
// An id supplied by the caller is preferred, so these logs join with the
// caller's own. A missing or malformed one is replaced by a generated id rather
// than dropped, so that no request is left untraceable and every record has the
// same shape.
func CorrelationID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := logging.Sanitize(r.Header.Get(CorrelationIDHeader))
		if id == "" {
			id = uuid.NewString()
		}

		w.Header().Set(CorrelationIDHeader, id)
		next.ServeHTTP(w, r.WithContext(logging.WithCorrelationID(r.Context(), id)))
	})
}
