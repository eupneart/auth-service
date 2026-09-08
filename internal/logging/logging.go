// Package logging carries a correlation id through a request's context so that
// every log record emitted while serving that request can be tied back to it.
package logging

import (
	"context"
	"log/slog"
)

// CorrelationIDAttr is the log attribute key under which the correlation id is
// recorded.
const CorrelationIDAttr = "cid"

// maxCorrelationIDLen bounds a caller-supplied correlation id.
const maxCorrelationIDLen = 128

type contextKey struct{}

// WithCorrelationID returns a copy of ctx carrying id.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// CorrelationIDFromContext returns the correlation id carried by ctx, or an
// empty string when there is none.
func CorrelationIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(contextKey{}).(string)
	return id
}

// Sanitize returns id unchanged when it is safe to record, and an empty string
// otherwise.
//
// Correlation ids originate from the caller and are written straight to the
// logs, so only a bounded set of printable characters is accepted: an over-long
// or control-character-carrying id would let a caller bloat the logs or forge
// entries in consumers that do not parse the JSON.
func Sanitize(id string) string {
	if id == "" || len(id) > maxCorrelationIDLen {
		return ""
	}
	for i := 0; i < len(id); i++ {
		switch c := id[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.':
		default:
			return ""
		}
	}
	return id
}

// NewHandler wraps next so that every record logged with a context carrying a
// correlation id gains a CorrelationIDAttr attribute. Records logged without one
// pass through unchanged.
//
// The attribute is added at the record's current nesting, so a logger derived
// through WithGroup records it inside that group rather than at the top level.
func NewHandler(next slog.Handler) slog.Handler {
	return correlationHandler{Handler: next}
}

type correlationHandler struct {
	slog.Handler
}

func (h correlationHandler) Handle(ctx context.Context, record slog.Record) error {
	if id := CorrelationIDFromContext(ctx); id != "" {
		record.AddAttrs(slog.String(CorrelationIDAttr, id))
	}
	return h.Handler.Handle(ctx, record)
}

// WithAttrs and WithGroup re-wrap the derived handler; without them a logger
// built through slog.Logger.With would silently lose the correlation id.

func (h correlationHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return correlationHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h correlationHandler) WithGroup(name string) slog.Handler {
	return correlationHandler{Handler: h.Handler.WithGroup(name)}
}
