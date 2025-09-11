package trace

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// ContextKey is a custom type for context keys to avoid collisions.
type ContextKey string

const RequestIDKey ContextKey = "request_id"

type RequestID struct{}

func WithRequestID() *RequestID {
	return &RequestID{}
}

// Middleware generates a unique request ID for each incoming HTTP request,
// stores it in the context, and sets it in the response headers.
func (r *RequestID) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRequestID retrieves the request ID from the context.
func GetRequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if reqID, ok := ctx.Value(RequestIDKey).(string); ok {
		return reqID
	}
	return ""
}
