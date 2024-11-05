package middleware

import (
	"context"
	"net"
	"net/http"
)

type ctxKey string

const TargetHost ctxKey = "target_host"

type ServerHostMiddleware struct{}

func NewServerHostMiddleware() *ServerHostMiddleware {
	return &ServerHostMiddleware{}
}

func (m *ServerHostMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostname := r.Host
		if host, _, err := net.SplitHostPort(r.Host); err == nil {
			hostname = host
		}

		ctx := context.WithValue(r.Context(), TargetHost, hostname)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetTargetHost(r *http.Request) string {
	return r.Context().Value(TargetHost).(string)
}
