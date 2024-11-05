package middleware

import (
	"net"
	"net/http"
)

type ServerHostMiddleware struct{}

func NewServerHostMiddleware() *ServerHostMiddleware {
	return &ServerHostMiddleware{}
}

func (s *ServerHostMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if host, _, err := net.SplitHostPort(r.Host); err == nil {
			r.Host = host
		}

		next.ServeHTTP(w, r)
	})
}
