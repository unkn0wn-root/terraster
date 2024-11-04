package middleware

import (
	"crypto/subtle"
	"net/http"

	"github.com/unkn0wn-root/go-load-balancer/internal/config"
)

type AuthMiddleware struct {
	apiKey string
}

func NewAuthMiddleware(config config.AuthConfig) Middleware {
	return &AuthMiddleware{
		apiKey: config.APIKey,
	}
}

func (m *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.authenticate(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *AuthMiddleware) authenticate(r *http.Request) bool {
	return m.validateAPIKey(r)
}

func (m *AuthMiddleware) validateAPIKey(r *http.Request) bool {
	key := r.Header.Get("X-API-Key")
	return subtle.ConstantTimeCompare([]byte(key), []byte(m.apiKey)) == 1
}
