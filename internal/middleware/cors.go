package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/unkn0wn-root/terraster/internal/config"
)

type CORS struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int
}

// Initializes and returns a new CORS instance based on the provided configuration.
func NewCORSMiddleware(cfg *config.Terraster) *CORS {
	var config *config.CORS
	for _, mw := range cfg.Middleware {
		if mw.CORS != nil {
			config = mw.CORS
			break
		}
	}

	if config == nil {
		return nil
	}

	return &CORS{
		AllowedOrigins:   config.AllowedOrigins,
		AllowedMethods:   config.AllowedMethods,
		AllowedHeaders:   config.AllowedHeaders,
		ExposedHeaders:   config.ExposedHeaders,
		AllowCredentials: config.AllowCredentials,
		MaxAge:           config.MaxAge,
	}
}

// Middleware is an HTTP middleware that sets CORS headers on incoming HTTP responses.
// Manages Cross-Origin Resource Sharing settings based on the CORS configuration.
func (c *CORS) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(c.AllowedOrigins) > 0 {
			if len(c.AllowedOrigins) == 1 && c.AllowedOrigins[0] == "*" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", strings.Join(c.AllowedOrigins, ","))
			}
		}

		if len(c.AllowedMethods) > 0 {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(c.AllowedMethods, ","))
		}

		if len(c.AllowedHeaders) > 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(c.AllowedHeaders, ","))
		}

		if len(c.ExposedHeaders) > 0 {
			w.Header().Set("Access-Control-Expose-Headers", strings.Join(c.ExposedHeaders, ","))
		}

		if c.AllowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if c.MaxAge > 0 {
			w.Header().Set("Access-Control-Max-Age", strconv.Itoa(c.MaxAge))
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
