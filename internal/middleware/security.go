package middleware

import (
	"fmt"
	"net/http"
)

type SecurityConfig struct {
	HSTS                  bool
	HSTSMaxAge            int
	HSTSIncludeSubDomains bool
	HSTSPreload           bool
	FrameOptions          string
	ContentTypeOptions    bool
	XSSProtection         bool
}

func SecurityMiddleware(config SecurityConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if config.HSTS {
				value := fmt.Sprintf("max-age=%d", config.HSTSMaxAge)
				if config.HSTSIncludeSubDomains {
					value += "; includeSubDomains"
				}
				if config.HSTSPreload {
					value += "; preload"
				}
				w.Header().Set("Strict-Transport-Security", value)
			}

			if config.FrameOptions != "" {
				w.Header().Set("X-Frame-Options", config.FrameOptions)
			}

			if config.ContentTypeOptions {
				w.Header().Set("X-Content-Type-Options", "nosniff")
			}

			if config.XSSProtection {
				w.Header().Set("X-XSS-Protection", "1; mode=block")
			}

			next.ServeHTTP(w, r)
		})
	}
}
