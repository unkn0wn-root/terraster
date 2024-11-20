package middleware

import (
	"fmt"
	"net/http"

	"github.com/unkn0wn-root/terraster/internal/config"
)

// ServerSecurity encapsulates various HTTP security headers configurations.
// It determines which security headers should be set on HTTP responses to enhance security.
type ServerSecurity struct {
	HSTS                  bool   // Enables HTTP Strict Transport Security (HSTS).
	HSTSMaxAge            int    // Specifies the duration (in seconds) for which the browser should remember that the site is only to be accessed using HTTPS.
	HSTSIncludeSubDomains bool   // If true, applies HSTS policy to all subdomains.
	HSTSPreload           bool   // If true, includes the site in browsers' HSTS preload lists.
	FrameOptions          string // Specifies the X-Frame-Options header value to control whether the site can be embedded in frames.
	ContentTypeOptions    bool   // Enables the X-Content-Type-Options header to prevent MIME type sniffing.
	XSSProtection         bool   // Enables the X-XSS-Protection header to activate the browser's built-in XSS protection.
}

// NewSecurityMiddleware initializes and returns a new ServerSecurity instance based on the provided configuration.
// It reads security-related settings from the configuration and sets up the corresponding fields.
func NewSecurityMiddleware(cfg *config.Config) *ServerSecurity {
	var config *config.SecurityConfig
	for _, mw := range cfg.Middleware {
		if mw.Security != nil {
			config = mw.Security
			break
		}
	}

	return &ServerSecurity{
		HSTS:                  config.HSTS,
		HSTSMaxAge:            config.HSTSMaxAge,
		HSTSIncludeSubDomains: config.HSTSIncludeSubDomains,
		HSTSPreload:           config.HSTSPreload,
		FrameOptions:          config.FrameOptions,
		ContentTypeOptions:    config.ContentTypeOptions,
		XSSProtection:         config.XSSProtection,
	}
}

// Middleware is an HTTP middleware that sets various security headers on incoming HTTP responses.
// It enhances the security posture of the server by configuring headers like HSTS, X-Frame-Options,
// X-Content-Type-Options, and X-XSS-Protection based on the ServerSecurity settings.
func (s *ServerSecurity) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.HSTS {
			value := fmt.Sprintf("max-age=%d", s.HSTSMaxAge)
			if s.HSTSIncludeSubDomains {
				value += "; includeSubDomains"
			}
			if s.HSTSPreload {
				value += "; preload"
			}
			w.Header().Set("Strict-Transport-Security", value)
		}

		if s.FrameOptions != "" {
			w.Header().Set("X-Frame-Options", s.FrameOptions)
		}

		if s.ContentTypeOptions {
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}

		if s.XSSProtection {
			w.Header().Set("X-XSS-Protection", "1; mode=block")
		}

		next.ServeHTTP(w, r)
	})
}
