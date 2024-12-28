package admin

import (
	"net"
	"net/http"
	"strings"

	"github.com/unkn0wn-root/terraster/internal/middleware"
	"go.uber.org/zap"
)

// IPRestrictionMiddleware validates incoming requests against configured allowed IPs
type IPRestrictionMiddleware struct {
	allowedIPs []string
	logger     *zap.Logger
}

// NewIPRestrictionMiddleware creates a new middleware for IP-based access control
func NewIPRestrictionMiddleware(allowedIPs []string, logger *zap.Logger) middleware.Middleware {
	return &IPRestrictionMiddleware{
		allowedIPs: allowedIPs,
		logger:     logger,
	}
}

// This middleware provides IP-based access control.
// It validates the client's IP address against a configured list of allowed IPs.
//
// The middleware follows these rules:
// - If no IPs are configured (allowedIPs is empty), all requests are allowed
// - If IPs are configured, only requests from those IPs are allowed
// - Client IP is extracted from X-Forwarded-For header first, then X-Real-IP, finally falling back to RemoteAddr
//
// The function will return an HTTP 403 Forbidden status if the IP is not allowed,
// or HTTP 500 Internal Server Error if the client IP cannot be determined.
func (m *IPRestrictionMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// if no ip configured - assume allow all
		if len(m.allowedIPs) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// extract client IP from request
		clientIP := extractIP(r)
		if clientIP == "" {
			http.Error(w, "Could not verify client IP", http.StatusInternalServerError)
			return
		}

		// check if client IP is allowed
		for _, allowedIP := range m.allowedIPs {
			if clientIP == allowedIP {
				next.ServeHTTP(w, r)
				return
			}
		}

		// if we get here, the IP is not allowed
		m.logger.Warn("Access denied: IP not allowed",
			zap.String("client_ip", clientIP),
			zap.Strings("allowed_ips", m.allowedIPs),
		)
		http.Error(w, "Access denied", http.StatusForbidden)
	})
}

// extractIP gets the real client IP, taking into account X-Forwarded-For and X-Real-IP headers
func extractIP(r *http.Request) string {
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs; take the first one
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// check X-Real-IP header if no X-Forwarded-For
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// if SplitHostPort fails, try using RemoteAddr directly
		return r.RemoteAddr
	}
	return ip
}
