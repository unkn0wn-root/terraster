package admin

import (
	"net"
	"net/http"

	"github.com/unkn0wn-root/terraster/internal/middleware"
	"go.uber.org/zap"
)

// HostnameMiddleware validates incoming requests against a configured hostname
type HostnameMiddleware struct {
	hostname string // Expected hostname to validate against
	logger   *zap.Logger
}

func NewHostnameMiddleware(hostname string, logger *zap.Logger) middleware.Middleware {
	return &HostnameMiddleware{
		hostname: hostname,
		logger:   logger,
	}
}

func (m *HostnameMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract hostname from request, ignoring port number
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			m.logger.Error("Could not split host", zap.Error(err))
			http.Error(w, "Could not verify target host", http.StatusInternalServerError)
			return
		}

		// If does not match - you shall not pass
		if host != m.hostname {
			m.logger.Warn("Invalid hostname",
				zap.String("expected", m.hostname),
				zap.String("received", host),
				zap.String("ip", r.RemoteAddr),
			)
			http.Error(w, "Invalid host", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
