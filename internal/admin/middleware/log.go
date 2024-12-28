package admin

import (
	"net/http"

	"github.com/unkn0wn-root/terraster/internal/middleware"
	"go.uber.org/zap"
)

type AccessLogMiddleware struct {
	logger *zap.Logger
}

func NewAccessLogMiddleware(logger *zap.Logger) middleware.Middleware {
	return &AccessLogMiddleware{
		logger: logger,
	}
}

func (m *AccessLogMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.logger.Info("Request to Admin API",
			zap.String("method", r.Method),
			zap.String("request url", r.URL.Path),
			zap.String("request addr.", r.RemoteAddr))

		// Wrap response writer to capture status code
		sw := &statusResponseWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		m.logger.Info("Response from Admin API",
			zap.Int("status", sw.status),
			zap.String("method", r.Method),
			zap.String("request path", r.URL.Path))
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}
