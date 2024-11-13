package admin

import (
	"log"
	"net/http"

	"github.com/unkn0wn-root/terraster/internal/middleware"
)

type AdminAccessLogMiddleware struct{}

func NewAdminAccessLogMiddleware() middleware.Middleware {
	return &AdminAccessLogMiddleware{}
}

func (m *AdminAccessLogMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Admin API access: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		// Wrap response writer to capture status code
		sw := &statusResponseWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		log.Printf("Admin API response: %d for %s %s", sw.status, r.Method, r.URL.Path)
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
