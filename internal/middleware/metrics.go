package middleware

import (
	"net/http"
	"time"
)

type MetricsMiddleware struct {
	metrics *metrics.Metrics
}

func NewMetricsMiddleware(metrics *metrics.Metrics) Middleware {
	return &MetricsMiddleware{metrics: metrics}
}

func (m *MetricsMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := newStatusWriter(w)

		next.ServeHTTP(sw, r)

		duration := time.Since(start)
		backend := r.Context().Value(BackendKey).(string)

		m.metrics.RecordRequest(
			backend,
			duration,
			sw.Status() >= 500,
		)
	})
}
