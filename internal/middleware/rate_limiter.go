package middleware

import (
	"net/http"

	"golang.org/x/time/rate"
)

type RateLimiterMiddleware struct {
	limiter *rate.Limiter
}

func NewRateLimiterMiddleware(rps float64, burst int) Middleware {
	return &RateLimiterMiddleware{
		limiter: rate.NewLimiter(rate.Limit(rps), burst),
	}
}

func (m *RateLimiterMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
