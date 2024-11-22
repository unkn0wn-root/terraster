package middleware

import (
	"net/http"

	"golang.org/x/time/rate"
)

// RateLimiterMiddleware provides rate limiting functionality to HTTP handlers.
// It ensures that incoming requests are processed at a controlled rate,
// preventing abuse and ensuring fair usage of server resources.
type RateLimiterMiddleware struct {
	limiter *rate.Limiter // limiter is the rate limiter instance that controls the request rate.
}

// NewRateLimiterMiddleware initializes and returns a new RateLimiterMiddleware.
// Sets up the rate limiter with the specified requests per second (rps) and burst size.
// If the burst size or rps are not provided (i.e., zero), default values are used.
func NewRateLimiterMiddleware(rps float64, burst int) Middleware {
	// Set default burst size if not provided.
	if burst == 0 {
		burst = 50
	}

	// Set default requests per second if not provided.
	if rps == 0 {
		rps = 20
	}

	return &RateLimiterMiddleware{
		limiter: rate.NewLimiter(rate.Limit(rps), burst), // Initialize the rate limiter with the specified limits.
	}
}

// Middleware is the core function that applies the rate limiting to incoming HTTP requests.
// It wraps the next handler in the chain, allowing controlled access based on the rate limiter's state.
// For each incoming request, the middleware checks if the request is allowed by the rate limiter.
// If the request exceeds the rate limit, it responds with a "Too Many Requests" error.
// Otherwise, it forwards the request to the next handler in the chain.
func (m *RateLimiterMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Attempt to allow the request based on the current rate limiter state.
		if !m.limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
