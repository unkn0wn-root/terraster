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
// It sets up the rate limiter with the specified requests per second (rps) and burst size.
// If the burst size or rps are not provided (i.e., zero), default values are used.
//
// Parameters:
// - rps: float64 representing the number of allowed requests per second.
// - burst: int specifying the maximum number of requests that can burst at once.
//
// Returns:
// - Middleware: An instance of RateLimiterMiddleware configured with the specified rate limits.
//
// Usage Example:
// limiter := NewRateLimiterMiddleware(10, 100)
// http.Handle("/", limiter.Middleware(myHandler))
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
//
// Parameters:
// - next: http.Handler representing the next handler in the middleware chain.
//
// Returns:
// - http.Handler: A wrapped handler that enforces rate limiting before invoking the next handler.
//
// Behavior:
// - For each incoming request, the middleware checks if the request is allowed by the rate limiter.
// - If the request exceeds the rate limit, it responds with a "Too Many Requests" error.
// - Otherwise, it forwards the request to the next handler in the chain.
func (m *RateLimiterMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Attempt to allow the request based on the current rate limiter state.
		if !m.limiter.Allow() {
			// If the request exceeds the rate limit, respond with HTTP 429 Too Many Requests.
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		// If the request is allowed, proceed to the next handler.
		next.ServeHTTP(w, r)
	})
}
