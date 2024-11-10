package middleware

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/unkn0wn-root/go-load-balancer/internal/auth/service"
	"golang.org/x/time/rate"
)

type AuthMiddleware struct {
	authService *service.AuthService
	rateLimiter *RateLimiter
}

func NewAuthMiddleware(authService *service.AuthService) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
		rateLimiter: NewRateLimiter(10, 30), // 10 requests per second, burst of 30
	}
}

func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply rate limiting
		if !m.rateLimiter.Allow(r.RemoteAddr) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Get token from header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "No token provided", http.StatusUnauthorized)
			return
		}

		// Validate token format
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			return
		}

		// Validate token
		claims, err := m.authService.ValidateToken(tokenParts[1])
		if err != nil {
			switch err {
			case service.ErrRevokedToken:
				http.Error(w, "Token has been revoked", http.StatusUnauthorized)
			case service.ErrInvalidToken:
				http.Error(w, "Invalid token", http.StatusUnauthorized)
			default:
				http.Error(w, "Authentication failed", http.StatusUnauthorized)
			}
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), "user_claims", claims)

		// Set security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

func NewRateLimiter(requestsPerSecond, burst int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rate.Limit(requestsPerSecond),
		burst:    burst,
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	limiter, exists := rl.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.limiters[key] = limiter
	}
	rl.mu.Unlock()

	return limiter.Allow()
}
