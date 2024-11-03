package middleware

import (
	"net/http"
	"sync"
	"time"
)

type CircuitBreaker struct {
	mu               sync.RWMutex
	failureThreshold int
	resetTimeout     time.Duration
	failures         map[string]int
	lastFailure      map[string]time.Time
	state            map[string]string // "closed", "open", "half-open"
}

func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: threshold,
		resetTimeout:     timeout,
		failures:         make(map[string]int),
		lastFailure:      make(map[string]time.Time),
		state:            make(map[string]string),
	}
}

func (cb *CircuitBreaker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backend := r.URL.Host

		cb.mu.RLock()
		state := cb.state[backend]
		lastFailure := cb.lastFailure[backend]
		cb.mu.RUnlock()

		if state == "open" {
			if time.Since(lastFailure) > cb.resetTimeout {
				cb.mu.Lock()
				cb.state[backend] = "half-open"
				cb.mu.Unlock()
			} else {
				http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
		}

		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)

		if sw.status >= 500 {
			cb.recordFailure(backend)
		} else {
			cb.recordSuccess(backend)
		}
	})
}

func (cb *CircuitBreaker) recordFailure(backend string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures[backend]++
	cb.lastFailure[backend] = time.Now()

	if cb.failures[backend] >= cb.failureThreshold {
		cb.state[backend] = "open"
	}
}

func (cb *CircuitBreaker) recordSuccess(backend string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state[backend] == "half-open" {
		cb.state[backend] = "closed"
		cb.failures[backend] = 0
	}
}
