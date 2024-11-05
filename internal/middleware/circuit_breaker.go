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
		if backend == "" {
			backend = r.Host // fallback if URL.Host is empty
		}

		// initialize state if not exists
		cb.mu.RLock()
		state, exists := cb.state[backend]
		if !exists {
			cb.mu.RUnlock()
			cb.mu.Lock()
			cb.state[backend] = "closed"
			state = "closed"
			cb.mu.Unlock()
		} else {
			cb.mu.RUnlock()
		}

		// check if circuit is open
		if state == "open" {
			cb.mu.RLock()
			lastFailure := cb.lastFailure[backend]
			cb.mu.RUnlock()

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
		} else if sw.status > 0 {
			cb.recordSuccess(backend)
		}
	})
}
func (cb *CircuitBreaker) recordFailure(backend string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// if it's been a while since the last failure, reset the count
	if lastFailure, exists := cb.lastFailure[backend]; exists {
		if time.Since(lastFailure) > cb.resetTimeout {
			cb.failures[backend] = 0
		}
	}

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

	// gradually reduce failure count on success in closed state
	if cb.failures[backend] > 0 {
		cb.failures[backend]--
	}
}
