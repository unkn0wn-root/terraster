package middleware

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// BackendState holds the state and failure information for a single backend.
type BackendState struct {
	mu          sync.RWMutex
	failures    int
	lastFailure time.Time
	state       atomic.Value // string: "closed", "open", "half-open"
}

type CircuitBreaker struct {
	failureThreshold int
	resetTimeout     time.Duration
	backends         sync.Map // map[string]*BackendState
}

func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: threshold,
		resetTimeout:     timeout,
		backends:         sync.Map{},
	}
}

// Middleware wraps the HTTP handler with circuit breaker logic.
func (cb *CircuitBreaker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backend := r.URL.Host
		if backend == "" {
			backend = r.Host // fallback if URL.Host is empty
		}

		bsIface, _ := cb.backends.LoadOrStore(backend, &BackendState{})
		bs := bsIface.(*BackendState)

		// Initialize the state to "closed" if not already set
		if bs.state.Load() == nil {
			bs.state.Store("closed")
		}

		currentState := bs.state.Load().(string)

		if currentState == "open" {
			lastFailure := bs.lastFailure
			if time.Since(lastFailure) > cb.resetTimeout {
				bs.state.Store("half-open")
			} else {
				http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
		}

		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)

		if sw.status >= 500 {
			cb.recordFailure(backend, bs)
		} else if sw.status > 0 {
			cb.recordSuccess(backend, bs)
		}
	})
}

// increments the failure count and updates the state if necessary.
func (cb *CircuitBreaker) recordFailure(backend string, bs *BackendState) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// Reset failure count if last failure was before resetTimeout
	if time.Since(bs.lastFailure) > cb.resetTimeout {
		bs.failures = 0
	}

	bs.failures++
	bs.lastFailure = time.Now()

	if bs.failures >= cb.failureThreshold {
		bs.state.Store("open")
	}
}

// decrements the failure count or resets the state based on current state.
func (cb *CircuitBreaker) recordSuccess(backend string, bs *BackendState) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	currentState := bs.state.Load().(string)

	if currentState == "half-open" {
		// Successful request in half-open state closes the circuit
		bs.state.Store("closed")
		bs.failures = 0
	} else if currentState == "closed" && bs.failures > 0 {
		// Gradually reduce failure count on success in closed state
		bs.failures--
	}
}
