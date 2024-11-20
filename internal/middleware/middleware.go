package middleware

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/unkn0wn-root/terraster/internal/config"
)

// Middleware defines an interface for HTTP middleware.
// Each middleware must implement the Middleware method, which takes the next handler in the chain
// and returns a new handler that wraps additional functionality around it.
type Middleware interface {
	Middleware(next http.Handler) http.Handler
}

// statusWriter is a custom ResponseWriter that captures the HTTP status code and the length of the response.
// It embeds the standard http.ResponseWriter and adds fields to store status and length.
type statusWriter struct {
	http.ResponseWriter     // Embeds the standard ResponseWriter to delegate standard methods.
	status              int // Stores the HTTP status code of the response.
	length              int // Stores the length of the response body in bytes.
}

// newStatusWriter initializes and returns a new instance of statusWriter.
// It sets the default status to http.StatusOK (200).
func newStatusWriter(w http.ResponseWriter) *statusWriter {
	return &statusWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
	}
}

// WriteHeader captures the status code and delegates the call to the embedded ResponseWriter.
func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Write captures the length of the response and delegates the write operation.
// It ensures that the status is set to http.StatusOK if not already set.
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.length += n
	return n, err
}

// Status returns the captured HTTP status code.
func (w *statusWriter) Status() int {
	return w.status
}

// Length returns the length of the response body in bytes.
func (w *statusWriter) Length() int {
	return w.length
}

// Hijack allows the middleware to support connection hijacking.
// It delegates the hijacking process to the embedded ResponseWriter if it implements the http.Hijacker interface.
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("upstream ResponseWriter does not implement http.Hijacker")
}

// Flush allows the middleware to support flushing of the response.
// It delegates the flush operation to the embedded ResponseWriter if it implements the http.Flusher interface.
func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// MiddlewareChain manages a sequence of middleware.
// It allows chaining multiple middleware together and applying them to a final HTTP handler.
type MiddlewareChain struct {
	middlewares []Middleware // A slice holding the middleware in the order they should be applied.
}

// NewMiddlewareChain initializes and returns a new MiddlewareChain with the provided middleware.
// It accepts a variadic number of Middleware and stores them in the chain.
func NewMiddlewareChain(middlewares ...Middleware) *MiddlewareChain {
	return &MiddlewareChain{
		middlewares: middlewares,
	}
}

// Use adds a new Middleware to the MiddlewareChain.
// It appends the middleware to the existing slice, maintaining the order of application.
func (c *MiddlewareChain) Use(middleware Middleware) {
	c.middlewares = append(c.middlewares, middleware)
}

// Then applies the middleware chain to the final HTTP handler.
// It wraps the final handler with each middleware in reverse order, so that the first middleware added
// is the first to process the request.
func (c *MiddlewareChain) Then(final http.Handler) http.Handler {
	if final == nil {
		final = http.DefaultServeMux // Defaults to the default ServeMux if no final handler is provided.
	}

	// Wrap the final handler with each middleware, starting from the last added.
	for i := len(c.middlewares) - 1; i >= 0; i-- {
		final = c.middlewares[i].Middleware(final)
	}

	return final
}

// AddConfiguredMiddlewars adds middleware to the chain based on the provided configuration.
// It checks the configuration for enabled middleware features like Circuit Breaker, Rate Limiting, and Security,
// and adds the corresponding middleware to the chain.
func (c *MiddlewareChain) AddConfiguredMiddlewars(config *config.Config) {
	// Circuit Breaker Middleware
	if config.CircuitBreaker != nil {
		var threshold int
		var resetTimeout time.Duration
		if config.CircuitBreaker.FailureThreshold == 0 {
			threshold = 5
		}

		if config.CircuitBreaker.ResetTimeout == 0 {
			resetTimeout = 30 * time.Second
		}

		cb := NewCircuitBreaker(threshold, resetTimeout)
		c.Use(cb)
	}

	// Rate Limiting Middleware
	if config.RateLimit != nil {
		rl := NewRateLimiterMiddleware(config.RateLimit.RequestsPerSecond, config.RateLimit.Burst)
		c.Use(rl)
	}

	// Security Middleware
	if config.Security != nil {
		sec := NewSecurityMiddleware(config)
		c.Use(sec)
	}

	// CORS Middleware
	if config.CORS != nil {
		cors := NewCORSMiddleware(config)
		c.Use(cors)
	}
}
