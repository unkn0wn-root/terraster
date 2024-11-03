package middleware

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

// Middleware interface
type Middleware interface {
	Middleware(next http.Handler) http.Handler
}

// statusWriter implementation
type statusWriter struct {
	http.ResponseWriter
	status int
	length int
}

func newStatusWriter(w http.ResponseWriter) *statusWriter {
	return &statusWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
	}
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.length += n
	return n, err
}

func (w *statusWriter) Status() int {
	return w.status
}

func (w *statusWriter) Length() int {
	return w.length
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("upstream ResponseWriter does not implement http.Hijacker")
}

func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Chain multiple middleware
type MiddlewareChain struct {
	middlewares []Middleware
}

func NewMiddlewareChain(middlewares ...Middleware) *MiddlewareChain {
	return &MiddlewareChain{
		middlewares: middlewares,
	}
}

func (c *MiddlewareChain) Then(final http.Handler) http.Handler {
	if final == nil {
		final = http.DefaultServeMux
	}

	for i := len(c.middlewares) - 1; i >= 0; i-- {
		final = c.middlewares[i].Middleware(final)
	}

	return final
}
