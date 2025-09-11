package middleware

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// CompressionMiddleware provides response compression functionality to HTTP handlers.
type CompressionMiddleware struct{}

func NewCompressionMiddleware() Middleware {
	return &CompressionMiddleware{}
}

// Middleware is the core function that applies response compression to HTTP responses.
// It wraps the next handler in the chain, enabling gzip compression for eligible responses.
// For each incoming request, the middleware checks if the client accepts gzip encoding by inspecting
// the "Accept-Encoding" header.
// If gzip is supported, it wraps the ResponseWriter with a gzip.Writer to compress the response.
// It sets the "Content-Encoding" header to "gzip" and removes the "Content-Length" header since
// the length of the compressed response is not known in advance.
// If gzip is not supported, it forwards the request to the next handler without modifying the response.
func (c *CompressionMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		gz := gzip.NewWriter(w)
		defer gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")

		compressedWriter := compressionWriter{
			Writer:         gz,
			ResponseWriter: w,
		}

		next.ServeHTTP(compressedWriter, r)
	})
}

// compressionWriter is a custom ResponseWriter that wraps the original ResponseWriter
// and an io.Writer (specifically a gzip.Writer). It overrides the Write method to ensure
// that data is written through the gzip.Writer, enabling response compression.
type compressionWriter struct {
	io.Writer
	http.ResponseWriter
}

// Write overrides the default Write method to write compressed data.
// It writes the byte slice 'b' to the embedded io.Writer, which compresses the data
// before sending it to the client.
func (c compressionWriter) Write(b []byte) (int, error) {
	return c.Writer.Write(b) // Delegate the write operation to the embedded io.Writer.
}

// Flush allows the compressionWriter to support flushing of the response.
func (c compressionWriter) Flush() {
	if flusher, ok := c.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack allows the compressionWriter to support connection hijacking.
func (c compressionWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := c.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("upstream ResponseWriter does not implement http.Hijacker")
}
