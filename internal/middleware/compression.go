package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
)

type compressionWriter struct {
	io.Writer
	http.ResponseWriter
}

func (c compressionWriter) Write(b []byte) (int, error) {
	return c.Writer.Write(b)
}

func CompressionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		gz := gzip.NewWriter(w)
		defer gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		next.ServeHTTP(compressionWriter{Writer: gz, ResponseWriter: w}, r)
	})
}
