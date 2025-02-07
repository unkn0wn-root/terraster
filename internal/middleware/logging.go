package middleware

import (
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type LoggingMiddleware struct {
	logger         *zap.Logger
	logLevel       zapcore.Level
	includeHeaders bool
	includeQuery   bool
	excludePaths   []string
}

type LoggingOption func(*LoggingMiddleware)

func WithLogLevel(level zapcore.Level) LoggingOption {
	return func(l *LoggingMiddleware) {
		l.logLevel = level
	}
}

// enables logging of request headers.
func WithHeaders(enabled bool) LoggingOption {
	return func(l *LoggingMiddleware) {
		if enabled {
			l.includeHeaders = true
		}
	}
}

// enables logging of query parameters.
func WithQueryParams(enabled bool) LoggingOption {
	return func(l *LoggingMiddleware) {
		if enabled {
			l.includeQuery = true
		}
	}
}

// excludes specified paths from logging.
func WithExcludePaths(paths []string) LoggingOption {
	return func(l *LoggingMiddleware) {
		l.excludePaths = paths
	}
}

func NewLoggingMiddleware(logger *zap.Logger, opts ...LoggingOption) *LoggingMiddleware {
	lm := &LoggingMiddleware{
		logger:         logger,
		logLevel:       zapcore.InfoLevel,
		includeHeaders: false,
		includeQuery:   false,
		excludePaths:   []string{},
	}

	for _, opt := range opts {
		opt(lm)
	}

	return lm
}

// wraps http.ResponseWriter to capture status code and response size.
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int64
}

// captures the status code.
func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// captures the response size.
func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += int64(size)
	return size, err
}

func (l *LoggingMiddleware) shouldExcludePath(path string) bool {
	for _, excludePath := range l.excludePaths {
		if strings.HasPrefix(path, excludePath) {
			return true
		}
	}
	return false
}

func (l *LoggingMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if l.shouldExcludePath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)

		fields := make([]zap.Field, 0, 8)
		fields = append(fields,
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", rw.status),
			zap.Duration("duration", duration),
			zap.String("ip", getIPAddress(r)),
			zap.String("user_agent", r.UserAgent()),
			zap.Int64("response_size", rw.size),
		)

		if l.includeQuery && len(r.URL.RawQuery) > 0 {
			queryParams := make(map[string]string)
			for key, values := range r.URL.Query() {
				queryParams[key] = strings.Join(values, ",")
			}
			fields = append(fields, zap.Any("query_params", queryParams))
		}

		if l.includeHeaders {
			headers := make(map[string]string)
			for key, values := range r.Header {
				headers[key] = strings.Join(values, ",")
			}
			fields = append(fields, zap.Any("headers", headers))
		}

		switch {
		case rw.status >= 500:
			l.logger.Error("Server error", fields...)
		case rw.status >= 400:
			l.logger.Warn("Client error", fields...)
		default:
			l.logger.Info("Request completed", fields...)
		}
	})
}

// extracts the IP address from the request.
func getIPAddress(r *http.Request) string {
	// Attempt to get the IP from the X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs, the first is the client
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Fallback to the remote address
	ip := r.RemoteAddr
	// Remove the port if present
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		return ip[:colon]
	}
	return ip
}
