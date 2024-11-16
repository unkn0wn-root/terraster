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

func WithHeaders() LoggingOption {
	return func(l *LoggingMiddleware) {
		l.includeHeaders = true
	}
}

func WithQueryParams() LoggingOption {
	return func(l *LoggingMiddleware) {
		l.includeQuery = true
	}
}

func WithExcludePaths(paths []string) LoggingOption {
	return func(l *LoggingMiddleware) {
		l.excludePaths = paths
	}
}

func NewLoggingMiddleware(opts ...LoggingOption) (*LoggingMiddleware, error) {
	config := zap.NewProductionConfig()
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder

	logger, err := config.Build()
	if err != nil {
		return nil, err
	}

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

	return lm, nil
}

type responseWriter struct {
	http.ResponseWriter
	status int
	size   int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

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

		// Build fields slice with capacity for common fields
		fields := make([]zap.Field, 0, 8)
		fields = append(fields,
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", rw.status),
			zap.Duration("duration", duration),
			zap.String("ip", r.RemoteAddr),
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
