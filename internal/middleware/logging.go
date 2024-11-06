package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

type LogLevel int

const (
	INFO LogLevel = iota
	WARNING
	ERROR
)

type LogEntry struct {
	Timestamp   string            `json:"timestamp"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Status      int               `json:"status"`
	Duration    string            `json:"duration"`
	IP          string            `json:"ip"`
	UserAgent   string            `json:"user_agent"`
	QueryParams map[string]string `json:"query_params,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Level       string            `json:"level"`
	Error       string            `json:"error,omitempty"`
}

type LoggingMiddleware struct {
	logger         *log.Logger
	logLevel       LogLevel
	includeHeaders bool
	includeQuery   bool
	excludePaths   []string
}

type LoggingOption func(*LoggingMiddleware)

func WithLogLevel(level LogLevel) LoggingOption {
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

func NewLoggingMiddleware(logger *log.Logger, opts ...LoggingOption) *LoggingMiddleware {
	if logger == nil {
		logger = log.Default()
	}

	lm := &LoggingMiddleware{
		logger:         logger,
		logLevel:       INFO,
		includeHeaders: false,
		includeQuery:   false,
		excludePaths:   []string{},
	}

	for _, opt := range opts {
		opt(lm)
	}

	return lm
}

type LogStatusWriter struct {
	http.ResponseWriter
	status int
	error  error
}

func newLogStatusWriter(w http.ResponseWriter) *LogStatusWriter {
	return &LogStatusWriter{ResponseWriter: w, status: http.StatusOK}
}

func (w *LogStatusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (l *LoggingMiddleware) shouldExcludePath(path string) bool {
	for _, excludePath := range l.excludePaths {
		if strings.HasPrefix(path, excludePath) {
			return true
		}
	}
	return false
}

func getLogLevel(status int) LogLevel {
	switch {
	case status >= 500:
		return ERROR
	case status >= 400:
		return WARNING
	default:
		return INFO
	}
}

func getLevelString(level LogLevel) string {
	switch level {
	case ERROR:
		return "ERROR"
	case WARNING:
		return "WARNING"
	default:
		return "INFO"
	}
}

func (l *LoggingMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if l.shouldExcludePath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		sw := newLogStatusWriter(w)

		next.ServeHTTP(sw, r)

		if getLogLevel(sw.status) >= l.logLevel {
			duration := time.Since(start)

			entry := LogEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Method:    r.Method,
				Path:      r.URL.Path,
				Status:    sw.status,
				Duration:  duration.String(),
				IP:        r.RemoteAddr,
				UserAgent: r.UserAgent(),
				Level:     getLevelString(getLogLevel(sw.status)),
			}

			if l.includeQuery {
				queryParams := make(map[string]string)
				for key, values := range r.URL.Query() {
					queryParams[key] = strings.Join(values, ",")
				}
				if len(queryParams) > 0 {
					entry.QueryParams = queryParams
				}
			}

			if l.includeHeaders {
				headers := make(map[string]string)
				for key, values := range r.Header {
					headers[key] = strings.Join(values, ",")
				}
				if len(headers) > 0 {
					entry.Headers = headers
				}
			}

			if sw.error != nil {
				entry.Error = sw.error.Error()
			}

			jsonEntry, err := json.Marshal(entry)
			if err != nil {
				l.logger.Printf("Error marshaling log entry: %v", err)
				return
			}

			l.logger.Println(string(jsonEntry))
		}
	})
}
