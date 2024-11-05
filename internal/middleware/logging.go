package middleware

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type LoggingMiddleware struct {
	logger *log.Logger
	logCh  chan string
	wg     sync.WaitGroup
}

func NewLoggingMiddleware(logFile string) *LoggingMiddleware {
	var logger *log.Logger

	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Failed to open log file: %v, falling back to default logger", err)
			logger = log.Default()
		} else {
			logger = log.New(file, "", log.LstdFlags)
		}
	} else {
		logger = log.Default()
	}

	m := &LoggingMiddleware{
		logger: logger,
		logCh:  make(chan string, 1000), // Buffer size of 1000 logs
	}

	m.wg.Add(1)
	go m.logWorker()

	return m
}

func (l *LoggingMiddleware) logWorker() {
	defer l.wg.Done()
	for msg := range l.logCh {
		l.logger.Println(msg)
	}
}

func (l *LoggingMiddleware) Shutdown() {
	close(l.logCh)
	l.wg.Wait()
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fµs", float64(d.Microseconds()))
	}
	return fmt.Sprintf("%.2fms", float64(d.Milliseconds()))
}

func (l *LoggingMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := newStatusWriter(w)

		host := r.Host
		if origHost, ok := r.Context().Value(TargetHost).(string); ok {
			host = origHost
		}

		next.ServeHTTP(sw, r)

		duration := time.Since(start)
		logEntry := fmt.Sprintf(
			"host=%s method=%s path=%s status=%d size=%d duration=%s userAgent=\"%s\" referer=\"%s\"",
			host,
			r.Method,
			r.URL.Path,
			sw.status,
			sw.length,
			formatDuration(duration),
			r.UserAgent(),
			r.Referer(),
		)

		select {
		case l.logCh <- logEntry:
		default:
			// channel full, log synchronously as fallback
			l.logger.Println(logEntry)
		}
	})
}
