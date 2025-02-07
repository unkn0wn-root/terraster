package server

import (
	"net/http"

	"github.com/unkn0wn-root/terraster/internal/config"
	"github.com/unkn0wn-root/terraster/internal/middleware"
	"github.com/unkn0wn-root/terraster/internal/service"
	"go.uber.org/zap"
)

// createServiceMiddleware constructs and configures the middleware chain for a specific service.
// It applies global middleware based on the server's configuration and allows overriding or adding
// middleware specific to the service. Finally, it appends a logging middleware to the chain.
func (s *Server) createServiceMiddleware(svc *service.ServiceInfo) http.Handler {
	baseHandler := http.HandlerFunc(s.handleRequest)

	chain := middleware.NewMiddlewareChain()
	chain.AddConfiguredMiddlewares(s.config, svc.Logger)

	// Check if the service has any specific middleware configurations to override or add.
	if svc.Middleware != nil {
		for _, mw := range svc.Middleware {
			switch {
			case mw.RateLimit != nil:
				// If a rate limiter configuration is provided, create and replace the existing rate limiter middleware.
				rl := middleware.NewRateLimiterMiddleware(mw.RateLimit.RequestsPerSecond, mw.RateLimit.Burst)
				chain.Replace(rl)
				s.logger.Info("Service Rate Limiter middleware overridden",
					zap.String("service", svc.Name),
					zap.Float64("requests_per_second", mw.RateLimit.RequestsPerSecond),
					zap.Int("burst", mw.RateLimit.Burst))

			case mw.CircuitBreaker != nil:
				// If a circuit breaker configuration is provided, create and replace the existing circuit breaker middleware.
				cb := middleware.NewCircuitBreaker(mw.CircuitBreaker.FailureThreshold, mw.CircuitBreaker.ResetTimeout)
				chain.Replace(cb)
				s.logger.Info("Service Circuit Breaker middleware overridden",
					zap.String("service", svc.Name),
					zap.Int("failure_threshold", mw.CircuitBreaker.FailureThreshold),
					zap.Duration("reset_timeout", mw.CircuitBreaker.ResetTimeout))

			case mw.Security != nil:
				// If a security configuration is provided, create and replace the existing security middleware.
				sec := middleware.NewSecurityMiddleware(s.config)
				chain.Replace(sec)
				s.logger.Info("Service Security middleware overridden",
					zap.String("service", svc.Name))

			case mw.CORS != nil:
				// If a CORS configuration is provided, create and replace the existing CORS middleware.
				cors := middleware.NewCORSMiddleware(s.config)
				chain.Replace(cors)
				s.logger.Info("Service CORS middleware overridden",
					zap.String("service", svc.Name))

			case mw.Compression:
				// If a compression configuration is provided, create and replace the existing compression middleware.
				compressor := middleware.NewCompressionMiddleware()
				chain.Replace(compressor)
			}
		}
	}

	logOpts := &config.LogOptions{
		Headers:     false, //default values if not set via config file
		QueryParams: false,
	}
	if slop := svc.LogOptions; slop != nil {
		logOpts = slop
	}

	// add logging middleware to the chain with service logger
	logger := middleware.NewLoggingMiddleware(
		svc.Logger,
		middleware.WithLogLevel(zap.InfoLevel),      // Set the logging level to Info.
		middleware.WithHeaders(logOpts.Headers),     // Configure the middleware to log HTTP headers.
		middleware.WithQueryParams(logOpts.Headers), // Configure the middleware to log query parameters.
		middleware.WithExcludePaths([]string{"/api/auth/login", "/api/auth/refresh"}), // Exclude sensitive paths from logging.
	)
	chain.Use(logger)

	return chain.Then(baseHandler)
}
