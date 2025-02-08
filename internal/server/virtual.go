package server

import (
	"net/http"
	"strings"
	"sync"

	"github.com/unkn0wn-root/terraster/internal/config"
	"github.com/unkn0wn-root/terraster/internal/middleware"
	"github.com/unkn0wn-root/terraster/internal/service"
	"go.uber.org/zap"
)

// HostHandler represents a pre-configured handler for a specific host.
// By storing both logger and handler, we avoid context lookups during request processing.
type HostHandler struct {
	logger  *zap.Logger
	handler http.Handler
}

// VirtualServiceHandler manages multiple service handlers on the same port.
// This is the core component that enables efficient handling of multiple
// services sharing the same port while maintaining separate configurations.
type VirtualServiceHandler struct {
	handlers       map[string]*HostHandler
	mu             sync.RWMutex
	defaultHandler http.Handler
}

// NewVirtualServiceHandler creates a new handler manager.
// This is called once per port during server initialization.
func NewVirtualServiceHandler() *VirtualServiceHandler {
	return &VirtualServiceHandler{
		handlers: make(map[string]*HostHandler),
	}
}

// AddService configures and stores a complete handler chain for a service.
// This is called during service registration, NOT during request processing.
// The key performance aspect is that this build the entire middleware chain
// once during initialization, rather than per-request.
func (mh *VirtualServiceHandler) AddService(s *Server, svc *service.ServiceInfo) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// Handle HTTP redirect
	hostname := strings.ToLower(svc.Host)
	if svc.ServiceType() == service.HTTP && svc.HTTPRedirect {
		mh.handlers[hostname] = &HostHandler{
			logger:  svc.Logger,
			handler: s.createRedirectHandler(svc),
		}
		return
	}

	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleRequest(w, r)
	})

	// Build middleware chain
	chain := middleware.NewMiddlewareChain()
	chain.AddConfiguredMiddlewares(s.config, svc.Logger)

	// Add service-specific middleware
	if svc.Middleware != nil {
		for _, mw := range svc.Middleware {
			switch {
			case mw.RateLimit != nil:
				rl := middleware.NewRateLimiterMiddleware(
					mw.RateLimit.RequestsPerSecond,
					mw.RateLimit.Burst,
				)
				chain.Replace(rl)
			case mw.CircuitBreaker != nil:
				cb := middleware.NewCircuitBreaker(
					mw.CircuitBreaker.FailureThreshold,
					mw.CircuitBreaker.ResetTimeout,
				)
				chain.Replace(cb)
			case mw.Security != nil:
				sec := middleware.NewSecurityMiddleware(s.config)
				chain.Replace(sec)
			case mw.CORS != nil:
				cors := middleware.NewCORSMiddleware(s.config)
				chain.Replace(cors)
			case mw.Compression:
				compressor := middleware.NewCompressionMiddleware()
				chain.Replace(compressor)
			}
		}
	}

	logOpts := &config.LogOptions{
		Headers:     false,
		QueryParams: false,
	}
	if slop := svc.LogOptions; slop != nil {
		logOpts = slop
	}

	logger := middleware.NewLoggingMiddleware(
		svc.Logger,
		middleware.WithLogLevel(zap.InfoLevel),
		middleware.WithHeaders(logOpts.Headers),
		middleware.WithQueryParams(logOpts.Headers),
		middleware.WithExcludePaths([]string{"/api/auth/login", "/api/auth/refresh"}),
	)
	chain.Use(logger)

	mh.handlers[hostname] = &HostHandler{
		logger:  svc.Logger,
		handler: chain.Then(baseHandler),
	}
}

// ServeHTTP is the entry point for all requests.
func (mh *VirtualServiceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mh.mu.RLock()
	hostHandler, exists := mh.handlers[mh.hostKey(r.Host)]
	mh.mu.RUnlock()

	if !exists {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}
	// Direct dispatch to pre-configured handler
	hostHandler.handler.ServeHTTP(w, r)
}

// hostKey return host without port. This does not validate or return any error.
// Takes `r.Host` as input which should always cotains valid hostname.
func (mh *VirtualServiceHandler) hostKey(host string) string {
	// fast path: no port
	i := strings.IndexByte(host, ':')
	if i < 0 {
		return strings.ToLower(host)
	}
	// if port exists, lowercase only up to port
	return strings.ToLower(host[:i])
}
