package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/unkn0wn-root/go-load-balancer/internal/admin"
	"github.com/unkn0wn-root/go-load-balancer/internal/config"
	"github.com/unkn0wn-root/go-load-balancer/internal/middleware"
	"github.com/unkn0wn-root/go-load-balancer/internal/pool"
	"github.com/unkn0wn-root/go-load-balancer/pkg/algorithm"
	"github.com/unkn0wn-root/go-load-balancer/pkg/health"
)

type Server struct {
	config        *config.Config
	serverPool    *pool.ServerPool
	algorithm     algorithm.Algorithm
	healthChecker *health.Checker
	adminAPI      *admin.AdminAPI
	server        *http.Server
	adminServer   *http.Server
	metricsServer *http.Server
	mu            sync.RWMutex
}

func New(ctx context.Context, cfg *config.Config) (*Server, error) {
	// Create server pool
	serverPool := pool.NewServerPool()

	// Initialize health checker
	healthChecker := health.NewChecker(
		cfg.HealthCheck.Interval,
		cfg.HealthCheck.Timeout,
	)

	// Create server instance
	srv := &Server{
		config:        cfg,
		serverPool:    serverPool,
		algorithm:     createAlgorithm(cfg.Algorithm),
		healthChecker: healthChecker,
	}

	// Initialize admin API
	srv.adminAPI = admin.NewAdminAPI(serverPool)

	// Add backends
	for _, backend := range cfg.Backends {
		if err := serverPool.AddBackend(backend); err != nil {
			return nil, fmt.Errorf("failed to add backend %s: %v", backend.URL, err)
		}
	}

	return srv, nil
}

func createAlgorithm(name string) algorithm.Algorithm {
	switch name {
	case "round-robin":
		return &algorithm.RoundRobin{}
	case "weighted-round-robin":
		return &algorithm.WeightedRoundRobin{}
	case "least-connections":
		return &algorithm.LeastConnections{}
	case "ip-hash":
		return &algorithm.IPHash{}
	case "least-response-time":
		return algorithm.NewLeastResponseTime()
	default:
		return &algorithm.RoundRobin{} // default algorithm
	}
}

func (s *Server) Start() error {
	// Start health checker
	go s.healthChecker.Start(context.Background())

	// Create main handler with middleware chain
	mainHandler := s.setupMiddleware()

	// Create main server
	s.server = &http.Server{
		Addr:           fmt.Sprintf(":%d", s.config.Port),
		Handler:        mainHandler,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Create admin server
	s.adminServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.config.AdminPort),
		Handler: s.adminAPI.Handler(),
	}

	// Start admin server
	go func() {
		if err := s.adminServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("Admin server error: %v", err)
		}
	}()

	// Start main server
	log.Printf("Load balancer started on port %d", s.config.Port)
	if s.config.TLS.Enabled {
		return s.server.ListenAndServeTLS(
			s.config.TLS.CertFile,
			s.config.TLS.KeyFile,
		)
	}
	return s.server.ListenAndServe()
}

func (s *Server) setupMiddleware() http.Handler {
	// Create base handler
	baseHandler := http.HandlerFunc(s.handleRequest)

	// Create middleware chain
	chain := middleware.NewMiddlewareChain(
		middleware.NewLoggingMiddleware(nil),
		middleware.NewRateLimiterMiddleware(
			s.config.RateLimit.RequestsPerSecond,
			s.config.RateLimit.Burst,
		),
		middleware.NewCircuitBreaker(5, time.Minute),
	)

	return chain.Then(baseHandler)
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	backendAlgo := s.algorithm.NextServer(s.serverPool, r)
	if backendAlgo == nil {
		http.Error(w, "No available backends", http.StatusServiceUnavailable)
		return
	}

	backend := s.serverPool.GetBackendByURL(backendAlgo.URL)
	if backend == nil {
		http.Error(w, "Selected backend not found", http.StatusServiceUnavailable)
		return
	}

	// Add backend to context
	ctx := context.WithValue(r.Context(), middleware.BackendKey, backend.URL.String())
	r = r.WithContext(ctx)

	// Track active connections
	backend.IncrementConnections()
	defer backend.DecrementConnections()

	start := time.Now()
	proxy := backend.ReverseProxy
	proxy.ServeHTTP(w, r)
	duration := time.Since(start)

	// Record response time for least-response-time algorithm
	if lrt, ok := s.algorithm.(*algorithm.LeastResponseTime); ok {
		lrt.UpdateResponseTime(backend.URL.String(), duration)
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	// Stop health checker
	s.healthChecker.Stop()

	// Create wait group for graceful shutdown
	var wg sync.WaitGroup

	// Shutdown main server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.server.Shutdown(ctx); err != nil {
			log.Printf("Main server shutdown error: %v", err)
		}
	}()

	// Shutdown admin server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.adminServer.Shutdown(ctx); err != nil {
			log.Printf("Admin server shutdown error: %v", err)
		}
	}()

	// Shutdown metrics server if enabled
	if s.metricsServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.metricsServer.Shutdown(ctx); err != nil {
				log.Printf("Metrics server shutdown error: %v", err)
			}
		}()
	}

	// Wait for all servers to shutdown
	waitChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitChan)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waitChan:
		return nil
	}
}

func (s *Server) UpdateConfig(cfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update configuration
	s.config = cfg

	// Update algorithm if changed
	if s.algorithm.Name() != cfg.Algorithm {
		s.algorithm = createAlgorithm(cfg.Algorithm)
	}

	// Update backends
	if err := s.serverPool.UpdateBackends(cfg.Backends); err != nil {
		return fmt.Errorf("failed to update backends: %v", err)
	}

	return nil
}
