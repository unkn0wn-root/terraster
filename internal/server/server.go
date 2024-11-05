package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/unkn0wn-root/go-load-balancer/internal/admin"
	"github.com/unkn0wn-root/go-load-balancer/internal/config"
	"github.com/unkn0wn-root/go-load-balancer/internal/middleware"
	"github.com/unkn0wn-root/go-load-balancer/internal/pool"
	"github.com/unkn0wn-root/go-load-balancer/internal/service"
	"github.com/unkn0wn-root/go-load-balancer/pkg/algorithm"
	"github.com/unkn0wn-root/go-load-balancer/pkg/health"
)

type Server struct {
	config         *config.Config
	algorithm      algorithm.Algorithm
	healthChecker  *health.Checker
	adminAPI       *admin.AdminAPI
	server         *http.Server
	adminServer    *http.Server
	serviceManager *service.Manager
	serverPool     *pool.ServerPool
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
}

func New(ctx context.Context, cfg *config.Config) (*Server, error) {
	serviceManager, err := service.NewManager(cfg)
	if err != nil {
		return nil, err
	}

	// Initialize health checker
	healthChecker := health.NewChecker(
		cfg.HealthCheck.Interval,
		cfg.HealthCheck.Timeout,
	)

	ctx, cancel := context.WithCancel(ctx)

	srv := &Server{
		config:         cfg,
		serviceManager: serviceManager,
		algorithm:      createAlgorithm(cfg.Algorithm),
		healthChecker:  healthChecker,
		ctx:            ctx,
		cancel:         cancel,
	}

	srv.adminAPI = admin.NewAdminAPI(serviceManager, cfg)

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

func (s *Server) Start(errorChan chan<- error) error {
	go s.healthChecker.Start(s.ctx)

	mainHandler := s.setupMiddleware()

	s.server = &http.Server{
		Addr:           fmt.Sprintf(":%d", s.config.Port),
		Handler:        mainHandler,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// admin server
	s.adminServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.config.AdminPort),
		Handler: s.adminAPI.Handler(),
	}

	go func() {
		if err := s.adminServer.ListenAndServe(); err != http.ErrServerClosed {
			defer s.cancel()
			log.Printf("Admin server error: %v", err)
			errorChan <- err
		}
	}()

	// main server
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
	baseHandler := http.HandlerFunc(s.handleRequest)
	// @toDo: get it from config
	logger := middleware.NewLoggingMiddleware("/var/log/lb/access.log")
	defer logger.Shutdown()

	chain := middleware.NewMiddlewareChain(
		middleware.NewCircuitBreaker(5, 30*time.Second),
		middleware.NewRateLimiterMiddleware(
			s.config.RateLimit.RequestsPerSecond,
			s.config.RateLimit.Burst,
		),
		middleware.NewServerHostMiddleware(),
		logger,
	)

	return chain.Then(baseHandler)
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	host := middleware.GetTargetHost(r)
	// find the appropriate service for this path
	serviceInfo := s.serviceManager.GetService(host, r.URL.Path)
	if serviceInfo == nil {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	// get backend for the service's server pool
	backendAlgo := s.algorithm.NextServer(serviceInfo.ServerPool, r)
	if backendAlgo == nil {
		http.Error(w, "No service available right now", http.StatusServiceUnavailable)
		return
	}

	backend := serviceInfo.ServerPool.GetBackendByURL(backendAlgo.URL)
	if backend == nil {
		http.Error(w, "No peers available", http.StatusServiceUnavailable)
		return
	}

	// strip the service path prefix if it exists
	if serviceInfo.Path != "" && strings.HasPrefix(r.URL.Path, serviceInfo.Path) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, serviceInfo.Path)
	}

	ctx := context.WithValue(r.Context(), middleware.BackendKey, backend.URL.String())
	r = r.WithContext(ctx)

	backend.IncrementConnections()
	defer backend.DecrementConnections()

	start := time.Now()
	proxy := backend.ReverseProxy
	proxy.ServeHTTP(w, r)
	duration := time.Since(start)

	// record response time for least-response-time algorithm
	if lrt, ok := s.algorithm.(*algorithm.LeastResponseTime); ok {
		lrt.UpdateResponseTime(backend.URL.String(), duration)
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.healthChecker.Stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.server.Shutdown(ctx); err != nil {
			log.Printf("Main server shutdown error: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.adminServer.Shutdown(ctx); err != nil {
			log.Printf("Admin server shutdown error: %v", err)
		}
	}()

	// wait for all servers to shutdown
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		log.Println("All servers shutdown successfully")
		return nil
	}
}

func (s *Server) UpdateConfig(cfg *config.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg
}
