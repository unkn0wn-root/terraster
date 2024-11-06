package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
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
		healthChecker:  healthChecker,
		ctx:            ctx,
		cancel:         cancel,
	}

	srv.adminAPI = admin.NewAdminAPI(serviceManager, cfg)

	return srv, nil
}

func (s *Server) Start(errorChan chan<- error) error {
	go s.healthChecker.Start(s.ctx)

	mainHandler := s.setupMiddleware()

	tlsConfig := &tls.Config{
		GetCertificate: s.getCertificateForHost,
	}

	s.server = &http.Server{
		Addr:           fmt.Sprintf(":%d", s.config.Port),
		Handler:        mainHandler,
		TLSConfig:      tlsConfig,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// This only runs if there are services with http redirects
	if s.hasHTTPSRedirects() {
		httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := middleware.GetTargetHost(r)
			service, err := s.serviceManager.GetService(host, r.URL.Path)
			if service == nil || err != nil {
				http.Error(w, "Service not found", http.StatusNotFound)
				return
			}

			if service.HTTPRedirect {
				target := fmt.Sprintf("%s://%s%s", "https", r.Host, r.RequestURI)
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}

			mainHandler.ServeHTTP(w, r)
		})

		redirectHandler := &http.Server{
			Addr:    fmt.Sprintf(":%d", s.config.HTTPSPort),
			Handler: httpHandler,
		}

		// start http redirect server in a separate goroutine
		go func() {
			if err := redirectHandler.ListenAndServe(); err != http.ErrServerClosed {
				defer s.cancel()
				log.Printf("Redirect server error: %v", err)
				errorChan <- err
			}
		}()
	}

	// admin server
	s.adminServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.config.AdminPort),
		Handler: s.adminAPI.Handler(),
	}

	// start admin server in a separate goroutine
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
	log := log.New(os.Stdout, "", log.LstdFlags)
	// @toDo: get it from config
	logger := middleware.NewLoggingMiddleware(
		log,
		middleware.WithLogLevel(middleware.INFO),
		middleware.WithHeaders(),
		middleware.WithQueryParams(),
		middleware.WithExcludePaths([]string{"/health"}), // exclude health check from logs
	)

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
	service, err := s.serviceManager.GetService(host, r.URL.Path)
	if err != nil {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	// get backend for the service's server pool
	backendAlgo := service.Algorithm.NextServer(service.ServerPool, r)
	if backendAlgo == nil {
		http.Error(w, "No service available right now", http.StatusServiceUnavailable)
		return
	}

	backend := service.ServerPool.GetBackendByURL(backendAlgo.URL)
	if backend == nil {
		http.Error(w, "No peers available", http.StatusServiceUnavailable)
		return
	}

	// strip the service path prefix if it exists
	if service.Path != "" && strings.HasPrefix(r.URL.Path, service.Path) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, service.Path)
	}

	ctx := context.WithValue(r.Context(), middleware.BackendKey, backend.URL.String())
	r = r.WithContext(ctx)

	if !backend.IncrementConnections() {
		http.Error(w, "Server at max capacity", http.StatusServiceUnavailable)
		return
	}
	defer backend.DecrementConnections()

	start := time.Now()
	proxy := backend.ReverseProxy
	proxy.ServeHTTP(w, r)
	duration := time.Since(start)

	// record response time for least-response-time algorithm
	if lrt, ok := service.Algorithm.(*algorithm.LeastResponseTime); ok {
		lrt.UpdateResponseTime(backend.URL.String(), duration)
	}
}

func (s *Server) getCertificateForHost(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	service, _ := s.serviceManager.GetService(info.ServerName, "") // we only need to match host
	if service == nil || service.TLS == nil {
		return nil, fmt.Errorf("no certificate configured for host: %s", info.ServerName)
	}

	// load certificate
	cert, err := tls.LoadX509KeyPair(service.TLS.CertFile, service.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate for host %s: %v", info.ServerName, err)
	}

	return &cert, nil
}

func (s *Server) hasHTTPSRedirects() bool {
	services := s.serviceManager.GetServices()
	for _, service := range services {
		for _, location := range service.Locations {
			if location.HTTPRedirect {
				return true
			}
		}
	}
	return false
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
