package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
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

// Constants for default configurations
const (
	DefaultHTTPPort     = 80
	DefaultHTTPSPort    = 443
	DefaultAdminPort    = 8080
	ReadTimeout         = 15 * time.Second
	WriteTimeout        = 15 * time.Second
	IdleTimeout         = 60 * time.Second
	TLSMinVersion       = tls.VersionTLS12
	ShutdownGracePeriod = 30 * time.Second
)

type Server struct {
	config         *config.Config
	healthChecker  *health.Checker
	adminAPI       *admin.AdminAPI
	adminServer    *http.Server
	serviceManager *service.Manager
	serverPool     *pool.ServerPool
	servers        []*http.Server
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	errorChan      chan<- error
}

// Start initializes and starts all servers.
func (s *Server) Start() error {
	log.Println("Starting server...")

	// Start health checker
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.healthChecker.Start(s.ctx)
	}()

	mainHandler := s.setupMiddleware()

	// Start service servers
	services := s.serviceManager.GetServices()
	for _, svc := range services {
		if err := s.startServiceServer(svc, mainHandler); err != nil {
			return err
		}
	}

	// Start admin server
	if err := s.startAdminServer(); err != nil {
		defer s.cancel()
		return err
	}

	log.Println("All servers started successfully")
	return nil
}

// startServiceServer sets up and starts HTTP and HTTPS servers for a service.
func (s *Server) startServiceServer(svc *service.ServiceInfo, handler http.Handler) error {
	// Load TLS certificate once if needed and start HTTPS server
	var tlsCert tls.Certificate
	var err error
	if svc.TLS != nil {
		tlsCert, err = tls.LoadX509KeyPair(svc.TLS.CertFile, svc.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate for service %s: %w", svc.Name, err)
		}

		httpsServer, err := s.createServer(svc, handler, "https", &tlsCert)
		if err != nil {
			return fmt.Errorf("failed to create HTTPS server for service %s: %w", svc.Name, err)
		}
		s.wg.Add(1)
		go s.runServer(httpsServer, s.errorChan, svc.Name, "https")
		return nil
	}

	// Start HTTP server otherwise
	httpServer, err := s.createServer(svc, handler, "http", nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP server for service %s: %w", svc.Name, err)
	}
	s.wg.Add(1)
	go s.runServer(httpServer, s.errorChan, svc.Name, "http")

	return nil
}

// startAdminServer sets up and starts the admin HTTP server.
func (s *Server) startAdminServer() error {
	var adminApiHost string
	if s.config.AdminAPI.Host == "" {
		adminApiHost = "localhost"
	}

	adminAddr := net.JoinHostPort(adminApiHost, strconv.Itoa(s.servicePort(s.config.AdminPort)))
	s.adminServer = &http.Server{
		Addr:         adminAddr,
		Handler:      s.adminAPI.Handler(),
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}

	s.wg.Add(1)
	go s.runServer(s.adminServer, s.errorChan, "admin", "http")

	return nil
}

// createServer constructs an HTTP or HTTPS server based on the scheme.
func (s *Server) createServer(svc *service.ServiceInfo, handler http.Handler, scheme string, tlsCert *tls.Certificate) (*http.Server, error) {
	finalHandler := handler
	if scheme == "http" && svc.HTTPRedirect && svc.TLS != nil {
		// For HTTP servers that need to redirect to HTTPS
		finalHandler = s.createRedirectHandler(svc)
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.servicePort(svc.Port)),
		Handler:      finalHandler,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}

	if scheme == "https" && tlsCert != nil {
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
			MinVersion:   TLSMinVersion,
		}
	}

	return server, nil
}

// runServer starts the server and handles errors.
func (s *Server) runServer(server *http.Server, errorChan chan<- error, name, scheme string) {
	defer s.wg.Done()

	log.Printf("Starting %s server on %s", scheme, server.Addr)

	var err error
	if scheme == "https" {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		log.Printf("Error starting %s server: %v", scheme, err)
		defer s.cancel()
		errorChan <- err
	} else {
		log.Printf("%s server stopped gracefully", scheme)
	}
}

// createRedirectHandler creates a handler that redirects HTTP to HTTPS.
func (s *Server) createRedirectHandler(svc *service.ServiceInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + net.JoinHostPort(svc.Host, strconv.Itoa(s.servicePort(svc.Port))) + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

// defaultHandler is a placeholder for the main HTTP handler.
func (s *Server) defaultHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Hello, World!"))
}

// NewServer creates a new Server instance with the provided configurations.
func NewServer(srvCtx context.Context, errChan chan<- error, cfg *config.Config) (*Server, error) {
	ctx, cancel := context.WithCancel(srvCtx)
	serviceManager, err := service.NewManager(cfg)
	if err != nil {
		cancel()
		return nil, err
	}

	return &Server{
		config:         cfg,
		healthChecker:  health.NewChecker(cfg.HealthCheck.Interval, cfg.HealthCheck.Timeout),
		adminAPI:       admin.NewAdminAPI(serviceManager, cfg),
		serviceManager: serviceManager,
		ctx:            ctx,
		cancel:         cancel,
		servers:        make([]*http.Server, 0),
		errorChan:      make(chan error),
	}, nil
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
	_, service, err := s.serviceManager.GetService(host, r.URL.Path, false)
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

func (s *Server) hasHTTPSRedirects() bool {
	services := s.serviceManager.GetServices()
	for _, service := range services {
		if service.HTTPRedirect {
			return true
		}
	}
	return false
}

func (s *Server) hostNameNoPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return ""
	}

	return h
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.healthChecker.Stop()

	var wg sync.WaitGroup

	// Shutdown admin server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.adminServer.Shutdown(ctx); err != nil {
			log.Printf("Admin server shutdown error: %v", err)
		}
	}()

	for _, srv := range s.servers {
		wg.Add(1)
		go func(server *http.Server) {
			defer wg.Done()
			if err := server.Shutdown(ctx); err != nil {
				log.Printf("Server shutdown error for %s: %v", server.Addr, err)
			}
		}(srv)
	}

	// Wait for all shutdowns to complete
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

func (s *Server) servicePort(port int) int {
	if port != 0 {
		return port
	}

	return DefaultHTTPPort
}
