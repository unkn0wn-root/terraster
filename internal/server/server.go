package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/unkn0wn-root/terraster/internal/admin"
	auth_service "github.com/unkn0wn-root/terraster/internal/auth/service"
	"github.com/unkn0wn-root/terraster/internal/config"
	"github.com/unkn0wn-root/terraster/internal/health"
	"github.com/unkn0wn-root/terraster/internal/middleware"
	"github.com/unkn0wn-root/terraster/internal/pool"
	"github.com/unkn0wn-root/terraster/internal/service"
	"github.com/unkn0wn-root/terraster/pkg/algorithm"
	"github.com/unkn0wn-root/terraster/pkg/logger"
	"go.uber.org/zap"
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
	healthCheckers map[string]*health.Checker
	serviceManager *service.Manager
	serverPool     *pool.ServerPool
	servers        []*http.Server
	logger         *zap.Logger
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	errorChan      chan<- error
}

func NewServer(
	srvCtx context.Context,
	errChan chan<- error,
	cfg *config.Config,
	authSrvc *auth_service.AuthService,
	zLog *zap.Logger,
) (*Server, error) {
	ctx, cancel := context.WithCancel(srvCtx)
	serviceManager, err := service.NewManager(cfg, zLog)
	if err != nil {
		return nil, err
	}

	s := &Server{
		config:         cfg,
		healthCheckers: make(map[string]*health.Checker),
		adminAPI:       admin.NewAdminAPI(serviceManager, cfg, authSrvc),
		serviceManager: serviceManager,
		ctx:            ctx,
		cancel:         cancel,
		servers:        make([]*http.Server, 0),
		errorChan:      make(chan error),
		logger:         zLog,
	}

	// Initialize health checkers per service
	for _, svc := range serviceManager.GetServices() {
		hcCfg := svc.HealthCheck
		// If service has no specific health check, use global
		if (&config.HealthCheckConfig{}) == hcCfg {
			hcCfg = cfg.HealthCheck
		}

		prefix := "[HealthChecker-" + svc.Name + "]"
		lc := logger.NewZapWriter(zLog, zap.InfoLevel, prefix)

		hc := health.NewChecker(
			hcCfg.Interval,
			hcCfg.Timeout,
			log.New(lc, "", 0),
		)
		s.healthCheckers[svc.Name] = hc
		// Register server pools with the respective health checker
		for _, loc := range svc.Locations {
			hc.RegisterPool(loc.ServerPool)
		}
	}

	return s, nil
}

// Start initializes and starts all servers.
func (s *Server) Start() error {
	for svcName, hc := range s.healthCheckers {
		s.wg.Add(1)
		go func(name string, checker *health.Checker) {
			defer s.wg.Done()
			s.logger.Info("Starting health checker", zap.String("service_name", name))
			checker.Start(s.ctx)
		}(svcName, hc)
	}

	mainHandler := s.setupMiddleware()

	// Start service servers
	services := s.serviceManager.GetServices()
	for _, svc := range services {
		if err := s.startServiceServer(svc, mainHandler); err != nil {
			s.cancel()
			return err
		}
	}

	if err := s.startAdminServer(); err != nil {
		s.cancel()
		return err
	}

	s.logger.Info("Starting server(s)...")
	return nil
}

// startServiceServer sets up and starts HTTP and HTTPS servers for a service.
func (s *Server) startServiceServer(svc *service.ServiceInfo, handler http.Handler) error {
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
func (s *Server) createServer(
	svc *service.ServiceInfo,
	handler http.Handler,
	scheme string,
	tlsCert *tls.Certificate,
) (*http.Server, error) {
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
	n := strings.ToUpper(name)
	s.logger.Info("Starting server, ", zap.String("name", n), zap.String("server_addr", server.Addr))

	var err error
	if scheme == "https" {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		s.logger.Error("Error starting server", zap.String("server_name", n), zap.Error(err))
		defer s.cancel()
		errorChan <- err
	} else {
		s.logger.Info("Server stopped gracefully", zap.String("server_name", n))
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

func (s *Server) setupMiddleware() http.Handler {
	baseHandler := http.HandlerFunc(s.handleRequest)
	// @toDo: get it from config
	logger := middleware.NewLoggingMiddleware(
		s.logger,
		middleware.WithLogLevel(zap.InfoLevel),
		middleware.WithHeaders(),
		middleware.WithQueryParams(),
		middleware.WithExcludePaths([]string{"/api/auth/login", "/api/auth/refresh"}),
	)

	chain := middleware.NewMiddlewareChain(
		middleware.NewCircuitBreaker(10, 10*time.Second),
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
	proxy := backend.Proxy
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
	s.cancel()
	var wg sync.WaitGroup

	// Shutdown admin server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.adminServer.Shutdown(ctx); err != nil {
			s.logger.Error("Admin server shutdown error", zap.Error(err))
		} else {
			s.logger.Info("Admin server shutdown successfully")
		}
	}()

	for _, srv := range s.servers {
		wg.Add(1)
		go func(server *http.Server) {
			defer wg.Done()
			if err := server.Shutdown(ctx); err != nil {
				s.logger.Error("Server shutdown error", zap.String("server_addr", server.Addr), zap.Error(err))
			} else {
				s.logger.Info("Server shutdown successfully", zap.String("server_addr", server.Addr))
			}
		}(srv)
	}

	// Stop health checkers
	for svcName, hc := range s.healthCheckers {
		wg.Add(1)
		go func(name string, checker *health.Checker) {
			defer wg.Done()
			checker.Stop()
			s.logger.Info("Health checker stopped", zap.String("name", name))
		}(svcName, hc)
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
		s.logger.Info("All servers and health checkers shutdown successfully")
		return nil
	}
}

func (s *Server) servicePort(port int) int {
	if port != 0 {
		return port
	}

	return DefaultHTTPPort
}
