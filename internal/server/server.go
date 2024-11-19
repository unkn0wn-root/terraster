package server

import (
	"context"
	"crypto/tls"
	"errors"
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

type tlsCache struct {
	certs map[string]*tls.Certificate
}

// newTLSCache creates an immutable certificate cache
func newTLSCache() *tlsCache {
	return &tlsCache{
		certs: make(map[string]*tls.Certificate),
	}
}

type Server struct {
	config         *config.Config
	healthChecker  *health.Checker
	adminAPI       *admin.AdminAPI
	adminServer    *http.Server
	healthCheckers map[string]*health.Checker
	serviceManager *service.Manager
	tlsConfigCache *tlsCache
	tlsConfigs     map[string]*tls.Certificate
	serverPool     *pool.ServerPool
	servers        []*http.Server
	serviceCache   *sync.Map
	portServers    map[int]*http.Server
	logger         *zap.Logger
	logManager     *logger.LoggerManager
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
	logManager *logger.LoggerManager,
) (*Server, error) {
	serviceManager, err := service.NewManager(cfg, zLog)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(srvCtx)

	s := &Server{
		config:         cfg,
		healthCheckers: make(map[string]*health.Checker),
		adminAPI:       admin.NewAdminAPI(serviceManager, cfg, authSrvc),
		serviceManager: serviceManager,
		ctx:            ctx,
		cancel:         cancel,
		servers:        make([]*http.Server, 0),
		serviceCache:   &sync.Map{},
		portServers:    make(map[int]*http.Server),
		errorChan:      make(chan error),
		logger:         zLog,
		logManager:     logManager,
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

	// setup main middleware handler
	mainHandler := s.setupMiddleware()

	// We need to fast read TLS configurtion for each service request
	// if multiple services are running on the same port
	// with diffrent host name so using cache to load all certficates
	s.tlsConfigCache = newTLSCache()

	// get all services
	services := s.serviceManager.GetServices()
	// Load all certificates during initialization
	// to avoid any delay during request processing
	for _, svc := range services {
		// check if serivce requires HTTPS
		if svc.ServiceType() == service.HTTPS {
			cert, err := tls.LoadX509KeyPair(svc.TLS.CertFile, svc.TLS.KeyFile)
			if err != nil {
				return fmt.Errorf("failed to load certificate for %s: %w", svc.Host, err)
			}

			s.tlsConfigCache.certs[svc.Host] = &cert
			s.logger.Info("Certificate loaded into cache", zap.String("host", svc.Host))
		}
	}

	for _, svc := range services {
		// start each service server
		if err := s.startServiceServer(svc, mainHandler); err != nil {
			s.cancel()
			return err
		}
	}

	if err := s.startAdminServer(); err != nil {
		s.cancel()
		return err
	}

	return nil
}

// startServiceServer sets up and starts HTTP and HTTPS servers for a service.
func (s *Server) startServiceServer(svc *service.ServiceInfo, handler http.Handler) error {
	// if there is a service with the same port,
	// we should bind the new service to the same socket
	// to reuse the same underlying HTTP instance.
	// This will route then based on HTTP host header
	port := s.servicePort(svc.Port)
	protocol := svc.ServiceType()
	if server := s.portServers[port]; server != nil {
		// we can't risk mixing HTTP and HTTPS connection to the same port
		// for existing server, protocol must match
		if (server.TLSConfig != nil) != (protocol == service.HTTPS) {
			return fmt.Errorf(
				"protocol mismatch: cannot mix HTTP and HTTPS on port %d for service %s",
				port,
				svc.Name,
			)
		}
		s.logger.Info("Service port already registred. Bounding to the same socket",
			zap.String("service", svc.Name),
			zap.String("host", svc.Host),
			zap.Int("port", port))
		return nil
	}

	svcType := svc.ServiceType()
	server, err := s.createServer(svc, handler, svcType)
	if err != nil {
		return fmt.Errorf("failed to create server for port %d: %w", port, err)
	}

	s.portServers[port] = server
	s.servers = append(s.servers, server)

	s.wg.Add(1)
	go s.runServer(server, s.errorChan, svc.Name, svcType)

	s.logger.Info("Service registered",
		zap.String("service", svc.Name),
		zap.String("host", svc.Host),
		zap.Int("port", port))

	return nil
}

// startAdminServer sets up and starts the admin HTTP server.
func (s *Server) startAdminServer() error {
	adminApiHost := s.config.AdminAPI.Host
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

	admSvcType := service.HTTP
	if s.config.TLS.Enabled {
		admSvcType = service.HTTPS
	}

	s.wg.Add(1)
	go s.runServer(s.adminServer, s.errorChan, "admin", admSvcType)

	return nil
}

// createServer constructs an HTTP or HTTPS server based on the scheme.
func (s *Server) createServer(
	svc *service.ServiceInfo,
	handler http.Handler,
	protocol service.ServiceType,
) (*http.Server, error) {
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.servicePort(svc.Port)),
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}

	if svc.HTTPRedirect && protocol == service.HTTP {
		// For HTTP servers that need to redirect to HTTPS
		server.Handler = s.createRedirectHandler(svc)
		return server, nil
	}

	server.Handler = handler
	server.TLSConfig = &tls.Config{
		MinVersion: TLSMinVersion,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Lock-free read from cache
			if cert := s.tlsConfigCache.certs[hello.ServerName]; cert != nil {
				return cert, nil
			}
			return nil, fmt.Errorf("no certificate for host: %s", hello.ServerName)
		},
	}

	return server, nil
}

// runServer starts the server and handles errors.
func (s *Server) runServer(
	server *http.Server,
	errorChan chan<- error,
	name string,
	serviceType service.ServiceType,
) {
	defer s.wg.Done()
	n := strings.ToUpper(name)
	s.logger.Info("Server started", zap.String("name", n), zap.String("server_addr", server.Addr))

	var err error
	if serviceType == service.HTTPS {
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
		redirectPort := svc.RedirectPort
		if redirectPort == 0 {
			redirectPort = DefaultHTTPSPort // assume default HTTPS port (443) if redirect is set but redirect port is not
		}
		target := "https://" + net.JoinHostPort(svc.Host, strconv.Itoa(redirectPort)) + r.URL.RequestURI()
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
	requestsLogger, err := s.logManager.GetLogger("request")
	if err != nil {
		s.logger.Error("Failed to get request logger", zap.Error(err))
	}

	// @toDo: get it from config
	logger := middleware.NewLoggingMiddleware(
		requestsLogger,
		middleware.WithLogLevel(zap.InfoLevel),
		middleware.WithHeaders(),
		middleware.WithQueryParams(),
		middleware.WithExcludePaths([]string{"/api/auth/login", "/api/auth/refresh"}),
	)

	chain := middleware.NewMiddlewareChain(
		middleware.NewCircuitBreaker(5, 3*time.Second),
		middleware.NewRateLimiterMiddleware(
			s.config.RateLimit.RequestsPerSecond,
			s.config.RateLimit.Burst,
		),
		logger,
	)

	return chain.Then(baseHandler)
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	host, port, err := parseHostPort(r.Host, r.TLS)
	if err != nil {
		http.Error(w, "Invalid host + port", http.StatusBadRequest)
		return
	}

	// determine the protocol of the request to be able to match to the correct service
	// checking if request is comming on TLS should be enough to determine the protocol
	// Determine the protocol of the request
	protocol := getProtocol(r)

	// build service key which later be cached or retrieved from cache if found
	// Build service key for caching
	key := getServiceKey(host, port, protocol)

	// Try to get the service from the cache
	srvc, err := s.getServiceFromCache(key)
	if err != nil {
		// Service not found in cache, get it from the service manager
		srvc, err = s.getServiceFromManager(host, r.URL.Path, port)
		if err != nil {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
		// Cache the service for future requests
		s.cacheService(key, srvc)
	}

	// Find the appropriate backend based on the configured algorithm
	backend, err := s.getBackend(srvc, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	if !backend.IncrementConnections() {
		http.Error(w, "Server at max capacity", http.StatusServiceUnavailable)
		return
	}
	defer backend.DecrementConnections()

	start := time.Now()
	backend.Proxy.ServeHTTP(w, r.WithContext(
		context.WithValue(r.Context(), middleware.BackendKey, backend.URL.String())),
	)
	duration := time.Since(start)

	// record response time for least-response-time algorithm
	s.recordResponseTime(srvc, backend.URL.String(), duration)
}

func getProtocol(r *http.Request) service.ServiceType {
	if r.TLS != nil {
		return service.HTTPS
	}
	return service.HTTP
}

func getServiceKey(host string, port int, protocol service.ServiceType) string {
	return service.ServiceKey{
		Host:     host,
		Port:     port,
		Protocol: protocol,
	}.String()
}

func (s *Server) getServiceFromCache(key string) (*service.LocationInfo, error) {
	cachedService, found := s.serviceCache.Load(key)
	if found {
		return cachedService.(*service.LocationInfo), nil
	}
	return nil, errors.New("service not found in cache")
}

func (s *Server) cacheService(key string, srvc *service.LocationInfo) {
	s.serviceCache.Store(key, srvc)
}

func (s *Server) getServiceFromManager(host, path string, port int) (*service.LocationInfo, error) {
	_, srvc, err := s.serviceManager.GetService(host, path, port, false)
	if err != nil {
		return nil, err
	}
	return srvc, nil
}

func (s *Server) getBackend(srvc *service.LocationInfo, r *http.Request) (*pool.Backend, error) {
	backendAlgo := srvc.Algorithm.NextServer(srvc.ServerPool, r)
	if backendAlgo == nil {
		return nil, errors.New("no service available")
	}

	backend := srvc.ServerPool.GetBackendByURL(backendAlgo.URL)
	if backend == nil {
		return nil, errors.New("no peers available")
	}

	return backend, nil
}

func (s *Server) recordResponseTime(srvc *service.LocationInfo, url string, duration time.Duration) {
	if lrt, ok := srvc.Algorithm.(*algorithm.LeastResponseTime); ok {
		lrt.UpdateResponseTime(url, duration)
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
