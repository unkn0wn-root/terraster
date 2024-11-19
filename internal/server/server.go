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

// tlsCache holds a map of TLS certificates keyed by hostname.
// It is used to efficiently retrieve certificates for incoming TLS connections.
type tlsCache struct {
	certs map[string]*tls.Certificate
}

// newTLSCache creates and returns a new instance of tlsCache with an initialized certificate map.
// This cache is immutable and intended for concurrent read access.
func newTLSCache() *tlsCache {
	return &tlsCache{
		certs: make(map[string]*tls.Certificate),
	}
}

// Server encapsulates all the components and configurations required to run the Terraster server.
// It manages HTTP/HTTPS servers, health checkers, admin APIs, TLS configurations, and service pools.
type Server struct {
	config         *config.Config              // Configuration settings for the server
	healthChecker  *health.Checker             // Global health checker (if any)
	adminAPI       *admin.AdminAPI             // Admin API handler
	adminServer    *http.Server                // HTTP server for admin API
	healthCheckers map[string]*health.Checker  // Individual health checkers per service
	serviceManager *service.Manager            // Manages the lifecycle and configuration of services
	tlsConfigCache *tlsCache                   // Cache for TLS configurations
	tlsConfigs     map[string]*tls.Certificate // Loaded TLS certificates
	serverPool     *pool.ServerPool            // Pool of server instances
	servers        []*http.Server              // Slice of all HTTP/HTTPS servers
	serviceCache   *sync.Map                   // Concurrent map for caching service lookups
	portServers    map[int]*http.Server        // Mapping of ports to their corresponding servers
	logger         *zap.Logger                 // Logger instance for logging server activities
	logManager     *logger.LoggerManager       // Manages different loggers
	mu             sync.RWMutex                // Mutex for synchronizing access to shared resources
	ctx            context.Context             // Context for managing server lifecycle
	cancel         context.CancelFunc          // Function to cancel the server context
	wg             sync.WaitGroup              // WaitGroup to wait for goroutines to finish
	errorChan      chan<- error                // Channel to report server errors
}

// NewServer initializes a new Server instance with the provided configurations and dependencies.
// It sets up health checkers for each service, initializes the admin API, and prepares the server for startup.
// Returns an error if any component fails to initialize.
func NewServer(
	srvCtx context.Context,
	errChan chan<- error,
	cfg *config.Config,
	authSrvc *auth_service.AuthService,
	zLog *zap.Logger,
	logManager *logger.LoggerManager,
) (*Server, error) {
	// Initialize the service manager with the given configuration and logger.
	serviceManager, err := service.NewManager(cfg, zLog)
	if err != nil {
		return nil, err
	}

	// Create a cancellable context derived from the provided server context.
	ctx, cancel := context.WithCancel(srvCtx)

	// Instantiate the Server struct with initialized fields.
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

	// Initialize health checkers for each service managed by the service manager.
	for _, svc := range serviceManager.GetServices() {
		hcCfg := svc.HealthCheck
		// Use global health check configuration if service-specific config is not provided.
		if (&config.HealthCheckConfig{}) == hcCfg {
			hcCfg = cfg.HealthCheck
		}

		// Create a prefixed logger for the health checker.
		prefix := "[HealthChecker-" + svc.Name + "]"
		lc := logger.NewZapWriter(zLog, zap.InfoLevel, prefix)

		// Instantiate a new health checker with the specified interval and timeout.
		hc := health.NewChecker(
			hcCfg.Interval,
			hcCfg.Timeout,
			log.New(lc, "", 0),
		)
		s.healthCheckers[svc.Name] = hc

		// Register all server pools associated with the service to the health checker.
		for _, loc := range svc.Locations {
			hc.RegisterPool(loc.ServerPool)
		}
	}

	return s, nil
}

// Start initializes and starts all configured HTTP/HTTPS servers along with the admin server.
// It sets up TLS configurations, loads certificates, and begins listening for incoming requests.
// Also starts all health checkers in separate goroutines.
// Returns an error if any server fails to start.
func (s *Server) Start() error {
	// Start all health checkers in separate goroutines.
	for svcName, hc := range s.healthCheckers {
		s.wg.Add(1)
		go func(name string, checker *health.Checker) {
			defer s.wg.Done()
			s.logger.Info("Starting health checker", zap.String("service_name", name))
			checker.Start(s.ctx)
		}(svcName, hc)
	}

	// Set up the main middleware handler chain.
	mainHandler := s.setupMiddleware()

	// Initialize the TLS configuration cache to handle TLS certificate retrieval efficiently.
	s.tlsConfigCache = newTLSCache()

	// Retrieve all services managed by the service manager.
	services := s.serviceManager.GetServices()
	// Preload all TLS certificates to prevent delays during request processing.
	for _, svc := range services {
		// Only load certificates for services that require HTTPS.
		if svc.ServiceType() == service.HTTPS {
			cert, err := tls.LoadX509KeyPair(svc.TLS.CertFile, svc.TLS.KeyFile)
			if err != nil {
				return fmt.Errorf("failed to load certificate for %s: %w", svc.Host, err)
			}

			s.tlsConfigCache.certs[svc.Host] = &cert
			s.logger.Info("Certificate loaded into cache", zap.String("host", svc.Host))
		}
	}

	// Start an HTTP/HTTPS server for each service.
	for _, svc := range services {
		if err := s.startServiceServer(svc, mainHandler); err != nil {
			s.cancel()
			return err
		}
	}

	// Start the admin HTTP server.
	if err := s.startAdminServer(); err != nil {
		s.cancel()
		return err
	}

	return nil
}

// startServiceServer sets up and starts HTTP and HTTPS servers for a given service.
// It ensures that services sharing the same port use the same underlying server instance to optimize resource usage.
// It also handles protocol mismatches and logs appropriate information.
// Returns an error if the server fails to start or if there is a protocol mismatch.
func (s *Server) startServiceServer(svc *service.ServiceInfo, handler http.Handler) error {
	// Determine the port on which the service should run.
	port := s.servicePort(svc.Port)
	protocol := svc.ServiceType()

	// Check if a server is already running on the desired port.
	if server := s.portServers[port]; server != nil {
		// Prevent mixing HTTP and HTTPS protocols on the same port.
		if (server.TLSConfig != nil) != (protocol == service.HTTPS) {
			return fmt.Errorf(
				"protocol mismatch: cannot mix HTTP and HTTPS on port %d for service %s",
				port,
				svc.Name,
			)
		}
		s.logger.Info("Service port already registered. Binding to the same socket",
			zap.String("service", svc.Name),
			zap.String("host", svc.Host),
			zap.Int("port", port))
		return nil
	}

	// Create a new HTTP or HTTPS server based on the service's protocol.
	svcType := svc.ServiceType()
	server, err := s.createServer(svc, handler, svcType)
	if err != nil {
		return fmt.Errorf("failed to create server for port %d: %w", port, err)
	}

	// Register the new server in the portServers map and the servers slice.
	s.portServers[port] = server
	s.servers = append(s.servers, server)

	// Start the server in a new goroutine.
	s.wg.Add(1)
	go s.runServer(server, s.errorChan, svc.Name, svcType)

	s.logger.Info("Service registered",
		zap.String("service", svc.Name),
		zap.String("host", svc.Host),
		zap.Int("port", port))

	return nil
}

// startAdminServer sets up and starts the administrative HTTP server.
// The admin server provides endpoints for managing and monitoring the server's operations.
// It supports both HTTP and HTTPS based on the server's TLS configuration.
// Returns an error if the admin server fails to start.
func (s *Server) startAdminServer() error {
	// Determine the host for the admin API, defaulting to localhost if not specified.
	adminApiHost := s.config.AdminAPI.Host
	if s.config.AdminAPI.Host == "" {
		adminApiHost = "localhost"
	}

	// Construct the address for the admin server.
	adminAddr := net.JoinHostPort(adminApiHost, strconv.Itoa(s.servicePort(s.config.AdminPort)))
	s.adminServer = &http.Server{
		Addr:         adminAddr,
		Handler:      s.adminAPI.Handler(),
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}

	// Determine the protocol for the admin server based on TLS settings.
	admSvcType := service.HTTP
	if s.config.TLS.Enabled {
		admSvcType = service.HTTPS
	}

	// Start the admin server in a new goroutine.
	s.wg.Add(1)
	go s.runServer(s.adminServer, s.errorChan, "admin", admSvcType)

	return nil
}

// createServer constructs and configures an HTTP or HTTPS server based on the provided service information.
// It sets up TLS configurations, including certificate retrieval from the cache for HTTPS servers.
// If the service requires HTTP to HTTPS redirection, it configures the appropriate handler.
// Returns the configured http.Server instance or an error if configuration fails.
func (s *Server) createServer(
	svc *service.ServiceInfo,
	handler http.Handler,
	protocol service.ServiceType,
) (*http.Server, error) {
	// Initialize the HTTP server with address and timeout configurations.
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.servicePort(svc.Port)),
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}

	// If the service requires HTTP to HTTPS redirection, set up the redirect handler.
	if svc.HTTPRedirect && protocol == service.HTTP {
		server.Handler = s.createRedirectHandler(svc)
		return server, nil
	}

	// Assign the main handler to the server.
	server.Handler = handler

	// Configure TLS settings for HTTPS servers.
	server.TLSConfig = &tls.Config{
		MinVersion: TLSMinVersion,
		// GetCertificate is a callback to retrieve the appropriate TLS certificate based on the client's SNI.
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Retrieve the certificate from the cache using the server name from the client's hello.
			if cert := s.tlsConfigCache.certs[hello.ServerName]; cert != nil {
				return cert, nil
			}
			return nil, fmt.Errorf("no certificate for host: %s", hello.ServerName)
		},
	}

	return server, nil
}

// runServer starts the provided HTTP or HTTPS server and listens for incoming connections.
// It handles server errors by logging them and sending them to the error channel.
// Ensures graceful shutdown by monitoring the server's lifecycle.
// Runs in a separate goroutine and decrements the WaitGroup upon completion.
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
	// Start the server based on its protocol.
	if serviceType == service.HTTPS {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}

	// Handle server errors, excluding graceful shutdown.
	if err != nil && err != http.ErrServerClosed {
		s.logger.Error("Error starting server", zap.String("server_name", n), zap.Error(err))
		defer s.cancel()
		errorChan <- err
	} else {
		s.logger.Info("Server stopped gracefully", zap.String("server_name", n))
	}
}

// createRedirectHandler creates an HTTP handler that redirects all incoming HTTP requests to HTTPS.
// The redirection preserves the original request URI and uses the specified redirect port.
// If no redirect port is specified, it defaults to the standard HTTPS port (443).
// This ensures that all traffic is secured over HTTPS.
func (s *Server) createRedirectHandler(svc *service.ServiceInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Determine the port to redirect to, defaulting to 443 if not specified.
		redirectPort := svc.RedirectPort
		if redirectPort == 0 {
			redirectPort = DefaultHTTPSPort
		}
		// Construct the target HTTPS URL with the appropriate port and request URI.
		target := "https://" + net.JoinHostPort(svc.Host, strconv.Itoa(redirectPort)) + r.URL.RequestURI()
		// Perform a permanent redirect to the HTTPS URL.
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

// defaultHandler is a placeholder HTTP handler that responds with a simple "Hello, World!" message.
// It can be replaced or extended with more complex logic as needed.
func (s *Server) defaultHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Hello, World!"))
}

// setupMiddleware constructs the middleware chain for handling incoming HTTP requests.
// It includes logging, rate limiting, and circuit breaker functionalities to enhance request handling.
// Returns the final HTTP handler after applying all middleware layers.
func (s *Server) setupMiddleware() http.Handler {
	// Base handler that processes the request after passing through all middleware.
	baseHandler := http.HandlerFunc(s.handleRequest)

	// Retrieve the request logger from the log manager.
	requestsLogger, err := s.logManager.GetLogger("request")
	if err != nil {
		s.logger.Error("Failed to get request logger", zap.Error(err))
	}

	// Initialize the logging middleware with desired configurations.
	logger := middleware.NewLoggingMiddleware(
		requestsLogger,
		middleware.WithLogLevel(zap.InfoLevel),
		middleware.WithHeaders(),
		middleware.WithQueryParams(),
		middleware.WithExcludePaths([]string{"/api/auth/login", "/api/auth/refresh"}),
	)

	// Create a middleware chain with circuit breaker, rate limiter, and logging middleware.
	chain := middleware.NewMiddlewareChain(
		middleware.NewCircuitBreaker(5, 3*time.Second),
		middleware.NewRateLimiterMiddleware(
			s.config.RateLimit.RequestsPerSecond,
			s.config.RateLimit.Burst,
		),
		logger,
	)

	// Apply the middleware chain to the base handler.
	return chain.Then(baseHandler)
}

// handleRequest processes incoming HTTP requests by determining the appropriate backend service.
// It handles service discovery, load balancing, and proxying requests to backend servers.
// Additionally, it manages connection counts and records response times for performance monitoring.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Parse the host and port from the request's Host header.
	host, port, err := parseHostPort(r.Host, r.TLS)
	if err != nil {
		http.Error(w, "Invalid host + port", http.StatusBadRequest)
		return
	}

	// Determine the protocol (HTTP or HTTPS) based on the TLS information.
	protocol := getProtocol(r)

	// Construct a unique service key for caching purposes.
	key := getServiceKey(host, port, protocol)

	// Attempt to retrieve the service information from the cache.
	srvc, err := s.getServiceFromCache(key)
	if err != nil {
		// If the service is not cached, retrieve it from the service manager.
		srvc, err = s.getServiceFromManager(host, r.URL.Path, port)
		if err != nil {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
		// Cache the retrieved service information for future requests.
		s.cacheService(key, srvc)
	}

	// Select an appropriate backend based on the configured load balancing algorithm.
	backend, err := s.getBackend(srvc, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Increment the connection count for the selected backend.
	if !backend.IncrementConnections() {
		http.Error(w, "Server at max capacity", http.StatusServiceUnavailable)
		return
	}
	defer backend.DecrementConnections()

	// Record the start time to measure response duration.
	start := time.Now()
	// Proxy the request to the selected backend, injecting the backend URL into the request context.
	backend.Proxy.ServeHTTP(w, r.WithContext(
		context.WithValue(r.Context(), middleware.BackendKey, backend.URL.String())),
	)
	// Calculate the duration taken to serve the request.
	duration := time.Since(start)

	// Record the response time for performance-based load balancing algorithms.
	s.recordResponseTime(srvc, backend.URL.String(), duration)
}

// getProtocol determines the protocol (HTTP or HTTPS) of the incoming request based on TLS information.
// Returns service.HTTPS if the request is over TLS, otherwise service.HTTP.
func getProtocol(r *http.Request) service.ServiceType {
	if r.TLS != nil {
		return service.HTTPS
	}
	return service.HTTP
}

// getServiceKey constructs a unique key for a service based on its host, port, and protocol.
// This key is used for caching and retrieving service information efficiently.
func getServiceKey(host string, port int, protocol service.ServiceType) string {
	return service.ServiceKey{
		Host:     host,
		Port:     port,
		Protocol: protocol,
	}.String()
}

// getServiceFromCache retrieves the service information from the cache using the provided key.
// Returns the service's location information if found, otherwise returns an error.
func (s *Server) getServiceFromCache(key string) (*service.LocationInfo, error) {
	cachedService, found := s.serviceCache.Load(key)
	if found {
		return cachedService.(*service.LocationInfo), nil
	}
	return nil, errors.New("service not found in cache")
}

// cacheService stores the provided service information in the cache using the specified key.
// This allows for faster retrieval of service details in subsequent requests.
func (s *Server) cacheService(key string, srvc *service.LocationInfo) {
	s.serviceCache.Store(key, srvc)
}

// getServiceFromManager retrieves the service information from the service manager based on host, path, and port.
// Returns the service's location information or an error if the service is not found.
func (s *Server) getServiceFromManager(host, path string, port int) (*service.LocationInfo, error) {
	_, srvc, err := s.serviceManager.GetService(host, path, port, false)
	if err != nil {
		return nil, err
	}
	return srvc, nil
}

// getBackend selects an appropriate backend server from the service's server pool based on the load balancing algorithm.
// Returns the selected backend or an error if no suitable backend is available.
func (s *Server) getBackend(srvc *service.LocationInfo, r *http.Request) (*pool.Backend, error) {
	// Use the service's load balancing algorithm to select the next backend.
	backendAlgo := srvc.Algorithm.NextServer(srvc.ServerPool, r)
	if backendAlgo == nil {
		return nil, errors.New("no service available")
	}

	// Retrieve the backend instance by its URL.
	backend := srvc.ServerPool.GetBackendByURL(backendAlgo.URL)
	if backend == nil {
		return nil, errors.New("no peers available")
	}

	return backend, nil
}

// recordResponseTime logs the response time for a given backend service.
// This information can be used by load balancing algorithms that factor in response times for decision making.
func (s *Server) recordResponseTime(srvc *service.LocationInfo, url string, duration time.Duration) {
	if lrt, ok := srvc.Algorithm.(*algorithm.LeastResponseTime); ok {
		lrt.UpdateResponseTime(url, duration)
	}
}

// Shutdown gracefully shuts down all running servers, including the admin server and all service servers.
// It also stops all health checkers and waits for all goroutines to finish within the provided context's deadline.
// Returns an error if the shutdown process is interrupted or fails.
func (s *Server) Shutdown(ctx context.Context) error {
	// Cancel the server's context to signal all goroutines to stop.
	s.cancel()
	var wg sync.WaitGroup

	// Initiate shutdown of the admin server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.adminServer.Shutdown(ctx); err != nil {
			s.logger.Error("Admin server shutdown error", zap.Error(err))
		} else {
			s.logger.Info("Admin server shutdown successfully")
		}
	}()

	// Initiate shutdown of all service servers.
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

	// Stop all health checkers.
	for svcName, hc := range s.healthCheckers {
		wg.Add(1)
		go func(name string, checker *health.Checker) {
			defer wg.Done()
			checker.Stop()
			s.logger.Info("Health checker stopped", zap.String("name", name))
		}(svcName, hc)
	}

	// Wait for all shutdown operations to complete.
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
