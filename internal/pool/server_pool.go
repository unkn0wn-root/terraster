package pool

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"

	"github.com/unkn0wn-root/terraster/internal/config"
	"github.com/unkn0wn-root/terraster/pkg/algorithm"
	"go.uber.org/zap"
)

type contextKey int

const (
	// RetryKey is used as a key to store and retrieve retry counts from the request context.
	RetryKey contextKey = iota
)

// PoolConfig holds configuration settings for the ServerPool, including the load balancing algorithm and maximum connections.
type PoolConfig struct {
	Algorithm string `json:"algorithm"`       // The name of the load balancing algorithm to use (e.g., "round-robin").
	MaxConns  int32  `json:"max_connections"` // The maximum number of concurrent connections allowed per backend.
}

// BackendSnapshot represents a snapshot of the current state of backends in the ServerPool.
// It includes a slice of all backends and a map for quick backend lookup by URL.
type BackendSnapshot struct {
	Backends     []*Backend          // Slice of all backend servers in the pool.
	BackendCache map[string]*Backend // Map for quick access to backends by their URL string.
}

// ServerPool manages a pool of backend servers, handling load balancing and connection management.
// It supports dynamic addition and removal of backends and maintains thread-safe access to its state.
type ServerPool struct {
	backends       atomic.Value // Atomic value storing the current BackendSnapshot.
	current        uint64       // Atomic counter used for round-robin load balancing.
	algorithm      atomic.Value // Atomic value storing the current load balancing algorithm.
	maxConnections atomic.Int32 // Atomic integer representing the maximum allowed connections per backend.
	log            *zap.Logger  // Logger instance for logging pool activities.
}

// NewServerPool initializes and returns a new ServerPool instance with default settings.
// It sets up an initial empty BackendSnapshot and configures the default load balancing algorithm and connection limits.
func NewServerPool(logger *zap.Logger) *ServerPool {
	pool := &ServerPool{log: logger}
	initialSnapshot := &BackendSnapshot{
		Backends:     []*Backend{},
		BackendCache: make(map[string]*Backend),
	}
	pool.backends.Store(initialSnapshot)
	pool.algorithm.Store(algorithm.CreateAlgorithm("round-robin"))
	pool.maxConnections.Store(1000)
	return pool
}

// AddBackend adds a new backend to the ServerPool with the specified configuration, route settings, and health check configuration.
// It parses the backend URL, creates a reverse proxy, initializes the backend, and updates the BackendSnapshot atomically.
// Returns an error if the backend URL is invalid or if there is an issue creating the reverse proxy.
func (s *ServerPool) AddBackend(
	cfg config.BackendConfig,
	rc RouteConfig,
	hcCfg *config.HealthCheckConfig,
) error {
	url, err := url.Parse(cfg.URL)
	if err != nil {
		return err
	}

	createProxy := &httputil.ReverseProxy{}
	rp := NewReverseProxy(
		url,
		rc,
		createProxy,
		s.log,
		WithURLRewriter(rc, url),
	)

	maxConnections := cfg.MaxConnections
	if maxConnections == 0 {
		maxConnections = s.GetMaxConnections() // Use pool's default if not specified.
	}

	if hcCfg == nil {
		s.log.Info("HealthCheckConfig is nil for backend, applying default health check.", zap.String("url", cfg.URL))
		hcCfg = config.DefaultHealthCheck.Copy()
	}

	backend := &Backend{
		URL:            url,
		Weight:         cfg.Weight,
		MaxConnections: maxConnections,
		Proxy:          rp,
		HealthCheckCfg: hcCfg,
	}
	backend.Alive.Store(true)                   // Mark the backend as initially alive.
	atomic.StoreInt32(&backend.SuccessCount, 0) // Initialize success count.
	atomic.StoreInt32(&backend.FailureCount, 0) // Initialize failure count.

	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	newBackends := make([]*Backend, len(currentSnapshot.Backends)+1)
	copy(newBackends, currentSnapshot.Backends)
	newBackends[len(currentSnapshot.Backends)] = backend

	newBackendCache := make(map[string]*Backend, len(currentSnapshot.BackendCache)+1)
	for k, v := range currentSnapshot.BackendCache {
		newBackendCache[k] = v
	}
	newBackendCache[url.String()] = backend

	// Create a new BackendSnapshot and atomically replace the old one.
	newSnapshot := &BackendSnapshot{
		Backends:     newBackends,
		BackendCache: newBackendCache,
	}
	s.backends.Store(newSnapshot)

	return nil
}

// RemoveBackend removes an existing backend from the ServerPool based on its URL.
// It updates the BackendSnapshot atomically to exclude the specified backend.
// Returns an error if the backend URL is invalid or if the backend does not exist in the pool.
func (s *ServerPool) RemoveBackend(backendURL string) error {
	// Parse the backend URL.
	url, err := url.Parse(backendURL)
	if err != nil {
		return err
	}

	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	backend, exists := currentSnapshot.BackendCache[url.String()]
	if !exists {
		return errors.New("backend not found")
	}

	newBackends := make([]*Backend, 0, len(currentSnapshot.Backends)-1)
	for _, b := range currentSnapshot.Backends {
		if b != backend {
			newBackends = append(newBackends, b)
		}
	}

	newBackendCache := make(map[string]*Backend, len(currentSnapshot.BackendCache)-1)
	for k, v := range currentSnapshot.BackendCache {
		if k != url.String() {
			newBackendCache[k] = v
		}
	}

	newSnapshot := &BackendSnapshot{
		Backends:     newBackends,
		BackendCache: newBackendCache,
	}
	s.backends.Store(newSnapshot)

	return nil
}

// GetNextPeer selects the next available backend based on the current load balancing algorithm.
// It returns the selected backend or nil if no suitable backend is available.
func (s *ServerPool) GetNextPeer() *Backend {
	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	backends := currentSnapshot.Backends
	backendCount := uint64(len(backends))

	if backendCount == 0 {
		return nil
	}

	if backendCount == 1 {
		if backends[0].Alive.Load() {
			return backends[0] // Only one backend and it's alive.
		}
		return nil
	}

	for i := uint64(0); i < backendCount; i++ {
		next := atomic.AddUint64(&s.current, 1)
		idx := next % backendCount
		if backends[idx].Alive.Load() {
			return backends[idx] // Return the first alive backend found.
		}
	}

	return nil
}

// MarkBackendStatus updates the alive status of a backend based on its URL.
// It is used by health checkers to mark backends as alive or dead.
func (s *ServerPool) MarkBackendStatus(backendUrl *url.URL, alive bool) {
	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	backend, exists := currentSnapshot.BackendCache[backendUrl.String()]
	if exists {
		backend.Alive.Store(alive) // Update the alive status.
	}
}

// GetBackends returns a slice of all backend servers converted to algorithm.Server type for use in load balancing algorithms.
func (s *ServerPool) GetBackends() []*algorithm.Server {
	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	currentBackends := currentSnapshot.Backends

	servers := make([]*algorithm.Server, len(currentBackends))
	for i, backend := range currentBackends {
		server := &algorithm.Server{
			URL:             backend.URL.String(),
			Weight:          backend.Weight,
			ConnectionCount: backend.ConnectionCount,
			MaxConnections:  backend.MaxConnections,
		}
		server.Alive.Store(backend.Alive.Load())
		server.CurrentWeight.Store(backend.CurrentWeight.Load())
		servers[i] = server
	}
	return servers
}

// UpdateBackends completely replaces the existing list of backends with a new set based on the provided configurations.
// It updates the load balancing algorithm and health check settings for each backend.
// Returns an error if any backend configuration is invalid.
func (s *ServerPool) UpdateBackends(configs []config.BackendConfig, serviceHealthCheck *config.HealthCheckConfig) error {
	newBackends := make([]*Backend, 0, len(configs))
	newBackendCache := make(map[string]*Backend, len(configs))

	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	currentBackendsMap := currentSnapshot.BackendCache

	for _, cfg := range configs {
		url, err := url.Parse(cfg.URL)
		if err != nil {
			return err
		}

		// Check if the backend already exists in the current backends.
		var existing *Backend
		if b, exists := currentBackendsMap[url.String()]; exists {
			existing = b
			existing.Weight = cfg.Weight
			if cfg.MaxConnections != 0 {
				existing.MaxConnections = cfg.MaxConnections
			}
			if cfg.HealthCheck.Type != "" {
				existing.HealthCheckCfg = cfg.HealthCheck
			}

			newBackends = append(newBackends, existing)
			newBackendCache[url.String()] = existing
		} else {
			// Create a new backend as it does not exist in the current pool.
			proxy := &httputil.ReverseProxy{}
			rp := NewReverseProxy(
				url,
				RouteConfig{},
				proxy,
				s.log,
			)

			maxConns := cfg.MaxConnections
			if maxConns == 0 {
				maxConns = s.GetMaxConnections() // Use pool's default if not specified.
			}

			backend := &Backend{
				URL:            url,
				Weight:         cfg.Weight,
				MaxConnections: maxConns,
				Proxy:          rp,
				HealthCheckCfg: serviceHealthCheck,
			}
			atomic.StoreInt32(&backend.SuccessCount, 0)
			atomic.StoreInt32(&backend.FailureCount, 0)
			backend.Alive.Store(true)
			newBackends = append(newBackends, backend)
			newBackendCache[url.String()] = backend
		}
	}

	newSnapshot := &BackendSnapshot{
		Backends:     newBackends,
		BackendCache: newBackendCache,
	}
	s.backends.Store(newSnapshot)

	return nil
}

// GetNextProxy retrieves the next available backend proxy based on the load balancing algorithm and increments its connection count.
// Returns the selected URLRewriteProxy or nil if no suitable backend is available.
func (s *ServerPool) GetNextProxy(r *http.Request) *URLRewriteProxy {
	if backend := s.GetNextPeer(); backend != nil {
		atomic.AddInt32(&backend.ConnectionCount, 1)
		return backend.Proxy
	}
	return nil
}

// GetBackendByURL retrieves a backend from the pool based on its URL.
// Returns the Backend if found, otherwise returns nil.
func (s *ServerPool) GetBackendByURL(url string) *Backend {
	// Load the current BackendSnapshot.
	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	return currentSnapshot.BackendCache[url]
}

// GetAllBackends returns a slice of all backends currently managed by the ServerPool.
func (s *ServerPool) GetAllBackends() []*Backend {
	// Load the current BackendSnapshot.
	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	return currentSnapshot.Backends
}

// UpdateConfig updates the ServerPool's configuration based on the provided PoolConfig.
// It allows changing the load balancing algorithm and the maximum number of connections dynamically.
func (s *ServerPool) UpdateConfig(update PoolConfig) {
	if update.MaxConns != 0 {
		s.maxConnections.Store(update.MaxConns)
	}

	if update.Algorithm != "" {
		s.algorithm.Store(algorithm.CreateAlgorithm(update.Algorithm))
	}
}

// GetConfig retrieves the current configuration of the ServerPool, including the load balancing algorithm and maximum connections.
func (s *ServerPool) GetConfig() PoolConfig {
	return PoolConfig{
		Algorithm: s.algorithm.Load().(algorithm.Algorithm).Name(),
		MaxConns:  s.maxConnections.Load(),
	}
}

// GetAlgorithm returns the current load balancing algorithm used by the ServerPool.
func (s *ServerPool) GetAlgorithm() algorithm.Algorithm {
	return s.algorithm.Load().(algorithm.Algorithm)
}

// SetAlgorithm sets a new load balancing algorithm for the ServerPool.
func (s *ServerPool) SetAlgorithm(algorithm algorithm.Algorithm) {
	s.algorithm.Store(algorithm)
}

// GetMaxConnections retrieves the current maximum number of connections allowed per backend.
func (s *ServerPool) GetMaxConnections() int32 {
	return s.maxConnections.Load()
}

// SetMaxConnections sets a new maximum number of connections allowed per backend.
func (s *ServerPool) SetMaxConnections(maxConns int32) {
	s.maxConnections.Store(maxConns)
}

// GetCurrentIndex retrieves the current index used for round-robin load balancing.
func (s *ServerPool) GetCurrentIndex() uint64 {
	return atomic.LoadUint64(&s.current)
}

// SetCurrentIndex sets the current index used for round-robin load balancing.
func (s *ServerPool) SetCurrentIndex(idx uint64) {
	atomic.StoreUint64(&s.current, idx)
}

// GetRetryFromContext extracts the retry count from the request's context.
// If no retry count is present, it returns 0.
// This is used to track the number of retry attempts for a given request.
func GetRetryFromContext(r *http.Request) int {
	if retry, ok := r.Context().Value(RetryKey).(int); ok {
		return retry
	}
	return 0
}
