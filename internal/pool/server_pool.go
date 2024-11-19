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
	RetryKey contextKey = iota
)

type PoolConfig struct {
	Algorithm string `json:"algorithm"`
	MaxConns  int32  `json:"max_connections"`
}

type BackendSnapshot struct {
	Backends     []*Backend
	BackendCache map[string]*Backend
}

type ServerPool struct {
	backends       atomic.Value
	current        uint64
	algorithm      atomic.Value
	maxConnections atomic.Int32
	log            *zap.Logger
}

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

func (s *ServerPool) AddBackend(
	cfg config.BackendConfig,
	rc RouteConfig,
	hcCfg *config.HealthCheckConfig,
) error {
	url, err := url.Parse(cfg.URL)
	if err != nil {
		return err
	}

	// Create one reverse proxy for multiple backends
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
		maxConnections = s.GetMaxConnections()
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
	backend.Alive.Store(true)
	atomic.StoreInt32(&backend.SuccessCount, 0)
	atomic.StoreInt32(&backend.FailureCount, 0)

	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	// Create new slice with added backend
	newBackends := make([]*Backend, len(currentSnapshot.Backends)+1)
	copy(newBackends, currentSnapshot.Backends)
	newBackends[len(currentSnapshot.Backends)] = backend

	// Create a new map with the added backend
	newBackendCache := make(map[string]*Backend, len(currentSnapshot.BackendCache)+1)
	for k, v := range currentSnapshot.BackendCache {
		newBackendCache[k] = v
	}
	newBackendCache[url.String()] = backend

	// Create a new snapshot and atomically replace it
	newSnapshot := &BackendSnapshot{
		Backends:     newBackends,
		BackendCache: newBackendCache,
	}
	s.backends.Store(newSnapshot)
	return nil
}

func (s *ServerPool) RemoveBackend(backendURL string) error {
	url, err := url.Parse(backendURL)
	if err != nil {
		return err
	}

	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	backend, exists := currentSnapshot.BackendCache[url.String()]
	if !exists {
		return errors.New("backend not found")
	}

	// Remove from slice
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

	// Create a new snapshot and atomically replace it
	newSnapshot := &BackendSnapshot{
		Backends:     newBackends,
		BackendCache: newBackendCache,
	}
	s.backends.Store(newSnapshot)
	return nil
}

func (s *ServerPool) GetNextPeer() *Backend {
	// Get current backends snapshot without locks
	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	backends := currentSnapshot.Backends
	backendCount := uint64(len(backends))

	if backendCount == 0 {
		return nil
	}

	if backendCount == 1 {
		if backends[0].Alive.Load() {
			return backends[0]
		}
		return nil
	}

	// Try up to backendCount times to find an alive backend
	for i := uint64(0); i < backendCount; i++ {
		next := atomic.AddUint64(&s.current, 1)
		idx := next % backendCount
		if backends[idx].Alive.Load() {
			return backends[idx]
		}
	}

	return nil
}

func (s *ServerPool) MarkBackendStatus(backendUrl *url.URL, alive bool) {
	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	backend, exists := currentSnapshot.BackendCache[backendUrl.String()]
	if exists {
		backend.Alive.Store(alive)
	}
}

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

// UpdateBackends completely replaces the backend list
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

		// Check if backend already exists in current backends
		var existing *Backend
		if b, exists := currentBackendsMap[url.String()]; exists {
			existing = b
			// Update existing backend
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
			// Create new backend
			proxy := &httputil.ReverseProxy{}
			rp := NewReverseProxy(
				url,
				RouteConfig{},
				proxy,
				s.log,
			)

			maxConns := cfg.MaxConnections
			if maxConns == 0 {
				maxConns = s.GetMaxConnections()
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

	// Create a new snapshot and atomically replace it
	newSnapshot := &BackendSnapshot{
		Backends:     newBackends,
		BackendCache: newBackendCache,
	}
	s.backends.Store(newSnapshot)
	return nil
}

func (s *ServerPool) GetNextProxy(r *http.Request) *URLRewriteProxy {
	if backend := s.GetNextPeer(); backend != nil {
		atomic.AddInt32(&backend.ConnectionCount, 1)
		return backend.Proxy
	}
	return nil
}

func (s *ServerPool) GetBackendByURL(url string) *Backend {
	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	return currentSnapshot.BackendCache[url]
}

func (s *ServerPool) GetAllBackends() []*Backend {
	currentSnapshot := s.backends.Load().(*BackendSnapshot)
	return currentSnapshot.Backends
}

func (s *ServerPool) UpdateConfig(update PoolConfig) {
	if update.MaxConns != 0 {
		s.maxConnections.Store(update.MaxConns)
	}

	if update.Algorithm != "" {
		s.algorithm.Store(algorithm.CreateAlgorithm(update.Algorithm))
	}
}

func (s *ServerPool) GetConfig() PoolConfig {
	return PoolConfig{
		Algorithm: s.algorithm.Load().(algorithm.Algorithm).Name(),
		MaxConns:  s.maxConnections.Load(),
	}
}
func (s *ServerPool) GetAlgorithm() algorithm.Algorithm {
	return s.algorithm.Load().(algorithm.Algorithm)
}

func (s *ServerPool) SetAlgorithm(algorithm algorithm.Algorithm) {
	s.algorithm.Store(algorithm)
}

func (s *ServerPool) GetMaxConnections() int32 {
	return s.maxConnections.Load()
}

func (s *ServerPool) SetMaxConnections(maxConns int32) {
	s.maxConnections.Store(maxConns)
}

func (s *ServerPool) GetCurrentIndex() uint64 {
	return atomic.LoadUint64(&s.current)
}

func (s *ServerPool) SetCurrentIndex(idx uint64) {
	atomic.StoreUint64(&s.current, idx)
}

// helper function for retry context
func GetRetryFromContext(r *http.Request) int {
	if retry, ok := r.Context().Value(RetryKey).(int); ok {
		return retry
	}
	return 0
}
