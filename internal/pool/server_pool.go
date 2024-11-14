package pool

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"

	"github.com/unkn0wn-root/terraster/internal/config"
	"github.com/unkn0wn-root/terraster/pkg/algorithm"
)

type contextKey int

const (
	RetryKey contextKey = iota
)

type PoolConfig struct {
	Algorithm string `json:"algorithm"`
	MaxConns  int32  `json:"max_connections"`
}

type ServerPool struct {
	backends       atomic.Value
	current        uint64
	algorithm      atomic.Value
	maxConnections atomic.Int32
}

func NewServerPool() *ServerPool {
	pool := &ServerPool{}
	pool.backends.Store([]*Backend{})
	pool.algorithm.Store(algorithm.CreateAlgorithm("round-robin"))
	pool.maxConnections.Store(1000)
	return pool
}

func (s *ServerPool) AddBackend(cfg config.BackendConfig, rc RouteConfig) error {
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
		WithURLRewriter(rc, url),
	)
	rp.proxy.BufferPool = NewBufferPool()
	rp.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// A canceled context usually means the client disconnected
		// or the request was canceled, not that the backend is unhealthy.
		if err == context.Canceled {
			return
		}
		s.MarkBackendStatus(url, false)
		retries := GetRetryFromContext(r)
		if retries < 3 {
			select {
			case <-r.Context().Done():
				return
			default:
				proxy := s.GetNextProxy(r)
				if proxy != nil {
					proxy.ServeHTTP(w, r)
					return
				}
				http.Error(w, "No proxy server available right now", http.StatusServiceUnavailable)
			}
		}
	}

	maxConnections := cfg.MaxConnections
	if maxConnections == 0 {
		maxConnections = s.GetMaxConnections()
	}

	backend := &Backend{
		URL:            url,
		Weight:         cfg.Weight,
		MaxConnections: maxConnections,
		Proxy:          rp,
	}
	backend.Alive.Store(true)

	currentBackends := s.backends.Load().([]*Backend)
	// Create new slice with added backend
	newBackends := make([]*Backend, len(currentBackends)+1)
	copy(newBackends, currentBackends)
	newBackends[len(currentBackends)] = backend

	// Atomically replace the backends slice
	s.backends.Store(newBackends)
	return nil
}

func (s *ServerPool) RemoveBackend(backendURL string) error {
	url, err := url.Parse(backendURL)
	if err != nil {
		return err
	}

	currentBackends := s.backends.Load().([]*Backend)
	// Find and remove the backend
	found := false
	newBackends := make([]*Backend, 0, len(currentBackends))

	for _, backend := range currentBackends {
		if backend.URL.String() != url.String() {
			newBackends = append(newBackends, backend)
		} else {
			found = true
		}
	}

	if !found {
		return errors.New("backend not found")
	}

	// Atomically replace the backends slice
	s.backends.Store(newBackends)
	return nil
}

func (s *ServerPool) GetNextPeer() *Backend {
	// Get current backends snapshot without locks
	backends := s.backends.Load().([]*Backend)
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
	backends := s.backends.Load().([]*Backend)

	for _, b := range backends {
		if b.URL.String() == backendUrl.String() {
			b.Alive.Store(alive)
			break
		}
	}
}

func (s *ServerPool) GetBackends() []*algorithm.Server {
	currentBackends := s.backends.Load().([]*Backend)

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
func (s *ServerPool) UpdateBackends(configs []config.BackendConfig) error {
	newBackends := make([]*Backend, 0, len(configs))

	for _, cfg := range configs {
		url, err := url.Parse(cfg.URL)
		if err != nil {
			return err
		}

		// Check if backend already exists in current backends
		currentBackends := s.backends.Load().([]*Backend)
		var existing *Backend
		for _, b := range currentBackends {
			if b.URL.String() == url.String() {
				existing = b
				break
			}
		}

		if existing != nil {
			// Update existing backend
			existing.Weight = cfg.Weight
			newBackends = append(newBackends, existing)
		} else {
			// Create new backend
			proxy := &httputil.ReverseProxy{}
			rp := NewReverseProxy(
				url,
				RouteConfig{},
				proxy,
			)

			backend := &Backend{
				URL:    url,
				Weight: cfg.Weight,
				Proxy:  rp,
			}
			backend.Alive.Store(true)
			newBackends = append(newBackends, backend)
		}
	}

	// Atomically replace entire backend list
	s.backends.Store(newBackends)
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
	currentBackends := s.backends.Load().([]*Backend)

	for _, backend := range currentBackends {
		if backend.URL.String() == url {
			return backend
		}
	}
	return nil
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

type Backend struct {
	URL             *url.URL
	Host            string
	Alive           atomic.Bool
	Weight          int
	CurrentWeight   atomic.Int32
	Proxy           *URLRewriteProxy
	ConnectionCount int32
	MaxConnections  int32
}

func (b *Backend) GetURL() string {
	return b.URL.String()
}

func (b *Backend) GetWeight() int {
	return b.Weight
}

func (b *Backend) GetCurrentWeight() int {
	return int(b.CurrentWeight.Load())
}

func (b *Backend) SetCurrentWeight(weight int) {
	b.CurrentWeight.Store(int32(weight))
}

func (b *Backend) GetConnectionCount() int {
	return int(atomic.LoadInt32(&b.ConnectionCount))
}

func (b *Backend) IsAlive() bool {
	return b.Alive.Load()
}

func (b *Backend) SetAlive(alive bool) {
	b.Alive.Store(alive)
}

func (b *Backend) IncrementConnections() bool {
	for {
		current := atomic.LoadInt32(&b.ConnectionCount)
		if current >= int32(b.MaxConnections) {
			return false
		}
		if atomic.CompareAndSwapInt32(&b.ConnectionCount, current, current+1) {
			return true
		}
	}
}

func (b *Backend) DecrementConnections() {
	atomic.AddInt32(&b.ConnectionCount, -1)
}

// helper function for retry context
func GetRetryFromContext(r *http.Request) int {
	if retry, ok := r.Context().Value(RetryKey).(int); ok {
		return retry
	}
	return 0
}
