package pool

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/unkn0wn-root/go-load-balancer/internal/config"
)

type ServerPool struct {
	backends []*Backend
	current  uint64
	mu       sync.RWMutex
}

type Backend struct {
	URL             *url.URL
	Alive           bool
	Weight          int
	CurrentWeight   int
	ReverseProxy    *httputil.ReverseProxy
	ConnectionCount int32
	mu              sync.RWMutex
}

func NewServerPool() *ServerPool {
	return &ServerPool{
		backends: make([]*Backend, 0),
	}
}

func (s *ServerPool) AddBackend(cfg config.BackendConfig) error {
	url, err := url.Parse(cfg.URL)
	if err != nil {
		return err
	}

	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
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
				http.Error(w, "Service not available", http.StatusServiceUnavailable)
			}
		}
	}

	backend := &Backend{
		URL:          url,
		Alive:        true,
		Weight:       cfg.Weight,
		ReverseProxy: proxy,
	}

	s.mu.Lock()
	s.backends = append(s.backends, backend)
	s.mu.Unlock()

	return nil
}

// Add the RemoveBackend method
func (s *ServerPool) RemoveBackend(backendURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	url, err := url.Parse(backendURL)
	if err != nil {
		return err
	}

	for i, backend := range s.backends {
		if backend.URL.String() == url.String() {
			// Remove the backend by creating a new slice without it
			s.backends = append(s.backends[:i], s.backends[i+1:]...)
			return nil
		}
	}

	return errors.New("backend not found")
}

func (s *ServerPool) GetNextPeer() *Backend {
	next := atomic.AddUint64(&s.current, 1)
	s.mu.RLock()
	defer s.mu.RUnlock()
	l := len(s.backends)
	if l == 0 {
		return nil
	}
	return s.backends[next%uint64(l)]
}

func (s *ServerPool) MarkBackendStatus(backendUrl *url.URL, alive bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, b := range s.backends {
		if b.URL.String() == backendUrl.String() {
			b.mu.Lock()
			b.Alive = alive
			b.mu.Unlock()
			break
		}
	}
}

func (s *ServerPool) GetBackends() []*Backend {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*Backend{}, s.backends...)
}

// Add method to update backends from config
func (s *ServerPool) UpdateBackends(configs []BackendConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create new backends slice
	newBackends := make([]*Backend, 0)

	// Add or update backends
	for _, cfg := range configs {
		url, err := url.Parse(cfg.URL)
		if err != nil {
			return err
		}

		// Check if backend already exists
		var existing *Backend
		for _, b := range s.backends {
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
			proxy := httputil.NewSingleHostReverseProxy(url)
			backend := &Backend{
				URL:          url,
				Alive:        true,
				Weight:       cfg.Weight,
				ReverseProxy: proxy,
			}
			newBackends = append(newBackends, backend)
		}
	}

	// Replace backends slice
	s.backends = newBackends
	return nil
}

// Add method to get next proxy
func (s *ServerPool) GetNextProxy(r *http.Request) *httputil.ReverseProxy {
	if backend := s.GetNextPeer(); backend != nil {
		atomic.AddInt32(&backend.ConnectionCount, 1)
		return backend.ReverseProxy
	}
	return nil
}

// Add method to increment/decrement connection count
func (b *Backend) IncrementConnections() {
	atomic.AddInt32(&b.ConnectionCount, 1)
}

func (b *Backend) DecrementConnections() {
	atomic.AddInt32(&b.ConnectionCount, -1)
}

type BackendConfig struct {
	URL    string `yaml:"url"`
	Weight int    `yaml:"weight"`
}

// Helper function for retry context
func GetRetryFromContext(r *http.Request) int {
	if retry, ok := r.Context().Value(RetryKey).(int); ok {
		return retry
	}
	return 0
}

type contextKey int

const (
	RetryKey contextKey = iota
)
