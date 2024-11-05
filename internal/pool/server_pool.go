package pool

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/unkn0wn-root/go-load-balancer/internal/config"
	"github.com/unkn0wn-root/go-load-balancer/pkg/algorithm"
)

type contextKey int

const (
	RetryKey contextKey = iota
)

type Config struct {
	Algorithm string `json:"algorithm"`
	MaxConns  int    `json:"max_connections"`
}

type ServerPool struct {
	backends       []*Backend
	current        uint64
	algorithm      string
	maxConnections int
	mu             sync.RWMutex
}

func NewServerPool() *ServerPool {
	return &ServerPool{
		backends:       make([]*Backend, 0),
		algorithm:      "round-robin", // default algorithm
		maxConnections: 1000,          // default max connections
	}
}

func (s *ServerPool) UpdateConfig(update Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if update.MaxConns != 0 {
		s.maxConnections = update.MaxConns
	}

	if update.Algorithm != "" {
		s.algorithm = update.Algorithm
	}

	return nil
}

func (s *ServerPool) GetConfig() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return Config{
		Algorithm: s.algorithm,
		MaxConns:  s.maxConnections,
	}
}
func (s *ServerPool) GetAlgorithm() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.algorithm
}

func (s *ServerPool) SetAlgorithm(algorithm string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.algorithm = algorithm
	return nil
}

func (s *ServerPool) GetMaxConnections() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxConnections
}

func (s *ServerPool) SetMaxConnections(maxConns int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxConnections = maxConns
	return nil
}

func (s *ServerPool) GetCurrentIndex() uint64 {
	return atomic.LoadUint64(&s.current)
}

func (s *ServerPool) SetCurrentIndex(idx uint64) {
	atomic.StoreUint64(&s.current, idx)
}

func (s *ServerPool) AddBackend(cfg config.BackendConfig) error {
	url, err := url.Parse(cfg.URL)
	if err != nil {
		return err
	}

	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.ModifyResponse = func(r *http.Response) error {
		r.Header.Del("Server")
		r.Header.Del("X-Powered-By")

		r.Header.Set("X-Proxy-By", "go-load-balancer")

		return nil
	}

	proxy.BufferPool = NewBufferPool()

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
				http.Error(w, "No proxy server available right now", http.StatusServiceUnavailable)
			}
		}
	}

	// Custom transport with timeouts and connection pooling
	// proxy.Transport = &http.Transport{
	//     Proxy: http.ProxyFromEnvironment,
	//     DialContext: (&net.Dialer{
	//         Timeout:   30 * time.Second,
	//         KeepAlive: 30 * time.Second,
	//     }).DialContext,
	//     ForceAttemptHTTP2:     true,
	//     MaxIdleConns:          100,
	//     IdleConnTimeout:       90 * time.Second,
	//     TLSHandshakeTimeout:   10 * time.Second,
	//     ExpectContinueTimeout: 1 * time.Second,
	//     MaxConnsPerHost:       10,
	//     MaxIdleConnsPerHost:   10,
	//     TLSClientConfig: &tls.Config{
	//         InsecureSkipVerify: false, // set to true if you need to skip SSL verification
	//     },
	// },

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

func (s *ServerPool) GetBackends() []*algorithm.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()

	servers := make([]*algorithm.Server, len(s.backends))
	for i, backend := range s.backends {
		servers[i] = &algorithm.Server{
			URL:             backend.URL.String(),
			Weight:          backend.Weight,
			CurrentWeight:   backend.CurrentWeight,
			ConnectionCount: backend.ConnectionCount,
			Alive:           backend.Alive,
		}
	}
	return servers
}

// Add method to update backends from config
func (s *ServerPool) UpdateBackends(configs []config.BackendConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	newBackends := make([]*Backend, 0)

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

	s.backends = newBackends
	return nil
}

func (s *ServerPool) GetNextProxy(r *http.Request) *httputil.ReverseProxy {
	if backend := s.GetNextPeer(); backend != nil {
		atomic.AddInt32(&backend.ConnectionCount, 1)
		return backend.ReverseProxy
	}
	return nil
}

func (s *ServerPool) GetBackendByURL(url string) *Backend {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, backend := range s.backends {
		if backend.URL.String() == url {
			return backend
		}
	}
	return nil
}

type Backend struct {
	URL             *url.URL
	Host            string
	Alive           bool
	Weight          int
	CurrentWeight   int
	ReverseProxy    *httputil.ReverseProxy
	ConnectionCount int32
	mu              sync.RWMutex
}

func (b *Backend) GetURL() string {
	return b.URL.String()
}

func (b *Backend) GetWeight() int {
	return b.Weight
}

func (b *Backend) GetCurrentWeight() int {
	return b.CurrentWeight
}

func (b *Backend) SetCurrentWeight(weight int) {
	b.CurrentWeight = weight
}

func (b *Backend) GetConnectionCount() int {
	return int(atomic.LoadInt32(&b.ConnectionCount))
}

func (b *Backend) IsAlive() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Alive
}

func (b *Backend) IncrementConnections() {
	atomic.AddInt32(&b.ConnectionCount, 1)
}

func (b *Backend) DecrementConnections() {
	atomic.AddInt32(&b.ConnectionCount, -1)
}

// Helper function for retry context
func GetRetryFromContext(r *http.Request) int {
	if retry, ok := r.Context().Value(RetryKey).(int); ok {
		return retry
	}
	return 0
}
