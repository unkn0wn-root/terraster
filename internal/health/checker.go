package health

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/unkn0wn-root/terraster/internal/pool"
)

// Supported health check types
const (
	HealthCheckTypeHTTP = "http"
	HealthCheckTypeTCP  = "tcp"
)

// Checker periodically checks the health of backends in registered ServerPools.
type Checker struct {
	interval time.Duration
	timeout  time.Duration
	pools    []*pool.ServerPool
	mu       sync.RWMutex
	client   *http.Client
	logger   *log.Logger
	running  atomic.Bool
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// creates a new health checker with the given interval and timeout.
func NewChecker(interval, timeout time.Duration, logger *log.Logger) *Checker {
	return &Checker{
		interval: interval,
		timeout:  timeout,
		pools:    make([]*pool.ServerPool, 0),
		client: &http.Client{
			Timeout: timeout,
		},
		logger: logger,
	}
}

func (c *Checker) RegisterPool(p *pool.ServerPool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pools = append(c.pools, p)
}

// begins the health checking process.
func (c *Checker) Start(ctx context.Context) {
	if !c.running.CompareAndSwap(false, true) {
		c.logger.Println("Health checker already running")
		return
	}

	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		c.logger.Println("Health checker started")
		for {
			select {
			case <-ticker.C:
				c.checkAllPools()
			case <-ctx.Done():
				c.logger.Println("Health checker stopping")
				return
			}
		}
	}()
}

// gracefully stops the health checker.
func (c *Checker) Stop() {
	if c.running.Load() {
		c.cancel()
		c.wg.Wait()
		c.running.Store(false)
		c.logger.Println("Health checker stopped")
	}
}

// iterates over all registered server pools and checks their backends.
func (c *Checker) checkAllPools() {
	c.mu.RLock()
	pools := make([]*pool.ServerPool, len(c.pools))
	copy(pools, c.pools)
	c.mu.RUnlock()

	var wg sync.WaitGroup
	for _, p := range pools {
		wg.Add(1)
		go func(pool *pool.ServerPool) {
			defer wg.Done()
			c.checkPool(pool)
		}(p)
	}
	wg.Wait()
}

// performs health checks on all backends within a single ServerPool.
func (c *Checker) checkPool(s *pool.ServerPool) {
	backends := s.GetAllBackends()
	var wg sync.WaitGroup
	for _, backend := range backends {
		wg.Add(1)
		go func(b *pool.Backend) {
			defer wg.Done()
			c.checkBackend(b)
		}(backend)
	}
	wg.Wait()
}

// performs a health check on a single backend based on its type.
func (c *Checker) checkBackend(b *pool.Backend) {
	switch strings.ToLower(b.HealthCheckCfg.Type) {
	case HealthCheckTypeHTTP:
		c.performHTTPHealthCheck(b)
	case HealthCheckTypeTCP:
		c.performTCPHealthCheck(b)
	default:
		c.logger.Printf("Unsupported health check type '%s' for backend %s", b.HealthCheckCfg.Type, b.URL)
		c.updateBackendHealth(b, false)
	}
}

// http-based health check
func (c *Checker) performHTTPHealthCheck(b *pool.Backend) {
	healthPath := b.HealthCheckCfg.Path
	if healthPath == "" {
		healthPath = "/health" // default health path
	}

	healthURL := *b.URL
	healthURL.Path = healthPath

	req, err := http.NewRequest("GET", healthURL.String(), nil)
	if err != nil {
		c.logger.Printf("Failed to create HTTP health check request for %s: %v", b.URL, err)
		c.updateBackendHealth(b, false)
		return
	}

	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Printf("HTTP health check failed for %s: %v", b.URL, err)
		c.updateBackendHealth(b, false)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.updateBackendHealth(b, true)
	} else {
		c.logger.Printf("HTTP health check returned non-2xx for %s: %d", b.URL, resp.StatusCode)
		c.updateBackendHealth(b, false)
	}
}

// TCP-based health check.
func (c *Checker) performTCPHealthCheck(b *pool.Backend) {
	healthAddress := b.URL.Host
	host, port, err := net.SplitHostPort(healthAddress)
	if err != nil {
		// If port is missing, infer from scheme
		host = healthAddress
		if b.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	tcpAddress := net.JoinHostPort(host, port)

	conn, err := net.DialTimeout("tcp", tcpAddress, c.timeout)
	if err != nil {
		c.logger.Printf("TCP health check failed for %s: %v", b.URL, err)
		c.updateBackendHealth(b, false)
		return
	}
	conn.Close()
	c.updateBackendHealth(b, true)
}

// updates the backend's health status based on the check result.
func (c *Checker) updateBackendHealth(b *pool.Backend, healthy bool) {
	if healthy {
		newSuccess := atomic.AddInt32(&b.SuccessCount, 1)
		atomic.StoreInt32(&b.FailureCount, 0)
		if newSuccess >= int32(b.HealthCheckCfg.Thresholds.Healthy) {
			if !b.Alive.Load() {
				c.logger.Printf("Backend %s marked as healthy", b.URL)
				s := findServerPool(c.pools, b)
				if s != nil {
					s.MarkBackendStatus(b.URL, true)
				}
			}
		}
	} else {
		newFailure := atomic.AddInt32(&b.FailureCount, 1)
		atomic.StoreInt32(&b.SuccessCount, 0)
		if newFailure >= int32(b.HealthCheckCfg.Thresholds.Unhealthy) {
			if b.Alive.Load() {
				c.logger.Printf("Backend %s marked as unhealthy", b.URL)
				s := findServerPool(c.pools, b)
				if s != nil {
					s.MarkBackendStatus(b.URL, false)
				}
			}
		}
	}
}

// locates the ServerPool containing the specified backend.
func findServerPool(pools []*pool.ServerPool, backend *pool.Backend) *pool.ServerPool {
	for _, s := range pools {
		currentBackends := s.GetAllBackends()
		for _, b := range currentBackends {
			if b == backend {
				return s
			}
		}
	}
	return nil
}
