package health

import (
	"context"
	"log"
	"sync"
	"time"
)

type Checker struct {
	mu       sync.RWMutex
	backends map[string]*Backend
	interval time.Duration
	timeout  time.Duration
	checkers map[string]HealthChecker
	stopCh   chan struct{}
}

type Backend struct {
	URL       string
	Alive     bool
	Failures  int
	Successes int
	Config    HealthCheckConfig
}

type HealthCheckConfig struct {
	Type               string
	Path               string
	Interval           time.Duration
	Timeout            time.Duration
	HealthyThreshold   int
	UnhealthyThreshold int
}

type HealthChecker interface {
	Check(url string) error
}

func NewChecker(interval, timeout time.Duration) *Checker {
	return &Checker{
		backends: make(map[string]*Backend),
		interval: interval,
		timeout:  timeout,
		checkers: make(map[string]HealthChecker),
		stopCh:   make(chan struct{}),
	}
}

func (c *Checker) AddBackend(url string, config HealthCheckConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.backends[url] = &Backend{
		URL:    url,
		Alive:  true,
		Config: config,
	}

	// Create appropriate checker
	switch config.Type {
	case "http":
		c.checkers[url] = NewHTTPChecker(config.Timeout)
	case "tcp":
		c.checkers[url] = NewTCPChecker(config.Timeout)
	}
}

func (c *Checker) Start(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.checkAll()
		case <-c.stopCh:
			return
		}
	}
}

func (c *Checker) checkAll() {
	var wg sync.WaitGroup

	c.mu.RLock()
	for url, backend := range c.backends {
		wg.Add(1)
		go func(url string, backend *Backend) {
			defer wg.Done()
			c.checkBackend(url, backend)
		}(url, backend)
	}
	c.mu.RUnlock()

	wg.Wait()
}

func (c *Checker) checkBackend(url string, backend *Backend) {
	checker := c.checkers[url]
	if checker == nil {
		return
	}

	err := checker.Check(url)

	c.mu.Lock()
	defer c.mu.Unlock()

	if err != nil {
		backend.Failures++
		backend.Successes = 0
		if backend.Failures >= backend.Config.UnhealthyThreshold {
			if backend.Alive {
				log.Printf("Backend %s is now unhealthy", url)
				backend.Alive = false
			}
		}
	} else {
		backend.Successes++
		backend.Failures = 0
		if backend.Successes >= backend.Config.HealthyThreshold {
			if !backend.Alive {
				log.Printf("Backend %s is now healthy", url)
				backend.Alive = true
			}
		}
	}
}

func (c *Checker) Stop() {
	close(c.stopCh)
}
