package service

import (
	"errors"
	"strings"
	"sync"

	"github.com/unkn0wn-root/go-load-balancer/internal/config"
	"github.com/unkn0wn-root/go-load-balancer/internal/pool"
)

var ErrServiceAlreadyExists = errors.New("service already exists")

type Manager struct {
	services map[string]*ServiceInfo
	mu       sync.RWMutex
}

type ServiceInfo struct {
	Name       string
	Host       string
	Path       string
	ServerPool *pool.ServerPool
}

func NewManager(cfg *config.Config) (*Manager, error) {
	m := &Manager{
		services: make(map[string]*ServiceInfo),
	}

	// If no services are defined in config, create a default service
	if len(cfg.Services) == 0 && len(cfg.Backends) > 0 {
		// Create default service
		defaultService := config.Service{
			Name:     "default",
			Host:     "",
			Path:     "",
			Backends: cfg.Backends,
		}
		if err := m.AddService(defaultService); err != nil {
			return nil, err
		}
	} else {
		for _, svc := range cfg.Services {
			if err := m.AddService(svc); err != nil {
				return nil, err
			}
		}
	}

	return m, nil
}

func (m *Manager) AddService(service config.Service) error {
	serverPool, err := m.createServerPool(service.Backends)
	if err != nil {
		return err
	}

	if _, exist := m.services[service.Path]; exist {
		return ErrServiceAlreadyExists
	}

	m.mu.Lock()
	m.services[service.Path] = &ServiceInfo{
		Name:       service.Name,
		Host:       service.Host,
		Path:       service.Path,
		ServerPool: serverPool,
	}
	m.mu.Unlock()

	return nil
}

func (m *Manager) GetService(host, path string) *ServiceInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// If there's only one service with empty path, return it
	if len(m.services) == 1 {
		for _, service := range m.services {
			return service
		}
	}

	// Find the most specific path match
	var matchedService *ServiceInfo
	var matchedLen int

	for _, service := range m.services {
		if service.Host != "" && !matchHost(service.Host, host) {
			continue
		}

		if strings.HasPrefix(path, service.Path) && len(service.Path) > matchedLen {
			matchedService = service
			matchedLen = len(service.Path)
		}
	}

	return matchedService
}

func (m *Manager) GetServiceByName(name string) []*ServiceInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	services := make([]*ServiceInfo, 0, len(m.services))

	for _, service := range m.services {
		if service.Name == name {
			services = append(services, service)
		}
	}
	return services
}

func (m *Manager) GetServices() []*ServiceInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	services := make([]*ServiceInfo, 0, len(m.services))
	for _, service := range m.services {
		services = append(services, service)
	}
	return services
}

func (m *Manager) createServerPool(backends []config.BackendConfig) (*pool.ServerPool, error) {
	serverPool := pool.NewServerPool()
	for _, backend := range backends {
		if err := serverPool.AddBackend(backend); err != nil {
			return nil, err
		}
	}
	return serverPool, nil
}

func matchHost(pattern, host string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == host
	}

	if pattern == "*" {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // Remove *
		return strings.HasSuffix(host, suffix)
	}

	return false
}
