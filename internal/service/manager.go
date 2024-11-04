package service

import (
	"strings"
	"sync"

	"github.com/unkn0wn-root/go-load-balancer/internal/config"
	"github.com/unkn0wn-root/go-load-balancer/internal/pool"
)

type Manager struct {
	services map[string]*ServiceInfo
	mu       sync.RWMutex
}

type ServiceInfo struct {
	Name       string
	Path       string
	ServerPool *pool.ServerPool
}

func NewManager(cfg *config.Config) *Manager {
	m := &Manager{
		services: make(map[string]*ServiceInfo),
	}

	serverPool := pool.NewServerPool()
	// If no services are defined in config, create a default service
	if len(cfg.Services) == 0 && len(cfg.Backends) > 0 {
		// Create default service
		for _, backend := range cfg.Backends {
			serverPool.AddBackend(backend)
		}

		// Add as default service with empty path
		m.services[""] = &ServiceInfo{
			Name:       "default",
			Path:       "",
			ServerPool: serverPool,
		}
	} else {
		for _, svc := range cfg.Services {
			m.AddService(svc)
		}
	}

	return m
}

func (m *Manager) AddService(service config.Service) error {
	serverPool := pool.NewServerPool()
	for _, backend := range service.Backends {
		if err := serverPool.AddBackend(backend); err != nil {
			return err
		}
	}

	m.mu.Lock()
	m.services[service.Path] = &ServiceInfo{
		Name:       service.Name,
		Path:       service.Path,
		ServerPool: serverPool,
	}
	m.mu.Unlock()

	return nil
}

func (m *Manager) GetServiceForPath(path string) *ServiceInfo {
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

	for servicePath, service := range m.services {
		if strings.HasPrefix(path, servicePath) {
			if len(servicePath) > matchedLen {
				matchedService = service
				matchedLen = len(servicePath)
			}
		}
	}

	return matchedService
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
