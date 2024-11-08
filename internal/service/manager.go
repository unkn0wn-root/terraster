package service

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/unkn0wn-root/go-load-balancer/internal/config"
	"github.com/unkn0wn-root/go-load-balancer/internal/pool"
	"github.com/unkn0wn-root/go-load-balancer/pkg/algorithm"
)

var (
	ErrServiceAlreadyExists = errors.New("service already exists")
	ErrDuplicateLocation    = errors.New("duplicate location path")
	ErrNotDefined           = errors.New("service must have either host or name defined")
)

type Manager struct {
	services map[string]*ServiceInfo
	mu       sync.RWMutex
}

// ServiceInfo contains information about a service
// e.g. name: api service, host: api.example.com
type ServiceInfo struct {
	Name         string
	Host         string
	Port         int
	TLS          *config.TLSConfig
	HTTPRedirect bool
	Locations    []*LocationInfo
}

// LocationInfo contains information about a path location
// e.g. /api, /v1, /v2
type LocationInfo struct {
	Path       string
	Rewrite    string
	Algorithm  algorithm.Algorithm
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
			Name: "default",
			Host: "",
			Locations: []config.Location{
				{
					Path:         "",
					LoadBalancer: "round-robin",
					Backends:     cfg.Backends,
				},
			},
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
	// For each location in the service, create a server pool
	locations := make([]*LocationInfo, 0, len(service.Locations))
	locationPaths := make(map[string]bool)
	for _, location := range service.Locations {
		if location.Path == "" {
			location.Path = "/"
		}

		if _, exist := locationPaths[location.Path]; exist {
			return ErrDuplicateLocation
		}

		if len(location.Backends) == 0 {
			return fmt.Errorf("service %s, location %s: no backends defined",
				service.Name, location.Path)
		}

		locationPaths[location.Path] = true

		serverPool, err := m.createServerPool(location)
		if err != nil {
			return err
		}

		locations = append(locations, &LocationInfo{
			Path:       location.Path,
			Algorithm:  algorithm.CreateAlgorithm(location.LoadBalancer),
			Rewrite:    location.Rewrite,
			ServerPool: serverPool,
		})
	}

	//use host as key, if empty use service name
	k := service.Host
	if k == "" {
		k = service.Name
	}

	if k == "" {
		return ErrNotDefined
	}

	if _, exist := m.services[k]; exist {
		return ErrServiceAlreadyExists
	}

	m.mu.Lock()
	m.services[k] = &ServiceInfo{
		Name:         service.Name,
		Host:         service.Host,
		Port:         service.Port,
		TLS:          service.TLS,
		HTTPRedirect: service.HTTPRedirect,
		Locations:    locations,
	}
	m.mu.Unlock()

	return nil
}

func (m *Manager) GetService(host, path string, hostOnly bool) (*ServiceInfo, *LocationInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matchedService *ServiceInfo
	for _, service := range m.services {
		if matchHost(service.Host, host) {
			if hostOnly {
				return service, nil, nil
			}
			matchedService = service
			break
		}
	}

	if matchedService == nil {
		return nil, nil, fmt.Errorf("service not found for host %s", host)
	}

	var matchedLocation *LocationInfo
	var matchedLen int
	for _, location := range matchedService.Locations {
		if strings.HasPrefix(path, location.Path) && len(location.Path) > matchedLen {
			matchedLocation = location
			matchedLen = len(location.Path)
		}
	}

	if matchedLocation == nil {
		return nil, nil, fmt.Errorf("location not found for path %s", path)
	}

	return matchedService, matchedLocation, nil
}

func (m *Manager) GetServiceByName(name string) *ServiceInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, service := range m.services {
		if service.Name == name {
			return service
		}
	}

	return nil
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

func (m *Manager) createServerPool(srvc config.Location) (*pool.ServerPool, error) {
	serverPool := pool.NewServerPool()
	serverPool.UpdateConfig(pool.PoolConfig{
		Algorithm: srvc.LoadBalancer,
	})
	for _, backend := range srvc.Backends {
		rc := pool.RouteConfig{
			Path:       srvc.Path,
			RewriteURL: srvc.Rewrite,
		}
		if err := serverPool.AddBackend(backend, rc); err != nil {
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
