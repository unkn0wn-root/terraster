package service

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/unkn0wn-root/terraster/internal/config"
	"github.com/unkn0wn-root/terraster/internal/pool"
	"github.com/unkn0wn-root/terraster/pkg/algorithm"
	"go.uber.org/zap"
)

var (
	// ErrServiceAlreadyExists is returned when attempting to add a service that already exists in the manager.
	ErrServiceAlreadyExists = errors.New("service already exists")
	// ErrDuplicateLocation is returned when a service is configured with duplicate location paths.
	ErrDuplicateLocation = errors.New("duplicate location path")
	// ErrNotDefined is returned when a service does not have either a host or name defined.
	ErrNotDefined = errors.New("service must have either host or name defined")
)

// ServiceType represents the type of service protocol, either HTTP or HTTPS.
type ServiceType string

const (
	// HTTP represents the HTTP protocol for a service.
	HTTP ServiceType = "http"
	// HTTPS represents the HTTPS protocol for a service.
	HTTPS ServiceType = "https"
)

// Manager is responsible for managing all the services within the Terraster application.
// It handles the addition, retrieval, and configuration of services, ensuring thread-safe access.
type Manager struct {
	services map[string]*ServiceInfo // A map of service identifiers to their corresponding ServiceInfo.
	logger   *zap.Logger             // Logger instance for logging service manager activities.
	mu       sync.RWMutex            // Mutex to ensure thread-safe access to the services map.
}

// ServiceInfo contains comprehensive information about a service, including its routing and backend configurations.
// It encapsulates details such as the service's name, host, port, TLS settings, and associated locations.
type ServiceInfo struct {
	Name         string                    // The unique name of the service.
	Host         string                    // The host address where the service is accessible.
	Port         int                       // The port number on which the service listens.
	TLS          *config.TLSConfig         // TLS configuration for the service, if HTTPS is enabled.
	HTTPRedirect bool                      // Indicates whether HTTP requests should be redirected to HTTPS.
	RedirectPort int                       // The port to which HTTP requests are redirected for HTTPS.
	HealthCheck  *config.HealthCheckConfig // Health check configuration specific to the service.
	Locations    []*LocationInfo           // A slice of LocationInfo representing different routing paths for the service.
}

// ServiceType determines the protocol type of the service based on its TLS configuration.
// It returns HTTPS if TLS is enabled, otherwise HTTP.
func (s *ServiceInfo) ServiceType() ServiceType {
	if s.TLS != nil && s.TLS.Enabled {
		return HTTPS
	}
	return HTTP
}

// LocationInfo contains routing and backend information for a specific path within a service.
// It defines how incoming requests matching the path should be handled and which backend servers to proxy to.
type LocationInfo struct {
	Path       string              // The URL path that this location handles.
	Rewrite    string              // The URL rewrite rule applied to incoming requests.
	Algorithm  algorithm.Algorithm // The load balancing algorithm used to select a backend server.
	ServerPool *pool.ServerPool    // The pool of backend servers associated with this location.
}

// NewManager initializes and returns a new instance of Manager.
// It sets up services based on the provided configuration and initializes their respective server pools.
// If no services are defined in the configuration but backends are provided, it creates a default service.
// Returns an error if any service fails to be added during initialization.
func NewManager(cfg *config.Config, logger *zap.Logger) (*Manager, error) {
	m := &Manager{
		services: make(map[string]*ServiceInfo),
		logger:   logger,
	}

	// If no services are defined in the config but backends are provided, create a default service.
	if len(cfg.Services) == 0 && len(cfg.Backends) > 0 {
		defaultService := config.Service{
			Name: "default",
			Host: "localhost",
			Port: 8080,
			Locations: []config.Location{
				{
					Path:         "",
					LoadBalancer: "round-robin",
					Backends:     cfg.Backends,
				},
			},
		}
		if err := m.AddService(defaultService, cfg.HealthCheck); err != nil {
			return nil, err
		}
	} else {
		for _, svc := range cfg.Services {
			// Use the global health check configuration if the service does not have a specific one.
			hcCfg := svc.HealthCheck
			if hcCfg == nil {
				hcCfg = cfg.HealthCheck
			}
			if err := m.AddService(svc, hcCfg); err != nil {
				return nil, err
			}
		}
	}

	return m, nil
}

// AddService adds a new service to the Manager with the provided configuration and health check settings.
// It processes each location within the service, creates corresponding server pools, and ensures no duplicate services or locations exist.
// Returns an error if the service already exists, if there are duplicate locations, or if required fields are missing.
func (m *Manager) AddService(service config.Service, globalHealthCheck *config.HealthCheckConfig) error {
	locations := make([]*LocationInfo, 0, len(service.Locations))
	locationPaths := make(map[string]bool)
	for _, location := range service.Locations {
		if location.Path == "" {
			location.Path = "/"
		}

		// Check for duplicate location paths within the service.
		if _, exist := locationPaths[location.Path]; exist {
			return ErrDuplicateLocation
		}

		// Ensure that each location has at least one backend defined.
		if len(location.Backends) == 0 {
			return fmt.Errorf("service %s, location %s: no backends defined",
				service.Name, location.Path)
		}

		locationPaths[location.Path] = true

		serverPool, err := m.createServerPool(location, globalHealthCheck)
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

	// Determine the key for the service map. Use the service name if available; otherwise, use the host.
	k := service.Name
	if k == "" {
		k = service.Host
	}

	if k == "" {
		return ErrNotDefined
	}

	if _, exist := m.services[k]; exist {
		return ErrServiceAlreadyExists
	}

	// Determine the health check configuration for the service.
	// Use the service-specific configuration if provided; otherwise, fallback to the global configuration.
	serviceHealthCheck := globalHealthCheck
	if service.HealthCheck != nil && service.HealthCheck.Type != "" {
		serviceHealthCheck = service.HealthCheck
	}

	m.mu.Lock()
	m.services[k] = &ServiceInfo{
		Name:         service.Name,
		Host:         service.Host,
		Port:         service.Port,
		TLS:          service.TLS,
		HTTPRedirect: service.HTTPRedirect, // Indicates if HTTP should be redirected to HTTPS.
		RedirectPort: service.RedirectPort, // Custom port for redirection if applicable.
		HealthCheck:  serviceHealthCheck,
		Locations:    locations, // Associated locations with their backends.
	}
	m.mu.Unlock()

	return nil
}

// GetService retrieves the service and location information based on the provided host, path, and port.
// If hostOnly is true, it returns only the ServiceInfo without matching a specific location.
// It returns an error if the service or location is not found.
func (m *Manager) GetService(
	host, path string,
	port int,
	hostOnly bool,
) (*ServiceInfo, *LocationInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matchedService *ServiceInfo
	for _, service := range m.services {
		if matchHost(service.Host, host) && service.Port == port {
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

// GetServiceByName retrieves a service based on its unique name.
// It returns the ServiceInfo if found, otherwise returns nil.
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

// GetServices returns a slice of all services managed by the Manager.
// It provides a thread-safe way to access the current list of services.
func (m *Manager) GetServices() []*ServiceInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	services := make([]*ServiceInfo, 0, len(m.services))
	for _, service := range m.services {
		services = append(services, service)
	}

	return services
}

// createServerPool initializes and configures a ServerPool for a given service location.
// It sets up the load balancing algorithm and adds all backends associated with the location to the pool.
// Returns the configured ServerPool or an error if backend initialization fails.
func (m *Manager) createServerPool(srvc config.Location, serviceHealthCheck *config.HealthCheckConfig) (*pool.ServerPool, error) {
	serverPool := pool.NewServerPool(m.logger)
	serverPool.UpdateConfig(pool.PoolConfig{
		Algorithm: srvc.LoadBalancer,
	})

	for _, backend := range srvc.Backends {
		rc := pool.RouteConfig{
			Path:          srvc.Path,             // The path associated with the backend.
			RewriteURL:    srvc.Rewrite,          // URL rewrite rules for the backend.
			Redirect:      srvc.Redirect,         // Redirect settings if applicable.
			SkipTLSVerify: backend.SkipTLSVerify, // TLS verification settings for the backend.
		}

		backendHealthCheck := serviceHealthCheck
		if backend.HealthCheck != nil {
			backendHealthCheck = backend.HealthCheck
		}

		if err := serverPool.AddBackend(backend, rc, backendHealthCheck); err != nil {
			return nil, err
		}
	}

	return serverPool, nil
}

// matchHost determines if the provided host matches the given pattern.
// It supports wildcard patterns, allowing for flexible host matching.
// Returns true if the host matches the pattern, otherwise false.
func matchHost(pattern, host string) bool {
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(pattern, host)
	}

	if pattern == "*" {
		return true
	}

	// Patterns starting with "*." are treated as wildcard subdomains.
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // Remove the asterisk.
		return strings.HasSuffix(strings.ToLower(host), strings.ToLower(suffix))
	}

	return false
}
