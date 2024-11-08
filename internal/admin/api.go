package admin

import (
	"encoding/json"
	"net/http"

	"github.com/unkn0wn-root/go-load-balancer/internal/config"
	"github.com/unkn0wn-root/go-load-balancer/internal/middleware"
	"github.com/unkn0wn-root/go-load-balancer/internal/pool"
	"github.com/unkn0wn-root/go-load-balancer/internal/service"
)

// AdminAPI represents the administrative API for managing the load balancer.
type AdminAPI struct {
	serviceManager *service.Manager
	mux            *http.ServeMux
	config         *config.Config
}

// NewAdminAPI creates a new instance of AdminAPI with the provided service manager and configuration.
// It initializes the HTTP mux and registers all API routes.
func NewAdminAPI(manager *service.Manager, cfg *config.Config) *AdminAPI {
	api := &AdminAPI{
		serviceManager: manager,
		mux:            http.NewServeMux(),
		config:         cfg,
	}
	api.registerRoutes()
	return api
}

// registerRoutes sets up the HTTP handlers for various administrative endpoints.
func (a *AdminAPI) registerRoutes() {
	a.mux.HandleFunc("/api/backends", a.handleBackends)
	a.mux.HandleFunc("/api/health", a.handleHealth)
	a.mux.HandleFunc("/api/stats", a.handleStats)
	a.mux.HandleFunc("/api/config", a.handleConfig)
	a.mux.HandleFunc("/api/services", a.handleServices)
	a.mux.HandleFunc("/api/locations", a.handleLocations)
}

// Handler returns the HTTP handler for the AdminAPI, wrapped with necessary middleware.
func (a *AdminAPI) Handler() http.Handler {
	var middlewares []middleware.Middleware
	// If authentication is enabled in the config, add the Auth middleware
	if a.config.Auth.Enabled {
		middlewares = append(middlewares, middleware.NewAuthMiddleware(config.AuthConfig{
			APIKey: a.config.Auth.APIKey,
		}))
	}

	middlewares = append(middlewares,
		NewAdminAccessLogMiddleware(),
		middleware.NewRateLimiterMiddleware(
			a.config.AdminAPI.RateLimit.RequestsPerSecond,
			a.config.AdminAPI.RateLimit.Burst),
		middleware.NewServerHostMiddleware(),
	)

	chain := middleware.NewMiddlewareChain(middlewares...)
	return chain.Then(a.mux)
}

// handleServices handles HTTP requests related to services.
// Supports retrieving all services or a specific service by name.
func (a *AdminAPI) handleServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// get service by name
		serviceName := r.URL.Query().Get("service_name")
		if serviceName != "" {
			service := a.serviceManager.GetServiceByName(serviceName)
			if service == nil {
				http.Error(w, "Service not found", http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(service)
			return
		}
		// else get all services
		services := a.serviceManager.GetServices()
		json.NewEncoder(w).Encode(services)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBackends manages the backends for a specific service and location.
// Supports GET, POST, and DELETE methods to retrieve, add, or remove backends.
func (a *AdminAPI) handleBackends(w http.ResponseWriter, r *http.Request) {
	serviceName := r.URL.Query().Get("service_name")
	serviceLocation := r.URL.Query().Get("path")
	if serviceName == "" {
		http.Error(w, "service_name is required", http.StatusBadRequest)
		return
	}

	srvc := a.serviceManager.GetServiceByName(serviceName)
	if srvc == nil {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	var location *service.LocationInfo
	for _, loc := range srvc.Locations {
		if loc.Path == serviceLocation {
			location = loc
			break
		}
	}

	if location == nil && serviceLocation == "" {
		if len(srvc.Locations) == 1 {
			location = srvc.Locations[0]
		} else {
			http.Error(w, "location parameter is required for services with multiple locations",
				http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "Location not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		backends := location.ServerPool.GetBackends()
		json.NewEncoder(w).Encode(backends)
	case http.MethodPost:
		var backend config.BackendConfig
		if err := json.NewDecoder(r.Body).Decode(&backend); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		rc := pool.RouteConfig{
			Path:       location.Path,
			RewriteURL: location.Rewrite,
		}

		if err := location.ServerPool.AddBackend(backend, rc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		var backend struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&backend); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := location.ServerPool.RemoveBackend(backend.URL); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLocations handles HTTP GET requests to retrieve locations for a specific service.
// It returns information about each location, including path, algorithm, and backend count
func (a *AdminAPI) handleLocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serviceName := r.URL.Query().Get("service_name")
	if serviceName == "" {
		http.Error(w, "service_name is required", http.StatusBadRequest)
		return
	}

	service := a.serviceManager.GetServiceByName(serviceName)
	if service == nil {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	type LocationResponse struct {
		Path      string `json:"path"`
		Algorithm string `json:"algorithm"`
		Backends  int    `json:"backends_count"`
	}

	locations := make([]LocationResponse, 0, len(service.Locations))
	for _, loc := range service.Locations {
		locations = append(locations, LocationResponse{
			Path:      loc.Path,
			Algorithm: loc.Algorithm.Name(),
			Backends:  len(loc.ServerPool.GetBackends()),
		})
	}

	json.NewEncoder(w).Encode(locations)
}

// handleHealth provides a health check endpoint that reports the status of all services and their backends.
// It returns whether each backend is alive and the number of active connections.
func (a *AdminAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	healthStatus := make(map[string]interface{})
	services := a.serviceManager.GetServices()
	for _, service := range services {
		for _, loc := range service.Locations {
			backends := loc.ServerPool.GetBackends()
			serviceHealth := make(map[string]interface{})
			for _, backend := range backends {
				serviceHealth[backend.URL] = map[string]interface{}{
					"alive":       backend.Alive,
					"connections": backend.ConnectionCount,
				}
			}
			healthStatus[service.Name] = serviceHealth
		}
	}

	json.NewEncoder(w).Encode(healthStatus)
}

// handleStats provides statistical information about services, including backend counts and connection metrics.
// It returns total backends, active backends, and total connections per service.
func (a *AdminAPI) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := make(map[string]interface{})
	services := a.serviceManager.GetServices()

	for _, service := range services {
		for _, loc := range service.Locations {
			backends := loc.ServerPool.GetBackends()
			totalConnections := 0
			activeBackends := 0
			for _, backend := range backends {
				if backend.Alive {
					activeBackends++
				}
				totalConnections += int(backend.ConnectionCount)
			}
			stats[service.Name] = map[string]interface{}{
				"total_backends":    len(backends),
				"active_backends":   activeBackends,
				"total_connections": totalConnections,
			}
		}
	}

	json.NewEncoder(w).Encode(stats)
}
