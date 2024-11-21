package admin

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/unkn0wn-root/terraster/internal/auth/handlers"
	"github.com/unkn0wn-root/terraster/internal/auth/models"
	auth_service "github.com/unkn0wn-root/terraster/internal/auth/service"
	"github.com/unkn0wn-root/terraster/internal/config"
	"github.com/unkn0wn-root/terraster/internal/middleware"
	"github.com/unkn0wn-root/terraster/internal/pool"
	"github.com/unkn0wn-root/terraster/internal/service"
	"go.uber.org/zap"
)

// AdminAPI represents the administrative API for managing the load balancer.
type AdminAPI struct {
	enabled        bool
	serviceManager *service.Manager
	mux            *http.ServeMux
	config         *config.APIConfig
	authService    *auth_service.AuthService
	authHandler    *handlers.AuthHandler
	logger         *zap.Logger
}

// NewAdminAPI creates a new instance of AdminAPI with the provided service manager and configuration.
// It initializes the HTTP mux and registers all API routes.
func NewAdminAPI(
	manager *service.Manager,
	cfg *config.APIConfig,
	authService *auth_service.AuthService,
	logger *zap.Logger,
) *AdminAPI {
	api := &AdminAPI{
		enabled:        cfg.AdminAPI.Enabled,
		serviceManager: manager,
		mux:            http.NewServeMux(),
		config:         cfg,
		authService:    authService,
		authHandler:    handlers.NewAuthHandler(authService),
		logger:         logger,
	}
	api.registerRoutes()
	return api
}

// registerRoutes sets up the HTTP handlers for various administrative endpoints.
func (a *AdminAPI) registerRoutes() {
	// Auth routes
	a.mux.HandleFunc("/api/auth/login", a.authHandler.Login)
	a.mux.HandleFunc("/api/auth/refresh", a.authHandler.RefreshToken)

	// Protected routes
	a.mux.Handle("/api/auth/change-password",
		a.requireAuth(http.HandlerFunc(a.authHandler.ChangePassword)))

	// Admin-only routes
	a.mux.Handle("/api/backends",
		a.requireAuth(a.requireRole(models.RoleAdmin, http.HandlerFunc(a.handleBackends))))
	a.mux.Handle("/api/config",
		a.requireAuth(a.requireRole(models.RoleAdmin, http.HandlerFunc(a.handleConfig))))

	// Reader routes
	a.mux.Handle("/api/services",
		a.requireAuth(a.requireRole(models.RoleReader, http.HandlerFunc(a.handleServices))))
	a.mux.Handle("/api/health",
		a.requireAuth(a.requireRole(models.RoleReader, http.HandlerFunc(a.handleHealth))))
	a.mux.Handle("/api/stats",
		a.requireAuth(a.requireRole(models.RoleReader, http.HandlerFunc(a.handleStats))))
	a.mux.Handle("/api/locations",
		a.requireAuth(a.requireRole(models.RoleReader, http.HandlerFunc(a.handleLocations))))
}

// Handler returns the HTTP handler for the AdminAPI, wrapped with necessary middleware.
func (a *AdminAPI) Handler() http.Handler {
	logger := middleware.NewLoggingMiddleware(
		a.logger,
		middleware.WithLogLevel(zap.InfoLevel),
		middleware.WithHeaders(),
		middleware.WithQueryParams(),
		middleware.WithExcludePaths([]string{"/api/auth/login", "/api/auth/refresh"}),
	)

	var middlewares []middleware.Middleware
	middlewares = append(middlewares,
		logger,
		NewAdminAccessLogMiddleware(),
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
	servicePath := r.URL.Query().Get("path")
	if serviceName == "" {
		http.Error(w, "service_name and path is required", http.StatusBadRequest)
		return
	}

	srvc := a.serviceManager.GetServiceByName(serviceName)
	if srvc == nil {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	svlc := srvc.Locations
	if len(svlc) == 0 {
		http.Error(w, "Service has no locations", http.StatusNotFound)
		return
	}

	var location *service.LocationInfo
	if servicePath == "" {
		if len(svlc) > 1 {
			http.Error(w, "'path' parameter is required for services with multiple locations",
				http.StatusBadRequest)
			return
		}
		location = svlc[0]
	} else {
		for _, loc := range svlc {
			if loc.Path == servicePath {
				location = loc
				break
			}
		}
	}

	if location == nil {
		http.Error(w, "Location not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		backends := location.ServerPool.GetBackends()
		json.NewEncoder(w).Encode(backends)
	case http.MethodPost:
		var req BackendRequest
		if err := DecodeAndValidate(w, r, &req); err != nil {
			return
		}

		// Map AddBackendRequest to config.BackendConfig
		backendCfg := config.BackendConfig{
			URL:            req.URL,
			Weight:         req.Weight,
			MaxConnections: req.MaxConnections,
			SkipTLSVerify:  req.SkipTLSVerify,
			HealthCheck:    req.HealthCheck, // May be nil
		}

		// @TODO: Add Redirect from location
		rc := pool.RouteConfig{
			Path:       location.Path,
			RewriteURL: location.Rewrite,
		}

		// Determine the HealthCheckConfig to pass:
		// Priority: Backend-specific > Service-specific > Global default
		var hcCfg *config.HealthCheckConfig
		if backendCfg.HealthCheck != nil {
			hcCfg = backendCfg.HealthCheck
		} else if srvc.HealthCheck != nil {
			hcCfg = srvc.HealthCheck
		} else {
			hcCfg = config.DefaultHealthCheck.Copy()
		}

		if err := location.ServerPool.AddBackend(backendCfg, rc, hcCfg); err != nil {
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
				if backend.Alive.Load() {
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

// Helper methods for route protection
func (a *AdminAPI) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Remove "Bearer " prefix
		if len(token) < 7 || token[:7] != "Bearer " {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}
		token = token[7:]

		// Validate token
		claims, err := a.authService.ValidateToken(token)
		if err != nil {
			switch err {
			case auth_service.ErrInvalidToken:
				http.Error(w, "Invalid token", http.StatusUnauthorized)
			case auth_service.ErrRevokedToken:
				http.Error(w, "Token has been revoked", http.StatusUnauthorized)
			default:
				http.Error(w, "Authentication failed", http.StatusUnauthorized)
			}
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), "user_claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *AdminAPI) requireRole(role models.Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value("user_claims").(*jwt.MapClaims)
		userRole := models.Role((*claims)["role"].(string))

		if userRole != role && userRole != models.RoleAdmin {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
