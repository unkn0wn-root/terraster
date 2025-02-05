package admin

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	admin "github.com/unkn0wn-root/terraster/internal/admin/middleware"
	apierr "github.com/unkn0wn-root/terraster/internal/auth"
	"github.com/unkn0wn-root/terraster/internal/auth/models"
	"github.com/unkn0wn-root/terraster/internal/config"
	"github.com/unkn0wn-root/terraster/internal/middleware"
	"github.com/unkn0wn-root/terraster/internal/pool"
	"github.com/unkn0wn-root/terraster/internal/service"
	"go.uber.org/zap"
)

type BackendStatus struct {
	URL         string `json:"url"`
	Alive       bool   `json:"alive"`
	Connections int32  `json:"connections"`
}

type AuthResult struct {
	Claims *jwt.MapClaims
	User   *models.User
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

	adminApiHost := a.config.AdminAPI.Host
	if adminApiHost == "" {
		adminApiHost = "localhost"
	}

	var middlewares []middleware.Middleware
	middlewares = append(middlewares,
		logger,
		admin.NewAccessLogMiddleware(a.logger),
		admin.NewHostnameMiddleware(adminApiHost, a.logger),
		admin.NewIPRestrictionMiddleware(a.config.AdminAPI.AllowedIPs, a.logger),
	)

	chain := middleware.NewMiddlewareChain(middlewares...)
	return chain.Then(a.mux)
}

// handleServices handles HTTP requests related to services.
// Supports retrieving all services or a specific service by name.
func (a *AdminAPI) handleServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		// first get service by name (if provided), else get all services
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
	servicePath := r.URL.Query().Get("path")
	if servicePath == "" {
		if len(svlc) > 1 {
			http.Error(w,
				"'path' parameter is required for services with multiple locations",
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(backends)
	case http.MethodPost:
		var req BackendRequest
		if err := DecodeAndValidate(w, r, &req); err != nil {
			return
		}

		// Map AddBackendRequest to config.BackendConfig
		backendCfg := config.Backend{
			URL:            req.URL,
			Weight:         req.Weight,
			MaxConnections: req.MaxConnections,
			SkipTLSVerify:  req.SkipTLSVerify,
			HealthCheck:    req.HealthCheck, // May be nil
		}

		// @TODO: Add Redirect from location
		rc := pool.Route{
			Path:       location.Path,
			RewriteURL: location.Rewrite,
		}

		// Determine the HealthCheck config to pass:
		// Priority: Backend-specific > Service-specific > Global default
		var hcCfg *config.HealthCheck
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

	w.Header().Set("Content-Type", "application/json")
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
					"alive":       backend.Alive.Load(),
					"connections": backend.ConnectionCount,
				}
			}
			healthStatus[service.Name] = serviceHealth
		}
	}

	w.Header().Set("Content-Type", "application/json")
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// authenticateRequest validates the authentication token from the request and returns user information.
// It performs the following steps:
// 1. Extracts and validates the Bearer token from the Authorization header
// 2. Validates the token's signature and claims
// 3. Retrieves the associated user information
func (a *AdminAPI) authenticateRequest(r *http.Request) (*AuthResult, error) {
	token := r.Header.Get("Authorization")
	if token == "" || len(token) < 7 || token[:7] != "Bearer " {
		return nil, apierr.ErrInvalidToken
	}

	claims, err := a.authService.ValidateToken(token[7:])
	if err != nil {
		return nil, err
	}

	userID := int64((*claims)["user_id"].(float64))
	user, err := a.authService.GetUserById(userID)
	if err != nil {
		return nil, err
	}

	return &AuthResult{
		Claims: claims,
		User:   user,
	}, nil
}

// requireAuthStrict is a middleware that enforces strict authentication requirements.
// It blocks access if either:
// 1. The authentication token is invalid
// 2. The user's password has expired
// This middleware is used for protected routes that require active, non-expired credentials.
func (a *AdminAPI) requireAuthStrict(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authRes, err := a.authenticateRequest(r)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// block access if password is expired
		if a.authService.IsPasswordExpired(authRes.User) {
			http.Error(w, "Password expired", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), "user_claims", authRes.Claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireAuth is a middleware that implements basic authentication validation.
// Unlike requireAuthStrict, it allows access with expired passwords.
// This middleware is used for routes that should be accessible even with expired credentials,
// such as the password change endpoint.
func (a *AdminAPI) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authResult, err := a.authenticateRequest(r)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_claims", authResult.Claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// handleConfig handles configuration management for service locations.
// Supports GET and PUT methods to retrieve and update service configurations.
// The endpoint can be accessed with either a specific service name or will default
// to the only service if just one exists
func (a *AdminAPI) handleConfig(w http.ResponseWriter, r *http.Request) {
	serviceName := r.URL.Query().Get("service_name")
	pathName := r.URL.Query().Get("path")

	var srvc *service.ServiceInfo
	if serviceName == "" {
		services := a.serviceManager.GetServices()
		switch len(services) {
		case 1:
			srvc = services[0]
		case 0:
			http.Error(w, "No services configured", http.StatusNotFound)
			return
		default:
			http.Error(w, "Multiple services exist, please specify service name", http.StatusBadRequest)
			return
		}
	} else {
		srvc = a.serviceManager.GetServiceByName(serviceName)
		if srvc == nil {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
	}

	if pathName == "" {
		http.Error(w, "Path cannot be empty", http.StatusNotFound)
		return
	}

	var location *service.LocationInfo
	for _, loc := range srvc.Locations {
		if loc.Path == pathName {
			location = loc
			break
		}
	}

	if location == nil {
		http.Error(w, "Location not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		cfg := location.ServerPool.GetConfig()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	case http.MethodPut:
		var update pool.PoolConfig
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		location.ServerPool.UpdateConfig(update)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
