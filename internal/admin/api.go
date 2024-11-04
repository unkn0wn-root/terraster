package admin

import (
	"encoding/json"
	"net/http"

	"github.com/unkn0wn-root/go-load-balancer/internal/config"
	"github.com/unkn0wn-root/go-load-balancer/internal/middleware"
	"github.com/unkn0wn-root/go-load-balancer/internal/pool"
)

type AdminAPI struct {
	serverPool *pool.ServerPool
	mux        *http.ServeMux
	config     *config.Config
}

func NewAdminAPI(pool *pool.ServerPool, cfg *config.Config) *AdminAPI {
	api := &AdminAPI{
		serverPool: pool,
		mux:        http.NewServeMux(),
		config:     cfg,
	}
	api.registerRoutes()
	return api
}

func (a *AdminAPI) registerRoutes() {
	a.mux.HandleFunc("/api/backends", a.handleBackends)
	a.mux.HandleFunc("/api/health", a.handleHealth)
	a.mux.HandleFunc("/api/stats", a.handleStats)
	a.mux.HandleFunc("/api/config", a.handleConfig)
}

func (a *AdminAPI) Handler() http.Handler {
	var middlewares []middleware.Middleware

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
	)

	chain := middleware.NewMiddlewareChain(middlewares...)
	return chain.Then(a.mux)
}

func (a *AdminAPI) handleBackends(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		backends := a.serverPool.GetBackends()
		json.NewEncoder(w).Encode(backends)

	case http.MethodPost:
		var backend config.BackendConfig
		if err := json.NewDecoder(r.Body).Decode(&backend); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := a.serverPool.AddBackend(backend); err != nil {
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
		if err := a.serverPool.RemoveBackend(backend.URL); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *AdminAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := make(map[string]interface{})
	backends := a.serverPool.GetBackends()

	for _, backend := range backends {
		health[backend.URL] = map[string]interface{}{
			"alive":       backend.Alive,
			"connections": backend.ConnectionCount,
		}
	}

	json.NewEncoder(w).Encode(health)
}

func (a *AdminAPI) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := make(map[string]interface{})
	backends := a.serverPool.GetBackends()

	totalConnections := 0
	activeBackends := 0

	for _, backend := range backends {
		if backend.Alive {
			activeBackends++
		}
		totalConnections += int(backend.ConnectionCount)
	}

	stats["total_backends"] = len(backends)
	stats["active_backends"] = activeBackends
	stats["total_connections"] = totalConnections

	json.NewEncoder(w).Encode(stats)
}
