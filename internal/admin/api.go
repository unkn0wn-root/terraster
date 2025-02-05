package admin

import (
	"net/http"
	"net/http/pprof"

	"github.com/golang-jwt/jwt/v4"
	"github.com/unkn0wn-root/terraster/internal/auth/handlers"
	"github.com/unkn0wn-root/terraster/internal/auth/models"
	auth_service "github.com/unkn0wn-root/terraster/internal/auth/service"
	"github.com/unkn0wn-root/terraster/internal/config"
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
		enabled:        cfg.API.Enabled,
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
	a.mux.Handle("/api/backends", a.registerMiddleware(models.RoleAdmin, http.HandlerFunc(a.handleBackends)))
	a.mux.Handle("/api/config", a.registerMiddleware(models.RoleAdmin, http.HandlerFunc(a.handleConfig)))

	// Admin-only debug route if enabled in config
	if a.config.API.Debug {
		a.mux.Handle("/debug/pprof/", a.registerMiddleware(models.RoleAdmin, http.HandlerFunc(pprof.Index)))
		a.mux.Handle("/debug/pprof/cmdline", a.registerMiddleware(models.RoleAdmin, http.HandlerFunc(pprof.Cmdline)))
		a.mux.Handle("/debug/pprof/profile", a.registerMiddleware(models.RoleAdmin, http.HandlerFunc(pprof.Profile)))
		a.mux.Handle("/debug/pprof/symbol", a.registerMiddleware(models.RoleAdmin, http.HandlerFunc(pprof.Symbol)))
		a.mux.Handle("/debug/pprof/trace", a.registerMiddleware(models.RoleAdmin, http.HandlerFunc(pprof.Trace)))
		a.mux.Handle("/debug/pprof/heap", a.registerMiddleware(models.RoleAdmin, pprof.Handler("heap")))
		a.mux.Handle("/debug/pprof/goroutine", a.registerMiddleware(models.RoleAdmin, pprof.Handler("goroutine")))
	}

	// Reader routes
	a.mux.Handle("/api/services", a.registerMiddleware(models.RoleReader, http.HandlerFunc(a.handleServices)))
	a.mux.Handle("/api/health", a.registerMiddleware(models.RoleReader, http.HandlerFunc(a.handleHealth)))
	a.mux.Handle("/api/stats", a.registerMiddleware(models.RoleReader, http.HandlerFunc(a.handleStats)))
	a.mux.Handle("/api/locations", a.registerMiddleware(models.RoleReader, http.HandlerFunc(a.handleLocations)))
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

func (a *AdminAPI) registerMiddleware(role models.Role, h http.Handler) http.Handler {
	return a.requireAuthStrict(a.requireRole(role, h))
}
