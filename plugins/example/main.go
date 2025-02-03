package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/unkn0wn-root/terraster/pkg/plugin"
)

type Config struct {
	AllowedOrigins []string `json:"allowed_origins"`
	RateLimit      int      `json:"rate_limit"`
	AuthHeader     string   `json:"auth_header"`
	Debug          bool     `json:"debug"`
}

type ExamplePlugin struct {
	config     Config
	rateLimits sync.Map // client -> limit data
	logger     Logger   // interface for logging
}

// RateLimitData tracks rate limiting data
type RateLimitData struct {
	count      int
	resetAt    time.Time
	lastAccess time.Time
}

type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
}

func New() plugin.Handler {
	// Read config from environment or file
	config := loadConfig()

	return &ExamplePlugin{
		config: config,
	}
}

func loadConfig() Config {
	// Try to load from environment first
	if configJSON := os.Getenv("EXAMPLE_PLUGIN_CONFIG"); configJSON != "" {
		var config Config
		if err := json.Unmarshal([]byte(configJSON), &config); err == nil {
			return config
		}
	}

	// Default config
	return Config{
		AllowedOrigins: []string{"*"},
		RateLimit:      100,
		AuthHeader:     "X-API-Key",
		Debug:          false,
	}
}

// ProcessRequest handles incoming requests
func (p *ExamplePlugin) ProcessRequest(ctx context.Context, req *http.Request) *plugin.Result {
	// 1. CORS Pre-flight handling
	if req.Method == http.MethodOptions {
		return p.handleCORS(req)
	}

	// 2. Rate limiting
	if exceeded, resetAt := p.isRateLimitExceeded(req); exceeded {
		return plugin.NewResult(
			plugin.Stop,
			plugin.WithStatus(http.StatusTooManyRequests),
			plugin.WithHeaders(http.Header{
				"X-RateLimit-Reset": []string{fmt.Sprint(resetAt.Unix())},
			}),
			plugin.WithJSONResponse(map[string]interface{}{
				"error":    "rate limit exceeded",
				"reset_at": resetAt.Format(time.RFC3339),
				"limit":    p.config.RateLimit,
				"interval": "1 minute",
			}),
		)
	}

	// 3. Authentication
	if !p.isAuthenticated(req) {
		return plugin.NewResult(
			plugin.Stop,
			plugin.WithStatus(http.StatusUnauthorized),
			plugin.WithJSONResponse(map[string]string{
				"error": fmt.Sprintf("missing or invalid %s header", p.config.AuthHeader),
			}),
		)
	}

	// 4. Request modification example
	// Add custom headers
	req.Header.Set("X-Processed-By", "example-plugin")
	req.Header.Set("X-Request-Start", time.Now().Format(time.RFC3339))

	// Store timing info in context for response processing
	*req = *req.WithContext(context.WithValue(req.Context(), "req_start", time.Now()))

	return plugin.ResultModify
}

// ProcessResponse handles outgoing responses
func (p *ExamplePlugin) ProcessResponse(ctx context.Context, resp *http.Response) *plugin.Result {
	// 1. Add security headers
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("X-Frame-Options", "DENY")
	resp.Header.Set("X-XSS-Protection", "1; mode=block")

	// 2. Add timing headers if we have the start time
	if startTime, ok := resp.Request.Context().Value("req_start").(time.Time); ok {
		processingTime := time.Since(startTime).Milliseconds()
		resp.Header.Set("X-Processing-Time", fmt.Sprintf("%dms", processingTime))
	}

	// 3. Add CORS headers for non-OPTIONS requests
	if resp.Request.Method != http.MethodOptions {
		origin := resp.Request.Header.Get("Origin")
		if p.isOriginAllowed(origin) {
			resp.Header.Set("Access-Control-Allow-Origin", origin)
			resp.Header.Set("Access-Control-Allow-Credentials", "true")
		}
	}

	// 4. Handle specific error cases (example)
	if resp.StatusCode >= 500 {
		// Log server errors
		p.logError("Backend error", map[string]interface{}{
			"status": resp.StatusCode,
			"path":   resp.Request.URL.Path,
			"method": resp.Request.Method,
		})

		// Optionally modify error response
		if p.config.Debug {
			return plugin.ResultModify
		}

		return plugin.NewResult(
			plugin.Stop,
			plugin.WithStatus(http.StatusBadGateway),
			plugin.WithJSONResponse(map[string]string{
				"error": "service temporarily unavailable",
			}),
		)
	}

	return plugin.ResultModify
}

func (p *ExamplePlugin) handleCORS(req *http.Request) *plugin.Result {
	origin := req.Header.Get("Origin")
	if !p.isOriginAllowed(origin) {
		return plugin.NewResult(
			plugin.Stop,
			plugin.WithStatus(http.StatusForbidden),
			plugin.WithJSONResponse(map[string]string{
				"error": "origin not allowed",
			}),
		)
	}

	return plugin.NewResult(
		plugin.Stop,
		plugin.WithStatus(http.StatusOK),
		plugin.WithHeaders(http.Header{
			"Access-Control-Allow-Origin":      []string{origin},
			"Access-Control-Allow-Methods":     []string{"GET, POST, PUT, DELETE, OPTIONS"},
			"Access-Control-Allow-Headers":     []string{"Content-Type, Authorization, " + p.config.AuthHeader},
			"Access-Control-Allow-Credentials": []string{"true"},
			"Access-Control-Max-Age":           []string{"86400"},
		}),
	)
}

func (p *ExamplePlugin) isRateLimitExceeded(req *http.Request) (bool, time.Time) {
	clientID := req.RemoteAddr

	now := time.Now()
	if data, exists := p.rateLimits.Load(clientID); exists {
		limit := data.(*RateLimitData)

		// Reset if window has passed
		if now.Sub(limit.resetAt) >= time.Minute {
			limit.count = 0
			limit.resetAt = now.Add(time.Minute)
		}

		limit.count++
		limit.lastAccess = now

		if limit.count > p.config.RateLimit {
			return true, limit.resetAt
		}
		return false, limit.resetAt
	}

	// First request for this client
	p.rateLimits.Store(clientID, &RateLimitData{
		count:      1,
		resetAt:    now.Add(time.Minute),
		lastAccess: now,
	})

	return false, now.Add(time.Minute)
}

func (p *ExamplePlugin) isAuthenticated(req *http.Request) bool {
	authToken := req.Header.Get(p.config.AuthHeader)
	return authToken != "" // Just example. Shoudl have real auth logic
}

func (p *ExamplePlugin) isOriginAllowed(origin string) bool {
	if len(p.config.AllowedOrigins) == 0 || p.config.AllowedOrigins[0] == "*" {
		return true
	}

	for _, allowed := range p.config.AllowedOrigins {
		if allowed == origin {
			return true
		}
	}
	return false
}

func (p *ExamplePlugin) logError(msg string, fields map[string]interface{}) {
	if p.logger != nil {
		p.logger.Error(msg, fields)
	}
}

// Required plugin interface methods
func (p *ExamplePlugin) Name() string {
	return "example_plugin"
}

func (p *ExamplePlugin) Priority() int {
	return 50 // Middle priority
}

func (p *ExamplePlugin) Cleanup() error {
	// Clean up rate limit data older than 1 hour
	now := time.Now()
	p.rateLimits.Range(func(key, value interface{}) bool {
		data := value.(*RateLimitData)
		if now.Sub(data.lastAccess) > time.Hour {
			p.rateLimits.Delete(key)
		}
		return true
	})
	return nil
}
