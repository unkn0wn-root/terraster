package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// SerciceConfig represents a partial configuration containing only sercices
type ServiceConfig struct {
	Services []Service `yaml:"services"`
}

// MergeConfigs merges multiple configuration files into a single Config
func MergeConfigs(mainConfigPath, servicesDir string, logger *zap.Logger) (*Config, error) {
	// load main config first
	mainConfig, err := Load(mainConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load main configuration file %w", err)
	}

	// if provided and exist - merge additional service configurations
	if servicesDir != "" {
		if _, err := os.Stat(servicesDir); err == nil {
			serviceFiles, err := findServiceFiles(servicesDir)
			if err != nil {
				return nil, fmt.Errorf("failed to read services directory: %w", err)
			}

			// this loads and merge configs
			for _, filePath := range serviceFiles {
				services, err := loadServiceConfig(filePath)
				if err != nil {
					return nil, fmt.Errorf("failed to load service config from %s: %w", filePath, err)
				}
				mainConfig.Services = append(mainConfig.Services, services.Services...)
			}
		}
	}

	// @todo (!!!) - this should validate more then healthchecker...
	if err := mainConfig.Validate(logger); err != nil {
		return nil, fmt.Errorf("invalid merged configuration: %w", err)
	}

	return mainConfig, nil
}

// findServiceFiles returns a list of yaml files in the specified dir.
func findServiceFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// must be .yaml or .yml file
		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			files = append(files, path)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}

// loadSerciceConfig loads a service configuration from a file.
func loadServiceConfig(path string) (*ServiceConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config ServiceConfig
	if err := yaml.UnmarshalStrict(data, &config); err != nil {
		return nil, fmt.Errorf("invalid service config in %s: %w", path, err)
	}

	return &config, nil
}

// Config represents the main configuration structure for the Terraster application.
// It aggregates various configuration sections such as server ports, TLS settings,
// load balancing algorithms, connection pooling, backends, authentication, administrative APIs,
// health checks, services, and middleware configurations.
type Config struct {
	Port        int                `yaml:"port"`             // The port on which the main server listens.
	Host        string             `yaml:"host"`             // The host on which the main server listens.
	HTTPPort    int                `yaml:"http_port"`        // The port for handling HTTP (non-TLS) traffic.
	HTTPSPort   int                `yaml:"https_port"`       // The port for handling HTTPS (TLS) traffic.
	TLS         TLSConfig          `yaml:"tls"`              // TLS configuration settings.
	Algorithm   string             `yaml:"algorithm"`        // The load balancing algorithm to use (e.g., "round-robin").
	ConnPool    PoolConfig         `yaml:"connection_pool"`  // Configuration for the connection pool.
	Backends    []BackendConfig    `yaml:"backends"`         // A list of backend services.
	HealthCheck *HealthCheckConfig `yaml:"health_check"`     // Global health check configuration.
	Services    []Service          `yaml:"services"`         // A list of services with their specific configurations.
	Middleware  []Middleware       `yaml:"middleware"`       // Global middleware configurations.
	CertManager CertManagerConfig  `json:"cert_manager"`     // Configuration for the certificate manager.
	PluginDir   string             `yaml:"plugin_directory"` // Plugins directory. Will default to `./plugins` if not specified
}

// TLSConfig holds configuration settings related to TLS (HTTPS) for the server.
// It includes flags and file paths necessary for setting up TLS.
type TLSConfig struct {
	Enabled                bool     `yaml:"enabled"`                  // Indicates whether TLS is enabled.
	CertFile               string   `yaml:"cert_file"`                // Path to the TLS certificate file.
	KeyFile                string   `yaml:"key_file"`                 // Path to the TLS private key file.
	CipherSuites           []uint16 `yaml:"cipher_suites"`            // List of supported cipher suites.
	SessionTicketsDisabled bool     `yaml:"session_tickets_disabled"` // Disables session ticket support if true.
	NextProtos             []string `yaml:"next_protos"`              // List of supported application protocols.
	HTTP2Enabled           *bool    `yaml:"http2"`                    // Whether to enable HTTP/2
}

// BackendConfig defines the configuration for a single backend service.
// It includes the backend's URL, load balancing weight, connection limits,
// TLS verification settings, and optional health check configurations.
type BackendConfig struct {
	URL            string             `yaml:"url"`                    // The URL of the backend service.
	Weight         int                `yaml:"weight"`                 // The weight for load balancing purposes.
	MaxConnections int32              `yaml:"max_connections"`        // Maximum number of concurrent connections to the backend.
	SkipTLSVerify  bool               `yaml:"skip_tls_verify"`        // Whether to skip TLS certificate verification for the backend.
	HealthCheck    *HealthCheckConfig `yaml:"health_check,omitempty"` // Optional health check configuration specific to the backend.
	ServerName     string             `yaml:"sni"`                    // Optional to support virtual hosts
	HTTP2          *bool              `yaml:"http2"`                  // Optional to enable http2 protocol to the backend service
}

// Thresholds defines the thresholds for determining the health status of a backend.
// It specifies how many consecutive successful or failed health checks are needed.
type Thresholds struct {
	Healthy   int `yaml:"healthy"`   // Number of consecutive successful health checks required to mark the backend as healthy.
	Unhealthy int `yaml:"unhealthy"` // Number of consecutive failed health checks required to mark the backend as unhealthy.
}

// HealthCheckConfig holds configuration settings for performing health checks on backends.
// It defines the type of health check, intervals, timeouts, and success/failure thresholds.
type HealthCheckConfig struct {
	Type       string        `yaml:"type"`           // "http" or "tcp"
	Path       string        `yaml:"path,omitempty"` // Applicable for HTTP health checks
	Interval   time.Duration `yaml:"interval"`       // e.g., "10s"
	Timeout    time.Duration `yaml:"timeout"`        // e.g., "2s"
	Thresholds Thresholds    `yaml:"thresholds"`     // Healthy and Unhealthy thresholds
}

// RateLimitConfig defines the configuration for rate limiting middleware.
// It specifies the number of requests allowed per second and the burst size.
type RateLimitConfig struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"` // Number of allowed requests per second.
	Burst             int     `yaml:"burst"`               // Maximum number of burst requests allowed.
}

// PoolConfig configures the connection pool used by the server.
// It sets limits on idle and open connections and defines the idle timeout duration.
type PoolConfig struct {
	MaxIdle     int           `yaml:"max_idle"`     // Maximum number of idle connections in the pool.
	MaxOpen     int           `yaml:"max_open"`     // Maximum number of open connections allowed.
	IdleTimeout time.Duration `yaml:"idle_timeout"` // Duration after which idle connections are closed. e.g., "90s"
}

// Service represents a single service with its specific configurations.
// It includes service identification, routing settings, TLS configurations,
// redirection policies, health checks, middleware, and associated locations.
type Service struct {
	Name              string             `yaml:"name"`                   // Unique name of the service.
	Host              string             `yaml:"host"`                   // Host address where the service is accessible.
	Port              int                `yaml:"port"`                   // Port number on which the service listens.
	TLS               *TLSConfig         `yaml:"tls"`                    // Optional TLS configuration for the service.
	HTTPRedirect      bool               `yaml:"http_redirect"`          // Indicates whether HTTP requests should be redirected to HTTPS.
	RedirectPort      int                `yaml:"redirect_port"`          // Custom port for redirection if applicable.
	HealthCheck       *HealthCheckConfig `yaml:"health_check,omitempty"` // Optional Per-Service Health Check
	Middleware        []Middleware       `yaml:"middleware"`             // Middleware configurations specific to the service.
	Locations         []Location         `yaml:"locations"`              // Routing paths and backend configurations for the service.
	LogName           string             `yaml:"log_name,omitempty"`     // Name of the logger to use for this service.
	Headers           *HeaderConfig      `yaml:"headers,omitempty"`      // Custom headers configuration for request and response objects
	DisablePluginLoad bool               `yaml:"plugin_disabled"`        // enabled or disable plugin load for specific service. False by default
}

// HeaderConfig is custom response and request headers modifier
type HeaderConfig struct {
	RequestHeaders        map[string]string `yaml:"request_headers,omitempty"`         // Request headers to be added/modified when forwarding to backend
	ResponseHeaders       map[string]string `yaml:"response_headers,omitempty"`        // Response headers to be added/modified before sending back to client
	RemoveRequestHeaders  []string          `yaml:"remove_request_headers,omitempty"`  // Headers to be removed from the request before forwarding
	RemoveResponseHeaders []string          `yaml:"remove_response_headers,omitempty"` // Headers to be removed from the response before sending back
}

// Middleware defines the configuration for various middleware components.
// Each field corresponds to a different type of middleware that can be applied.
type Middleware struct {
	RateLimit      *RateLimitConfig `yaml:"rate_limit"`      // Rate limiting configuration.
	CircuitBreaker *CircuitBreaker  `yaml:"circuit_breaker"` // Circuit breaker configuration.
	Security       *SecurityConfig  `yaml:"security"`        // Security headers configuration.
	CORS           *CORS            `yaml:"cors"`            // CORS (Cross-Origin Resource Sharing) configuration.
	Compression    bool             `yaml:"compression"`     // Enables compression if true.
}

// Location defines the routing and backend configurations for a specific path within a service.
// It includes path matching, URL rewriting, redirection targets, load balancing policies, and associated backends.
type Location struct {
	Path         string          `yaml:"path"`      // URL path that this location handles.
	Rewrite      string          `yaml:"rewrite"`   // URL rewrite rule applied to incoming requests.
	Redirect     string          `yaml:"redirect"`  // URL to redirect to, if applicable.
	LoadBalancer string          `yaml:"lb_policy"` // Load balancing policy (e.g., "round-robin").
	Backends     []BackendConfig `yaml:"backends"`  // List of backend configurations for this location.
}

// CircuitBreaker defines the configuration for a circuit breaker middleware.
// It sets thresholds for failures and the timeout before attempting to reset the circuit.
type CircuitBreaker struct {
	FailureThreshold int           `yaml:"failure_threshold"` // Number of consecutive failures to trigger the circuit breaker.
	ResetTimeout     time.Duration `yaml:"reset_timeout"`     // Duration to wait before attempting to reset the circuit after it has been tripped.
}

// SecurityConfig holds configuration settings for security-related HTTP headers.
// It defines how various security headers should be set to enhance the security posture of the server.
type SecurityConfig struct {
	HSTS                  bool   `yaml:"hsts"`                    // Enables HTTP Strict Transport Security (HSTS).
	HSTSMaxAge            int    `yaml:"hsts_max_age"`            // Duration (in seconds) for the HSTS policy.
	HSTSIncludeSubDomains bool   `yaml:"hsts_include_subdomains"` // Applies HSTS policy to all subdomains if true.
	HSTSPreload           bool   `yaml:"hsts_preload"`            // Includes the site in browsers' HSTS preload lists if true.
	FrameOptions          string `yaml:"frame_options"`           // Value for the X-Frame-Options header.
	ContentTypeOptions    bool   `yaml:"content_type_options"`    // Enables the X-Content-Type-Options header to prevent MIME type sniffing.
	XSSProtection         bool   `yaml:"xss_protection"`          // Enables the X-XSS-Protection header to activate the browser's XSS protection.
}

// CORS defines the configuration for Cross-Origin Resource Sharing.
// It specifies allowed origins, methods, headers, exposed headers, credential support, and caching durations.
type CORS struct {
	AllowedOrigins   []string `yaml:"allowed_origins"`   // List of origins allowed to access the resources.
	AllowedMethods   []string `yaml:"allowed_methods"`   // HTTP methods allowed for CORS requests.
	AllowedHeaders   []string `yaml:"allowed_headers"`   // HTTP headers allowed in CORS requests.
	ExposedHeaders   []string `yaml:"exposed_headers"`   // HTTP headers exposed to the browser.
	AllowCredentials bool     `yaml:"allow_credentials"` // Indicates whether credentials are allowed in CORS requests.
	MaxAge           int      `yaml:"max_age"`           // Duration (in seconds) for which the results of a preflight request can be cached.
}

// CertManagerConfig holds configuration settings for the certificate manager.
type CertManagerConfig struct {
	CertDir          string         `json:"cert_dir"`
	Alerting         AlertingConfig `json:"alerting"`
	CheckInterval    time.Duration  `yaml:"check_interval"`
	ExpirationThresh time.Duration  `yaml:"expiration_threshold"`
}

// AlertingConfig holds SMTP settings for alerting.
type AlertingConfig struct {
	Enabled   bool     `json:"enabled"`
	SMTPHost  string   `json:"smtp_host"`
	SMTPPort  int      `json:"smtp_port"`
	FromEmail string   `json:"from_email"`
	FromPass  string   `json:"from_password"`
	ToEmails  []string `json:"to_emails"`
}

// DefaultHealthCheck provides a default configuration for health checks.
// It is used when no global or backend-specific health check configuration is provided.
var DefaultHealthCheck = HealthCheckConfig{
	Type:     "http",
	Path:     "/health",
	Interval: 10 * time.Second,
	Timeout:  2 * time.Second,
	Thresholds: Thresholds{
		Healthy:   2,
		Unhealthy: 4,
	},
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.UnmarshalStrict(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// @TODO: Implement the Validate method for the Config struct
// and add more validation
func (cfg *Config) Validate(logger *zap.Logger) error {
	// Apply default global health check if not set
	if cfg.HealthCheck == nil {
		logger.Warn("Global health_check not defined. Applying default health check configuration.")
		cfg.HealthCheck = DefaultHealthCheck.Copy()
	} else {
		// Validate global health check
		if cfg.HealthCheck.Type != "http" && cfg.HealthCheck.Type != "tcp" {
			return fmt.Errorf("invalid global health_check type: %s", cfg.HealthCheck.Type)
		}
		if cfg.HealthCheck.Interval <= 0 {
			return fmt.Errorf("health_check interval must be positive")
		}
		if cfg.HealthCheck.Timeout <= 0 {
			return fmt.Errorf("health_check timeout must be positive")
		}
		if cfg.HealthCheck.Thresholds.Healthy <= 0 || cfg.HealthCheck.Thresholds.Unhealthy <= 0 {
			return fmt.Errorf("health_check thresholds must be positive integers")
		}
	}

	return nil
}

func (hc *HealthCheckConfig) Copy() *HealthCheckConfig {
	if hc == nil {
		return nil
	}

	copyHC := *hc
	return &copyHC
}
