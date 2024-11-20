package config

import (
	"fmt"
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Port           int                `yaml:"port"`
	HTTPPort       int                `yaml:"http_port"`
	HTTPSPort      int                `yaml:"https_port"`
	AdminPort      int                `yaml:"admin_port"`
	TLS            TLSConfig          `yaml:"tls"`
	Algorithm      string             `yaml:"algorithm"`
	RateLimit      *RateLimitConfig   `yaml:"rate_limit"`
	ConnPool       PoolConfig         `yaml:"connection_pool"`
	Backends       []BackendConfig    `yaml:"backends"`
	Auth           APIAuthConfig      `yaml:"auth"`
	AdminAPI       AdminAPIConfig     `yaml:"admin_api"`
	HealthCheck    *HealthCheckConfig `yaml:"health_check"`
	Services       []Service          `yaml:"services"`
	CircuitBreaker *CircuitBreaker    `yaml:"circuit_breaker"`
	Security       *SecurityConfig    `yaml:"security"`
	CORS           *CORS              `yaml:"cors"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type BackendConfig struct {
	URL            string             `yaml:"url"`
	Weight         int                `yaml:"weight"`
	MaxConnections int32              `yaml:"max_connections"`
	SkipTLSVerify  bool               `yaml:"skip_tls_verify"`
	HealthCheck    *HealthCheckConfig `yaml:"health_check,omitempty"`
}

type Thresholds struct {
	Healthy   int `yaml:"healthy"`
	Unhealthy int `yaml:"unhealthy"`
}

type HealthCheckConfig struct {
	Type       string        `yaml:"type"`           // "http" or "tcp"
	Path       string        `yaml:"path,omitempty"` // Applicable for HTTP health checks
	Interval   time.Duration `yaml:"interval"`       // e.g., "10s"
	Timeout    time.Duration `yaml:"timeout"`        // e.g., "2s"
	Thresholds Thresholds    `yaml:"thresholds"`     // Healthy and Unhealthy thresholds
}

type RateLimitConfig struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

type PoolConfig struct {
	MaxIdle     int           `yaml:"max_idle"`
	MaxOpen     int           `yaml:"max_open"`
	IdleTimeout time.Duration `yaml:"idle_timeout"` // e.g., "90s"
}

type AdminAPIConfig struct {
	Host      string          `yaml:"host"`
	Enabled   bool            `yaml:"enabled"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

type APIAuthConfig struct {
	JWTSecret            string `yaml:"jwt_secret"`
	DBPath               string `yaml:"db_path"`
	TokenCleanupInterval int    `yaml:"token_cleanup_interval"`
	PasswordExpiryDays   int    `yaml:"password_expiry_days"`
	PasswordHistoryLimit int    `yaml:"password_history_limit"`
}

type Service struct {
	Name         string             `yaml:"name"`
	Host         string             `yaml:"host"`
	Port         int                `yaml:"port"`
	TLS          *TLSConfig         `yaml:"tls"`
	HTTPRedirect bool               `yaml:"http_redirect"`
	RedirectPort int                `yaml:"redirect_port"`
	HealthCheck  *HealthCheckConfig `yaml:"health_check,omitempty"` // Optional Per-Service Health Check
	Locations    []Location         `yaml:"locations"`
}

type Location struct {
	Path         string          `yaml:"path"`
	Rewrite      string          `yaml:"rewrite"`
	Redirect     string          `yaml:"redirect"`
	LoadBalancer string          `yaml:"lb_policy"`
	Backends     []BackendConfig `yaml:"backends"`
}

type CircuitBreaker struct {
	FailureThreshold int           `yaml:"failure_threshold"`
	ResetTimeout     time.Duration `yaml:"reset_timeout"`
}

type SecurityConfig struct {
	HSTS                  bool   `yaml:"hsts"`
	HSTSMaxAge            int    `yaml:"hsts_max_age"`
	HSTSIncludeSubDomains bool   `yaml:"hsts_include_subdomains"`
	HSTSPreload           bool   `yaml:"hsts_preload"`
	FrameOptions          string `yaml:"frame_options"`
	ContentTypeOptions    bool   `yaml:"content_type_options"`
	XSSProtection         bool   `yaml:"xss_protection"`
}

type CORS struct {
	AllowedOrigins   []string `yaml:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers"`
	ExposedHeaders   []string `yaml:"exposed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	MaxAge           int      `yaml:"max_age"`
}

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
func (cfg *Config) Validate() error {
	// Apply default global health check if not set
	if cfg.HealthCheck == nil {
		log.Printf("Global health_check not defined. Applying default health check configuration.")
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
