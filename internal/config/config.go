package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Port        int             `yaml:"port"`
	HTTPPort    int             `yaml:"http_port"`
	HTTPSPort   int             `yaml:"https_port"`
	AdminPort   int             `yaml:"admin_port"`
	TLS         TLSConfig       `yaml:"tls"`
	Algorithm   string          `yaml:"algorithm"`
	Backends    []BackendConfig `yaml:"backends"`
	HealthCheck HealthCheck     `yaml:"health_check"`
	RateLimit   RateLimitConfig `yaml:"rate_limit"`
	ConnPool    PoolConfig      `yaml:"connection_pool"`
	Auth        APIAuthConfig   `yaml:"auth"`
	AdminAPI    AdminAPIConfig  `yaml:"admin_api"`
	Services    []Service       `yaml:"services"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type BackendConfig struct {
	URL            string      `yaml:"url"`
	Weight         int         `yaml:"weight"`
	MaxConnections int32       `yaml:"max_connections"`
	HealthCheck    HealthCheck `yaml:"health_check"`
}

type HealthCheck struct {
	Type       string        `yaml:"type"`
	Path       string        `yaml:"path"`
	Interval   time.Duration `yaml:"interval"`
	Timeout    time.Duration `yaml:"timeout"`
	Thresholds Thresholds    `yaml:"thresholds"`
}

type Thresholds struct {
	Healthy   int `yaml:"healthy"`
	Unhealthy int `yaml:"unhealthy"`
}

type RateLimitConfig struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

type PoolConfig struct {
	MaxIdle     int           `yaml:"max_idle"`
	MaxOpen     int           `yaml:"max_open"`
	IdleTimeout time.Duration `yaml:"idle_timeout"`
}

type AdminAPIConfig struct {
	Host      string          `yaml:"host"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

type APIAuthConfig struct {
	JWTSecret            string `json:"jwt_secret"`
	DBPath               string `json:"db_path"`
	TokenCleanupInterval int    `json:"token_cleanup_interval"`
	PasswordExpiryDays   int    `json:"password_expiry_days"`
	PasswordHistoryLimit int    `json:"password_history_limit"`
}

type Service struct {
	Name         string     `yaml:"name"`
	Host         string     `yaml:"host"`
	Port         int        `yaml:"port"`
	TLS          *TLSConfig `yaml:"tls"`
	HTTPRedirect bool       `yaml:"http_redirect"`
	Locations    []Location `yaml:"locations"`
}

type Location struct {
	Path         string          `yaml:"path"`
	Rewrite      string          `yaml:"rewrite"`
	Redirect     string          `yaml:"redirect"`
	LoadBalancer string          `yaml:"lb_policy"`
	Backends     []BackendConfig `yaml:"backends"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
