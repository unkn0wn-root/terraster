package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Port        int             `yaml:"port"`
	AdminPort   int             `yaml:"admin_port"`
	TLS         TLSConfig       `yaml:"tls"`
	Algorithm   string          `yaml:"algorithm"`
	Backends    []BackendConfig `yaml:"backends"`
	HealthCheck HealthCheck     `yaml:"health_check"`
	RateLimit   RateLimitConfig `yaml:"rate_limit"`
	ConnPool    PoolConfig      `yaml:"connection_pool"`
	Auth        AuthConfig      `yaml:"auth"`
	AdminAPI    AdminAPIConfig  `yaml:"admin_api"`
}

type TLSConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Domains  []string `yaml:"domains"`
	CertDir  string   `yaml:"cert_dir"`
	AutoCert bool     `yaml:"auto_cert"`
	CertFile string   `yaml:"cert_file"`
	KeyFile  string   `yaml:"key_file"`
}

type BackendConfig struct {
	URL            string      `yaml:"url"`
	Weight         int         `yaml:"weight"`
	MaxConnections int         `yaml:"max_connections"`
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

type AuthConfig struct {
	Enabled bool   `yaml:"enabled"`
	APIKey  string `yaml:"api_key"`
}

type AdminAPIConfig struct {
	RateLimit RateLimitConfig `yaml:"rate_limit"`
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
