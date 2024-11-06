package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type EnvConfig struct {
	config *Config
}

func NewEnvConfig() *EnvConfig {
	return &EnvConfig{
		config: &Config{},
	}
}

func (e *EnvConfig) Load() *Config {
	e.loadBasicConfig()
	e.loadTLSConfig()
	e.loadHealthCheck()
	e.loadRateLimit()
	e.loadConnectionPool()
	e.loadBackends()
	e.loadAuthBasicConfig()
	return e.config
}

func (e *EnvConfig) loadBasicConfig() {
	e.config.Port = getEnvInt("LB_PORT", 8080)
	e.config.AdminPort = getEnvInt("LB_ADMIN_PORT", 8081)
	e.config.Algorithm = getEnv("LB_ALGORITHM", "round-robin")
}

func (e *EnvConfig) loadTLSConfig() {
	e.config.TLS = TLSConfig{
		Enabled:  getEnvBool("LB_TLS_ENABLED", false),
		Domains:  getEnvStringSlice("LB_TLS_DOMAINS", []string{}),
		CertDir:  getEnv("LB_TLS_CERT_DIR", "/etc/certs"),
		AutoCert: getEnvBool("LB_TLS_AUTO_CERT", false),
		CertFile: getEnv("LB_TLS_CERT_FILE", ""),
		KeyFile:  getEnv("LB_TLS_KEY_FILE", ""),
	}
}

func (e *EnvConfig) loadHealthCheck() {
	e.config.HealthCheck = HealthCheck{
		Type:     getEnv("LB_HEALTH_CHECK_TYPE", "http"),
		Path:     getEnv("LB_HEALTH_CHECK_PATH", "/health"),
		Interval: getEnvDuration("LB_HEALTH_CHECK_INTERVAL", 10*time.Second),
		Timeout:  getEnvDuration("LB_HEALTH_CHECK_TIMEOUT", 2*time.Second),
		Thresholds: Thresholds{
			Healthy:   getEnvInt("LB_HEALTH_CHECK_HEALTHY_THRESHOLD", 2),
			Unhealthy: getEnvInt("LB_HEALTH_CHECK_UNHEALTHY_THRESHOLD", 3),
		},
	}
}

func (e *EnvConfig) loadRateLimit() {
	e.config.RateLimit = RateLimitConfig{
		RequestsPerSecond: getEnvFloat("LB_RATE_LIMIT_RPS", 100.0),
		Burst:             getEnvInt("LB_RATE_LIMIT_BURST", 150),
	}
}

func (e *EnvConfig) loadConnectionPool() {
	e.config.ConnPool = PoolConfig{
		MaxIdle:     getEnvInt("LB_CONN_POOL_MAX_IDLE", 100),
		MaxOpen:     getEnvInt("LB_CONN_POOL_MAX_OPEN", 1000),
		IdleTimeout: getEnvDuration("LB_CONN_POOL_IDLE_TIMEOUT", 90*time.Second),
	}
}

func (e *EnvConfig) loadBackends() {
	backendUrls := getEnvStringSlice("LB_BACKENDS", []string{})
	backendWeights := getEnvIntSlice("LB_BACKEND_WEIGHTS", nil)
	backendMaxConns := getEnvIntSlice("LB_BACKEND_MAX_CONNECTIONS", nil)

	for i, url := range backendUrls {
		weight := 1
		if i < len(backendWeights) {
			weight = backendWeights[i]
		}

		maxConn := 1000
		if i < len(backendMaxConns) {
			maxConn = backendMaxConns[i]
		}

		backend := BackendConfig{
			URL:            url,
			Weight:         weight,
			MaxConnections: int32(maxConn),
			HealthCheck:    e.config.HealthCheck, // Use default health check
		}

		e.config.Backends = append(e.config.Backends, backend)
	}
}

func (e *EnvConfig) loadAuthBasicConfig() {
	e.config.Auth = AuthConfig{
		Enabled: getEnvBool("LB_AUTH_ENABLED", true),
		APIKey:  getEnv("LB_AUTH_API_KEY", "default-api-key"),
	}
}

func (e *EnvConfig) loadAdminConfig() {
	e.config.AdminAPI = AdminAPIConfig{
		RateLimit: RateLimitConfig{
			RequestsPerSecond: getEnvFloat("LB_ADMIN_RATE_LIMIT_RPS", 5.0),
			Burst:             getEnvInt("LB_ADMIN_RATE_LIMIT_BURST", 10),
		},
	}
}

// Helper functions for environment variable parsing
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvFloat(key string, defaultValue float64) float64 {
	if value, exists := os.LookupEnv(key); exists {
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		return strings.ToLower(value) == "true"
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func getEnvStringSlice(key string, defaultValue []string) []string {
	if value, exists := os.LookupEnv(key); exists {
		if value == "" {
			return defaultValue
		}
		return strings.Split(value, ",")
	}
	return defaultValue
}

func getEnvIntSlice(key string, defaultValue []int) []int {
	if value, exists := os.LookupEnv(key); exists {
		if value == "" {
			return defaultValue
		}

		strValues := strings.Split(value, ",")
		intValues := make([]int, 0, len(strValues))

		for _, strValue := range strValues {
			if i, err := strconv.Atoi(strings.TrimSpace(strValue)); err == nil {
				intValues = append(intValues, i)
			}
		}

		if len(intValues) > 0 {
			return intValues
		}
	}
	return defaultValue
}
