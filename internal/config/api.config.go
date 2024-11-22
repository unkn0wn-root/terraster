package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

// APIAuthConfig defines the authentication configuration for the API.
// It includes JWT secrets, database paths, token management settings, and password policies.
type APIConfig struct {
	AdminAPI      API            `yaml:"api"`
	AdminDatabase DatabaseConfig `yaml:"database"`
	AdminAuth     AuthConfig     `yaml:"auth"`
}

type API struct {
	Enabled bool       `yaml:"enabled"`
	Host    string     `yaml:"host"`
	Port    int        `yaml:"port"`
	TLS     *TLSConfig `yaml:"tls"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type AuthConfig struct {
	JWTSecret            string `yaml:"jwt_secret"`
	PasswordMinLength    int    `yaml:"password_min_length"`
	PasswordExpiryDays   int    `yaml:"password_expiry_days"`
	PasswordHistoryLimit int    `yaml:"password_history_limit"`
	TokenCleanupInterval string `yaml:"token_cleanup_interval"`
}

func LoadAPIConfig(path string) (*APIConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config APIConfig
	if err := yaml.UnmarshalStrict(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
