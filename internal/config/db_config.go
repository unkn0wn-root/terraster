package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

// APIAuthConfig defines the authentication configuration for the API.
// It includes JWT secrets, database paths, token management settings, and password policies.
type APIAuthConfig struct {
	JWTSecret            string `yaml:"jwt_secret"`             // Secret key used for signing JWT tokens.
	PasswordMinLength    int    `yaml:"password_min_length"`    // Minimum length for user passwords.
	DBPath               string `yaml:"db_path"`                // Path to the authentication database.
	TokenCleanupInterval string `yaml:"token_cleanup_interval"` // Interval for cleaning up expired tokens e.g. "24h", "30m", "1d".
	PasswordExpiryDays   int    `yaml:"password_expiry_days"`   // Number of days after which passwords expire.
	PasswordHistoryLimit int    `yaml:"password_history_limit"` // Number of previous passwords to remember and prevent reuse.
}

func LoadAPIConfig(path string) (*APIAuthConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config APIAuthConfig
	if err := yaml.UnmarshalStrict(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
