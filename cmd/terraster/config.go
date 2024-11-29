package main

import (
	"github.com/unkn0wn-root/terraster/internal/config"
	"go.uber.org/zap"
)

// ConfigManager handles configuration loading and provides defaults
type ConfigManager struct {
	logger *zap.Logger
}

func NewConfigManager(logger *zap.Logger) *ConfigManager {
	return &ConfigManager{
		logger: logger,
	}
}

// LoadAPIConfig loads the API configuration with graceful fallback to set admin api as disabled
func (cm *ConfigManager) LoadAPIConfig(path string) *config.APIConfig {
	cfg, err := config.LoadAPIConfig(path)
	if err != nil {
		cm.logger.Warn("Failed to load Admin API configuration file. Admin API is disabled",
			zap.Error(err),
			zap.String("path", path))

		return &config.APIConfig{
			AdminAPI: config.API{
				Enabled: false,
			},
		}
	}

	return cfg
}
