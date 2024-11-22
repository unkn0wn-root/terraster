package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/unkn0wn-root/terraster/internal/auth/database"
	"github.com/unkn0wn-root/terraster/internal/auth/service"
	"github.com/unkn0wn-root/terraster/internal/config"
	"github.com/unkn0wn-root/terraster/internal/server"
	"github.com/unkn0wn-root/terraster/pkg/logger"
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

type ServerBuilder struct {
	config     *config.Config
	apiConfig  *config.APIConfig
	logger     *zap.Logger
	logManager *logger.LoggerManager
}

func NewServerBuilder(
	cfg *config.Config,
	apiCfg *config.APIConfig,
	logger *zap.Logger,
	logManager *logger.LoggerManager,
) *ServerBuilder {
	return &ServerBuilder{
		config:     cfg,
		apiConfig:  apiCfg,
		logger:     logger,
		logManager: logManager,
	}
}

// BuildServer constructs the server with all necessary components
func (sb *ServerBuilder) BuildServer(ctx context.Context, errChan chan<- error) (*server.Server, error) {
	var db *database.SQLiteDB
	var authService *service.AuthService

	if sb.apiConfig.AdminAPI.Enabled {
		var err error
		db, err = database.NewSQLiteDB(sb.apiConfig.AdminDatabase.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize database: %w", err)
		}

		authService = service.NewAuthService(db, sb.buildAuthConfig())
	}

	srv, err := server.NewServer(
		ctx,
		errChan,
		sb.config,
		sb.apiConfig,
		authService,
		sb.logger,
		sb.logManager,
	)

	if err != nil {
		// If server creation fails, we need to clean up the auth service
		if authService != nil {
			authService.Close()
		}
		return nil, err
	}

	return srv, nil
}

func (sb *ServerBuilder) buildAuthConfig() service.AuthConfig {
	return service.AuthConfig{
		JWTSecret:            []byte(sb.apiConfig.AdminAuth.JWTSecret),
		TokenExpiry:          15 * time.Minute,
		RefreshTokenExpiry:   7 * 24 * time.Hour,
		MaxLoginAttempts:     5,
		LockDuration:         15 * time.Minute,
		MaxActiveTokens:      5,
		TokenCleanupInterval: 7 * time.Hour,
		PasswordMinLength:    12,
		RequireUppercase:     true,
		RequireNumber:        true,
		RequireSpecialChar:   true,
		PasswordExpiryDays:   sb.apiConfig.AdminAuth.PasswordExpiryDays,
		PasswordHistoryLimit: sb.apiConfig.AdminAuth.PasswordHistoryLimit,
	}
}

func main() {
	var configPath *string
	configPath = flag.String("config", "config.yaml", "path to config file")
	configPath = flag.String("c", "config.yaml", "path to config file")
	apiConfigPath := flag.String("api_config", "api.config.yaml", "path to API config file")
	apiConfigPath = flag.String("ac", "api.config.yaml", "path to API config file")

	flag.Parse()

	logManager, err := logger.NewLoggerManager("log.config.json")
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Ensure that all logger buffers are flushed before the application exits.
	defer func() {
		if err := logManager.Sync(); err != nil {
			log.Fatalf("Failed to sync loggers: %s", err)
		}
	}()

	// this logger is main log for both admin api and application logging
	// proxy/r,w gets own logger
	logger, err := logManager.GetLogger("main")
	if err != nil {
		log.Fatalf("Failed to get logger: %v", err)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	if err := cfg.Validate(logger); err != nil {
		logger.Fatal("Invalid config", zap.Error(err))
	}

	errChan := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	configManager := NewConfigManager(logger)
	apiConfig := configManager.LoadAPIConfig(*apiConfigPath)

	builder := NewServerBuilder(cfg, apiConfig, logger, logManager)
	srv, err := builder.BuildServer(ctx, errChan)
	if err != nil {
		logger.Fatal("Failed to initialize server", zap.Error(err))
	}

	// Set up a channel to listen for OS signals for graceful shutdown (e.g., SIGINT, SIGTERM).
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil {
			errChan <- err // Send any server start errors to the error channel.
		}
	}()

	// Listen for shutdown signals, server errors, or context cancellations.
	select {
	case <-sigChan:
		logger.Info("Shutdown signal received, starting graceful shutdown")
		cancel()
	case err := <-errChan:
		logger.Fatal("Server error triggered shutdown", zap.Error(err))
	case <-ctx.Done():
		logger.Info("Context cancelled")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil && err != context.Canceled {
		logger.Fatal("Error during shutdown", zap.Error(err))
	} else {
		logger.Info("Shutdown completed")
	}
}
