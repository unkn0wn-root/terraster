package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/unkn0wn-root/terraster/internal/config"
	"github.com/unkn0wn-root/terraster/internal/server"
	"github.com/unkn0wn-root/terraster/pkg/logger"
	"go.uber.org/zap"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to main config file")
	servicesDir := flag.String("services", "", "optional directory containing services configurations")
	apiConfigPath := flag.String("api-config", "api.config.yaml", "path to API config file")
	customLogConfigs := flag.String("log-config", "", "comma-separated paths to custom provided log config files")
	flag.Parse()

	// initilize logging manager
	logManager, logger := initializeLogging(customLogConfigs)
	defer syncLoggers(logManager)
	// load configs
	cfg, apiConfig := loadConfigs(configPath, servicesDir, apiConfigPath, logger)

	errChan := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// build server and initialize components
	srv := initializeServer(ctx, cfg, apiConfig, errChan, logger, logManager)
	// run server
	runServer(ctx, cancel, srv, errChan, logger)

}

// initializeLogging initializes the logger manager and retrieves the main logger.
func initializeLogging(customLogConfigs *string) (*logger.LoggerManager, *zap.Logger) {
	logConfigPaths := []string{"log.config.json"}
	if *customLogConfigs != "" {
		customConfigs := strings.Split(*customLogConfigs, ",")
		for _, customConfig := range customConfigs {
			if tp := strings.TrimSpace(customConfig); tp != "" {
				logConfigPaths = append(logConfigPaths, tp)
			}
		}
	}

	logManager, err := logger.NewLoggerManager(logConfigPaths)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	logger, err := logManager.GetLogger("terraster")
	if err != nil {
		log.Fatalf("Failed to get logger: %v", err)
	}
	return logManager, logger
}

// Ensure that all logger buffers are flushed before the application exits.
func syncLoggers(logManager *logger.LoggerManager) {
	if err := logManager.Sync(); err != nil {
		log.Fatalf("Failed to sync loggers: %s", err)
	}
}

// Load and merge all configuration files
func loadConfigs(configPath, servicesDir, apiConfigPath *string, logger *zap.Logger) (*config.Terraster, *config.APIConfig) {
	cfg, err := config.MergeConfigs(*configPath, *servicesDir, logger)
	if err != nil {
		logger.Fatal("Failed to load and merge configs", zap.Error(err))
	}

	configManager := NewConfigManager(logger)
	apiConfig := configManager.LoadAPIConfig(*apiConfigPath)
	return cfg, apiConfig
}

// runServerWithGracefulShutdown starts the server and listens for shutdown signals
func runServer(
	ctx context.Context,
	cancel context.CancelFunc,
	srv *server.Server,
	errChan chan error,
	logger *zap.Logger,
) {
	go func() {
		if err := srv.Start(); err != nil {
			errChan <- err // Send any server start errors to the error channel.
		}
	}()

	// Set up a channel to listen for OS signals for graceful shutdown (e.g., SIGINT, SIGTERM).
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigChan:
		logger.Warn("Shutdown signal received. Initializing graceful shutdown")
		cancel()
	case err := <-errChan:
		logger.Fatal("Server error triggered shutdown", zap.Error(err))
	case <-ctx.Done():
		return
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && err != context.Canceled {
		logger.Fatal("Error during shutdown", zap.Error(err))
	}
	logger.Info("Server shutdown completed")
}
