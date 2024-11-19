package main

import (
	"context"
	"flag"
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

// main is the entry point of the Terraster application.
// It initializes configurations, logging, authentication services, and the main server.
// It also sets up graceful shutdown handling to ensure all services terminate properly.
func main() {
	var configPath *string
	// Define command-line flags for specifying the path to the configuration file.
	configPath = flag.String("config", "config.yaml", "path to config file")
	configPath = flag.String("c", "config.yaml", "path to config file")
	flag.Parse()

	// Initialize the logger manager with the specified logging configuration file.
	// The application will terminate if the logger fails to initialize.
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

	// Retrieve the main application logger from the logger manager.
	logger, err := logManager.GetLogger("main")
	if err != nil {
		log.Fatalf("Failed to get logger: %v", err)
	}

	// Load the main application configuration from the specified configuration file.
	// The application will terminate if the configuration fails to load or is invalid.
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	// Validate the loaded configuration to ensure all required fields and settings are correct.
	if err := cfg.Validate(); err != nil {
		logger.Fatal("Invalid config", zap.Error(err))
	}

	// Initialize the authentication database using the provided database path from the configuration.
	// The application will terminate if the database fails to initialize.
	db, err := database.NewSQLiteDB(cfg.Auth.DBPath)
	if err != nil {
		logger.Fatal("Failed to initialize database", zap.Error(err))
	}

	// Configure the authentication service with the necessary settings.
	// These settings include JWT secrets, token expiry durations, password policies, and more.
	authConfig := service.AuthConfig{
		JWTSecret:            []byte(cfg.Auth.JWTSecret),
		TokenExpiry:          15 * time.Minute,              // Short-lived access token.
		RefreshTokenExpiry:   7 * 24 * time.Hour,            // 7-day refresh token.
		MaxLoginAttempts:     5,                             // Maximum number of login attempts before locking the account.
		LockDuration:         15 * time.Minute,              // Duration for which the account is locked after exceeding login attempts.
		MaxActiveTokens:      5,                             // Maximum number of active tokens per user.
		TokenCleanupInterval: 7 * time.Hour,                 // Interval for cleaning up expired tokens.
		PasswordMinLength:    12,                            // Minimum required length for passwords.
		RequireUppercase:     true,                          // Enforce inclusion of uppercase letters in passwords.
		RequireNumber:        true,                          // Enforce inclusion of numbers in passwords.
		RequireSpecialChar:   true,                          // Enforce inclusion of special characters in passwords.
		PasswordExpiryDays:   cfg.Auth.PasswordExpiryDays,   // Number of days after which passwords expire.
		PasswordHistoryLimit: cfg.Auth.PasswordHistoryLimit, // Number of previous passwords to remember and prevent reuse.
	}

	// Initialize the authentication service with the database and configuration.
	// The service is responsible for handling user authentication, token management, and related functionalities.
	authService := service.NewAuthService(db, authConfig)
	// Ensure that the authentication service cleans up any background tasks or resources when the application exits.
	defer authService.Close()

	// Create a cancellable context that can be used to signal shutdown across all components.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize a channel to receive error notifications from the server.
	errChan := make(chan error, 1)
	// Create a new server instance with the provided context, error channel, configuration, authentication service, and loggers.
	srv, err := server.NewServer(ctx, errChan, cfg, authService, logger, logManager)
	if err != nil {
		logger.Fatal("Failed to initialize server", zap.Error(err))
	}

	// Set up a channel to listen for OS signals for graceful shutdown (e.g., SIGINT, SIGTERM).
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the server in a separate goroutine to allow the main goroutine to listen for shutdown signals.
	go func() {
		if err := srv.Start(); err != nil {
			errChan <- err // Send any server start errors to the error channel.
		}
	}()

	// Listen for shutdown signals, server errors, or context cancellations.
	select {
	case <-sigChan:
		// Received an OS signal to terminate the application.
		logger.Info("Shutdown signal received, starting graceful shutdown")
		cancel() // Cancel the context to signal all components to begin shutdown.
	case err := <-errChan:
		// Received an error from the server, initiating shutdown.
		logger.Fatal("Server error triggered shutdown", zap.Error(err))
	case <-ctx.Done():
		// Context was canceled, possibly by another part of the application.
		logger.Info("Context cancelled")
	}

	// Create a context with a timeout to ensure that the shutdown process does not hang indefinitely.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	// Attempt to gracefully shut down the server, allowing up to 15 seconds for active connections to close.
	if err := srv.Shutdown(shutdownCtx); err != nil && err != context.Canceled {
		logger.Fatal("Error during shutdown", zap.Error(err))
	} else {
		logger.Info("Shutdown completed")
	}
}
