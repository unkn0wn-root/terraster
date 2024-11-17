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

func main() {
	var configPath *string
	configPath = flag.String("config", "config.yaml", "path to config file")
	configPath = flag.String("c", "config.yaml", "path to config file")
	flag.Parse()

	if err := logger.Init("log.config.json"); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	logger := logger.Logger()

	defer func() {
		if err := logger.Sync(); err != nil {
			log.Printf("Logger sync error: %v", err)
		}
	}()

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	if err := cfg.Validate(); err != nil {
		logger.Fatal("Invalid config", zap.Error(err))
	}

	// Initialize database
	db, err := database.NewSQLiteDB(cfg.Auth.DBPath)
	if err != nil {
		logger.Fatal("Failed to initialize database", zap.Error(err))
	}

	// Initialize auth service
	authConfig := service.AuthConfig{
		JWTSecret:            []byte(cfg.Auth.JWTSecret),
		TokenExpiry:          15 * time.Minute,   // Short-lived access token
		RefreshTokenExpiry:   7 * 24 * time.Hour, // 7-day refresh token
		MaxLoginAttempts:     5,
		LockDuration:         15 * time.Minute,
		MaxActiveTokens:      5,
		TokenCleanupInterval: 7 * time.Hour,
		PasswordMinLength:    12,
		RequireUppercase:     true,
		RequireNumber:        true,
		RequireSpecialChar:   true,
		PasswordExpiryDays:   cfg.Auth.PasswordExpiryDays,
		PasswordHistoryLimit: cfg.Auth.PasswordHistoryLimit,
	}
	authService := service.NewAuthService(db, authConfig)
	defer authService.Close() // Cleanup background tasks

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	srv, err := server.NewServer(ctx, errChan, cfg, authService, logger)
	if err != nil {
		logger.Fatal("Failed to initialize server", zap.Error(err))
	}

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil {
			errChan <- err
		}
	}()

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
