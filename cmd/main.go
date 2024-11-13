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
)

func main() {
	var configPath *string
	configPath = flag.String("config", "config.yaml", "path to config file")
	configPath = flag.String("c", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	db, err := database.NewSQLiteDB(cfg.Auth.DBPath)
	if err != nil {
		log.Fatal(err)
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
	srv, err := server.NewServer(ctx, errChan, cfg, authService)
	if err != nil {
		log.Fatalf("Failed to initialize server %v", err)
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
		log.Println("Shutdown signal received, starting graceful shutdown")
		cancel()
	case err := <-errChan:
		log.Printf("Server error triggered shutdown: %v", err)
	case <-ctx.Done():
		log.Println("Context cancelled")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil && err != context.Canceled {
		log.Printf("Error during shutdown: %v", err)
	} else {
		log.Println("Shutdown completed")
	}
}
