package main

import (
	"context"
	"fmt"
	"time"

	"github.com/unkn0wn-root/terraster/internal/auth/database"
	"github.com/unkn0wn-root/terraster/internal/auth/service"
	"github.com/unkn0wn-root/terraster/internal/config"
	"github.com/unkn0wn-root/terraster/internal/server"
	"github.com/unkn0wn-root/terraster/pkg/logger"
	"go.uber.org/zap"
)

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

func initializeServer(
	ctx context.Context,
	cfg *config.Config,
	apiConfig *config.APIConfig,
	errChan chan error,
	logger *zap.Logger,
	logManager *logger.LoggerManager,
) *server.Server {
	builder := NewServerBuilder(cfg, apiConfig, logger, logManager)
	srv, err := builder.BuildServer(ctx, errChan)
	if err != nil {
		logger.Fatal("Failed to initialize server", zap.Error(err))
	}

	return srv
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
