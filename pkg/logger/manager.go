package logger

import (
	"fmt"
	"sync"

	"go.uber.org/zap"
)

type LoggerManager struct {
	loggers       map[string]*zap.Logger
	mu            sync.RWMutex
	defaultConfig *Config
}

func NewLoggerManager(logsConfigPaths []string) (*LoggerManager, error) {
	lm := &LoggerManager{
		loggers:       make(map[string]*zap.Logger),
		defaultConfig: &DefaultConfig,
	}

	// init logger but since we need logger - panic if it fails
	if err := Init(logsConfigPaths, lm); err != nil {
		return nil, err
	}

	return lm, nil
}

// adds a new logger to the manager.
// Returns error if a logger with the same name already exists.
func (lm *LoggerManager) AddLogger(name string, logger *zap.Logger) error {
	if logger == nil {
		return fmt.Errorf("logger cannot be nil")
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	if _, exists := lm.loggers[name]; exists {
		return fmt.Errorf("logger '%s' already exists", name)
	}

	lm.loggers[name] = logger
	return nil
}

// Retrieves a logger by name. Returns error if logger doesn't exist.
func (lm *LoggerManager) GetLogger(name string) (*zap.Logger, error) {
	// First try read lock
	lm.mu.RLock()
	logger, exists := lm.loggers[name]
	lm.mu.RUnlock()
	if exists {
		return logger, nil
	}

	return nil, fmt.Errorf("logger '%s' not found", name)
}

// Returns a copy of the map containing all loggers.
func (lm *LoggerManager) GetAllLoggers() map[string]*zap.Logger {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	copyMap := make(map[string]*zap.Logger, len(lm.loggers))
	for k, v := range lm.loggers {
		copyMap[k] = v
	}
	return copyMap
}

// Sync flushes all loggers managed by LoggerManager.
// Returns a multi-error containing all sync errors encountered.
func (lm *LoggerManager) Sync() error {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	var errs []error
	for name, logger := range lm.loggers {
		if err := logger.Sync(); err != nil {
			errs = append(errs, fmt.Errorf("failed to sync logger '%s': %w", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("sync errors: %v", errs)
	}
	return nil
}

// Removes a logger from the manager.
// Returns error if logger doesn't exist.
func (lm *LoggerManager) RemoveLogger(name string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if _, exists := lm.loggers[name]; !exists {
		return fmt.Errorf("logger '%s' not found", name)
	}

	delete(lm.loggers, name)
	return nil
}
