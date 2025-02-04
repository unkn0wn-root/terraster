package plugin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"plugin"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	DefaultTimeout = 5 * time.Second // DefaultTimeout defines the maximum time allowed for plugin processing
)

var (
	ErrFailedToRead = errors.New("Failed to read plugin directory")
	ErrFailedToLoad = errors.New("Failed to load plugin")
)

// Manager handles loading, initialization, and execution of plugins
type Manager struct {
	plugins []Handler // Ordered list of plugin handlers
	logger  *zap.Logger
	enabled atomic.Bool
	mu      sync.RWMutex
}

// NewManager creates a Manager instance with initial capacity of 10 plugins
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		plugins: make([]Handler, 0, 10),
		logger:  logger,
	}
}

// Initialize loads all .so plugin files from the specified directory.
// Plugins are sorted by priority after loading.
// Context is used to cancel the initialization process.
func (pm *Manager) Initialize(ctx context.Context, pluginDir string) error {
	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		pm.logger.Info("Plugins directory not found. Plugin not enabled", zap.String("path", pluginDir))
		return nil
	}

	files, err := filepath.Glob(filepath.Join(pluginDir, "*.so"))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToRead, err)
	}

	// return if there are no plugins
	if len(files) == 0 {
		return nil
	}

	plugins := make([]Handler, 0, len(files))
	for _, file := range files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			handler, err := pm.loadPlugin(file)
			if err != nil {
				pm.logger.Error("Failed to load plugin",
					zap.String("file", file),
					zap.Error(err))
				return ErrFailedToLoad
			}
			plugins = append(plugins, handler)
		}
	}

	// Sort plugins by priority
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Priority() < plugins[j].Priority()
	})

	pm.mu.Lock()
	pm.plugins = plugins
	pm.enabled.Store(true)
	pm.mu.Unlock()

	pm.logger.Info("Plugin system initialized",
		zap.Int("plugins_loaded", len(plugins)),
		zap.String("plugin_dir", pluginDir),
	)

	return nil
}

// loadPlugin loads a single plugin from the given path.
// The plugin must export a "New" function that returns a Handler.
func (pm *Manager) loadPlugin(path string) (Handler, error) {
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin: %w", err)
	}

	newFunc, err := p.Lookup("New")
	if err != nil {
		return nil, fmt.Errorf("plugin does not export 'New' symbol: %w", err)
	}

	createPlugin, ok := newFunc.(func() Handler)
	if !ok {
		return nil, fmt.Errorf("plugin 'New' has wrong signature")
	}

	handler := createPlugin()
	pm.logger.Info("Loaded plugin",
		zap.String("name", handler.Name()),
		zap.Int("priority", handler.Priority()),
		zap.String("path", path),
	)

	return handler, nil
}

// ProcessRequest executes plugins in priority order for HTTP requests.
// Returns early on timeout or if a plugin returns Stop action.
// Uses default timeout if request context has no deadline.
func (pm *Manager) ProcessRequest(req *http.Request) *Result {
	if !pm.enabled.Load() {
		return ResultContinue
	}

	ctx := req.Context()
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}

	plugins := pm.getPluginsNoLock()
	for _, p := range plugins {
		select {
		case <-ctx.Done():
			return NewResult(
				Stop,
				WithStatus(http.StatusGatewayTimeout),
				WithJSONResponse(map[string]string{
					"error": "plugin processing timeout",
				}),
			)
		default:
			result := p.ProcessRequest(ctx, req)
			action := result.Action()
			if action == Stop {
				return result
			}

			if result != ResultContinue && result != ResultModify {
				result.Release()
			}
		}
	}

	return ResultContinue
}

// ProcessResponse executes plugins in priority order for HTTP responses.
// Returns early on context cancellation or if a plugin returns Stop action.
func (pm *Manager) ProcessResponse(resp *http.Response) *Result {
	if !pm.enabled.Load() {
		return ResultContinue
	}

	ctx := resp.Request.Context()
	plugins := pm.getPluginsNoLock()

	for _, p := range plugins {
		select {
		case <-ctx.Done():
			return ResultContinue
		default:
			result := p.ProcessResponse(ctx, resp)
			action := result.Action()

			if action == Stop {
				return result
			}

			if result != ResultContinue && result != ResultModify {
				result.Release()
			}
		}
	}

	return ResultContinue
}

// getPluginsNoLock returns the current plugins slice without locking
func (pm *Manager) getPluginsNoLock() []Handler {
	return pm.plugins
}

// Shutdown cleans up all plugins and disables the manager.
// Context can be used to cancel the shutdown process
func (pm *Manager) Shutdown(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, p := range pm.plugins {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := p.Cleanup(); err != nil {
				pm.logger.Error("Plugin cleanup failed",
					zap.String("plugin", p.Name()),
					zap.Error(err),
				)
			}
		}
	}

	pm.enabled.Store(false)
	pm.plugins = nil
	return nil
}

// IsEnabled returns whether the plugin manager is currently enabled.
func (pm *Manager) IsEnabled() bool {
	return pm.enabled.Load()
}
