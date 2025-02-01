package plugin

import (
	"context"
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
	PluginDir      = "./plugins" // Default directory for plugins
	DefaultTimeout = 100 * time.Millisecond
)

// Handler defines the interface that all plugins must implement
type Handler interface {
	// ProcessRequest processes the request before it's sent to the backend
	// Context MUST be honored for cancellation and timeouts
	ProcessRequest(ctx context.Context, req *http.Request)

	// ProcessResponse processes the response before it's sent back to the client
	// Context MUST be honored for cancellation and timeouts
	ProcessResponse(ctx context.Context, resp *http.Response)

	// Name returns the plugin name
	Name() string

	// Priority returns the plugin priority (lower numbers run first)
	Priority() int

	// Cleanup performs any necessary cleanup when the plugin is unloaded
	Cleanup() error
}

// Manager handles plugin lifecycle and execution with minimal lock contention
type Manager struct {
	plugins []Handler
	logger  *zap.Logger
	mu      sync.RWMutex
	enabled atomic.Bool
}

// NewManager creates an optimized plugin manager
func NewManager(logger *zap.Logger) *Manager {
	pm := &Manager{
		plugins: make([]Handler, 0, 10), // Pre-allocate
		logger:  logger,
	}
	return pm
}

func (pm *Manager) Initialize(ctx context.Context) error {
	execPath, err := os.Executable() // get exec. path
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Plugin directory is always next to the executable
	pluginPath := filepath.Join(filepath.Dir(execPath), PluginDir)

	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
		pm.logger.Info("No plugins directory found", zap.String("path", pluginPath))
		return nil // Not an error, just no plugins
	}

	files, err := filepath.Glob(filepath.Join(pluginPath, "*.so"))
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %w", err)
	}

	plugins := make([]Handler, 0, len(files))

	for _, file := range files {
		// Use context for initialization timeout
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if handler, err := pm.loadPlugin(file); err != nil {
				pm.logger.Error("Failed to load plugin",
					zap.String("file", file),
					zap.Error(err),
				)
				continue // Skip failed plugins but continue loading others
			} else {
				plugins = append(plugins, handler)
			}
		}
	}

	// Sort plugins by priority
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Priority() < plugins[j].Priority()
	})

	pm.mu.Lock()
	pm.plugins = plugins
	pm.mu.Unlock()

	if len(plugins) > 0 {
		pm.enabled.Store(true)
		pm.logger.Info("Plugin system initialized",
			zap.Int("plugins_loaded", len(plugins)),
			zap.String("plugin_dir", pluginPath),
		)
	}

	return nil
}

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

// getRequestContext returns the appropriate context for plugin execution
func (pm *Manager) getRequestContext(req *http.Request) (context.Context, context.CancelFunc) {
	// Use request's context as parent to inherit any user-provided deadlines/cancellation
	ctx := req.Context()

	// If parent context has no deadline and we have a default timeout
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return context.WithTimeout(ctx, DefaultTimeout)
	}

	// Otherwise just create a new cancel context inheriting parent deadline/cancellation
	return context.WithCancel(ctx)
}

// ProcessRequest executes request processors honoring context
func (pm *Manager) ProcessRequest(req *http.Request) {
	if !pm.enabled.Load() {
		return
	}

	ctx, cancel := pm.getRequestContext(req)
	defer cancel()

	pm.mu.RLock()
	plugins := pm.plugins
	pm.mu.RUnlock()

	for _, p := range plugins {
		select {
		case <-ctx.Done():
			return
		default:
			p.ProcessRequest(ctx, req)
		}
	}
}

// ProcessResponse executes response processors honoring context
func (pm *Manager) ProcessResponse(resp *http.Response) {
	if !pm.enabled.Load() {
		return
	}

	ctx, cancel := pm.getRequestContext(resp.Request)
	defer cancel()

	pm.mu.RLock()
	plugins := pm.plugins
	pm.mu.RUnlock()

	for _, p := range plugins {
		select {
		case <-ctx.Done():
			return
		default:
			p.ProcessResponse(ctx, resp)
		}
	}

	return
}

// Shutdown cleans up plugins
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

// IsEnabled returns whether the plugin system is enabled
func (pm *Manager) IsEnabled() bool {
	return pm.enabled.Load()
}
