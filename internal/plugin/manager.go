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
	DefaultTimeout = 5 * time.Second
)

type Manager struct {
	plugins []Handler
	logger  *zap.Logger
	enabled atomic.Bool
	mu      sync.RWMutex
}

func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		plugins: make([]Handler, 0, 10),
		logger:  logger,
	}
}

func (pm *Manager) Initialize(ctx context.Context, pluginDir string) error {
	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		pm.logger.Info("No plugins directory found", zap.String("path", pluginDir))
		return nil
	}

	files, err := filepath.Glob(filepath.Join(pluginDir, "*.so"))
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %w", err)
	}

	plugins := make([]Handler, 0, len(files))

	for _, file := range files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if handler, err := pm.loadPlugin(file); err != nil {
				pm.logger.Error("Failed to load plugin",
					zap.String("file", file),
					zap.Error(err),
				)
				continue
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
	pm.enabled.Store(true)
	pm.mu.Unlock()

	pm.logger.Info("Plugin system initialized",
		zap.Int("plugins_loaded", len(plugins)),
		zap.String("plugin_dir", pluginDir),
	)

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

func (pm *Manager) getPluginsNoLock() []Handler {
	return pm.plugins
}

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

func (pm *Manager) IsEnabled() bool {
	return pm.enabled.Load()
}
