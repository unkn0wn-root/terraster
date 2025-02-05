package pool

import (
	"net/url"

	"github.com/unkn0wn-root/terraster/internal/config"
	"github.com/unkn0wn-root/terraster/pkg/plugin"
	"go.uber.org/zap"
)

// WithURLRewriter is configuring the URLRewriteProxy.
// It sets up a URL rewriter based on the provided Route and backend URL.
// This allows the proxy to modify incoming request URLs according to the specified rewrite rules,
// ensuring that requests are correctly routed to the intended backend services.
func WithURLRewriter(config Route, backendURL *url.URL) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.urlRewriter = NewURLRewriter(p.rConfig, backendURL)
	}
}

// WithLogger is configuring the URLRewriteProxy with a custom logger.
func WithLogger(logger *zap.Logger) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.logger = logger
	}
}

// WithHeaderConfig sets custom req/res headers
func WithHeaderConfig(cfg *config.Header) ProxyOption {
	return func(p *URLRewriteProxy) {
		if cfg == nil {
			return
		}

		p.headerHandler = NewHeaderHandler(*cfg)
	}
}

func WithPluginManager(pm *plugin.Manager) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.pluginManager = pm
		p.pluginEnabled = pm != nil && pm.IsEnabled()
	}
}
