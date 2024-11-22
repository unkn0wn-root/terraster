package pool

import (
	"net/url"

	"go.uber.org/zap"
)

// WithURLRewriter is a functional option for configuring the URLRewriteProxy.
// It sets up a URL rewriter based on the provided RouteConfig and backend URL.
// This allows the proxy to modify incoming request URLs according to the specified rewrite rules,
// ensuring that requests are correctly routed to the intended backend services.
func WithURLRewriter(config RouteConfig, backendURL *url.URL) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.urlRewriter = NewURLRewriter(p.rConfig, backendURL)
	}
}

// Functional option for configuring the URLRewriteProxy with a custom logger.
func WithLogger(logger *zap.Logger) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.logger = logger
	}
}
