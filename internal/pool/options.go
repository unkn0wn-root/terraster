package pool

import (
	"net/url"

	"go.uber.org/zap"
)

// WithURLRewriter is a functional option for configuring the URLRewriteProxy.
// It sets up a URL rewriter based on the provided RouteConfig and backend URL.
// This allows the proxy to modify incoming request URLs according to the specified rewrite rules,
// ensuring that requests are correctly routed to the intended backend services.
//
// Parameters:
// - config: RouteConfig defines the routing and rewriting rules for the proxy.
// - backendURL: *url.URL specifies the target backend server's URL.
//
// Returns:
// - ProxyOption: A function that applies the URL rewriter configuration to a URLRewriteProxy instance.
//
// Usage Example:
// proxy := NewReverseProxy(targetURL, config, httputil.NewSingleHostReverseProxy(targetURL), logger, WithURLRewriter(config, targetURL))
func WithURLRewriter(config RouteConfig, backendURL *url.URL) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.urlRewriter = NewURLRewriter(p.rConfig, backendURL)
	}
}

// WithLogger is a functional option for configuring the URLRewriteProxy with a custom logger.
// It allows the proxy to use a specific zap.Logger instance for logging purposes,
// enabling better control over log formatting, levels, and output destinations.
//
// Parameters:
// - logger: *zap.Logger is the logger instance to be used by the URLRewriteProxy.
//
// Returns:
// - ProxyOption: A function that applies the logger configuration to a URLRewriteProxy instance.
//
// Usage Example:
// proxy := NewReverseProxy(targetURL, config, httputil.NewSingleHostReverseProxy(targetURL), logger, WithLogger(customLogger))
func WithLogger(logger *zap.Logger) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.logger = logger
	}
}
