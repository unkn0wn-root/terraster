package pool

import (
	"net/url"

	"go.uber.org/zap"
)

func WithURLRewriter(config RouteConfig, backendURL *url.URL) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.urlRewriter = NewURLRewriter(p.rConfig, backendURL)
	}
}

func WithLogger(logger *zap.Logger) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.logger = logger
	}
}
