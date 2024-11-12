package pool

import (
	"log"
	"net/url"
)

func WithURLRewriter(config RouteConfig, backendURL *url.URL) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.urlRewriter = NewURLRewriter(p.rConfig, backendURL)
	}
}

func WithLogger(logger *log.Logger) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.logger = logger
	}
}
