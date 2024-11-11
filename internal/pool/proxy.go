package pool

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	// HTTP Status codes
	StatusMovedPermanently  = http.StatusMovedPermanently
	StatusFound             = http.StatusFound
	StatusSeeOther          = http.StatusSeeOther
	StatusTemporaryRedirect = http.StatusTemporaryRedirect
	StatusPermanentRedirect = http.StatusPermanentRedirect

	// Header keys
	HeaderServer         = "Server"
	HeaderXPoweredBy     = "X-Powered-By"
	HeaderXProxyBy       = "X-Proxy-By"
	HeaderLocation       = "Location"
	HeaderXForwardedFor  = "X-Forwarded-For"
	HeaderXForwardedHost = "X-Forwarded-Host"
	HeaderHost           = "Host"

	DefaultScheme     = "http"
	DefaultProxyLabel = "go-load-balancer"
)

type ProxyError struct {
	Op  string
	Err error
}

func (e *ProxyError) Error() string {
	return fmt.Sprintf("proxy error during %s: %v", e.Op, e.Err)
}

type RouteConfig struct {
	Path       string // The route path (e.g., "/api")
	RewriteURL string // The URL to rewrite to (e.g., "/v1")
}

type URLRewriteProxy struct {
	proxy      *httputil.ReverseProxy
	target     *url.URL
	path       string
	rewriteURL string
	logger     *log.Logger
}

type ProxyOption func(*URLRewriteProxy)

func WithLogger(logger *log.Logger) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.logger = logger
	}
}

func NewReverseProxy(
	target *url.URL,
	config RouteConfig,
	px *httputil.ReverseProxy,
	opts ...ProxyOption,
) *URLRewriteProxy {
	prx := &URLRewriteProxy{
		target:     target,
		path:       config.Path,
		rewriteURL: config.RewriteURL,
		logger:     log.Default(),
		proxy:      px,
	}

	for _, opt := range opts {
		opt(prx)
	}

	prx.logf("Creating proxy with target: %s, path: %s, rewriteURL: %s",
		target.String(), config.Path, config.RewriteURL)

	reverseProxy := prx.proxy
	reverseProxy.Director = prx.director
	reverseProxy.ModifyResponse = prx.modifyResponse
	prx.proxy = reverseProxy

	return prx
}

func (p *URLRewriteProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, p.path) {
		p.logf("Path %s does not match prefix %s", r.URL.Path, p.path)
		http.NotFound(w, r)
		return
	}

	p.proxy.ServeHTTP(w, r)
}

func (p *URLRewriteProxy) director(req *http.Request) {
	p.logf("Processing request: %s %s", req.Method, req.URL.Path) // debug...
	p.updateRequestHeaders(req)
	p.rewriteRequestURL(req)
}

func (p *URLRewriteProxy) rewriteRequestURL(req *http.Request) {
	req.URL.Scheme = p.target.Scheme
	req.URL.Host = p.target.Host
	req.Host = p.target.Host

	p.stripPathPrefix(req)
}

func (p *URLRewriteProxy) stripPathPrefix(req *http.Request) {
	trimmed := strings.TrimPrefix(req.URL.Path, p.path)
	if p.path == "/" && req.URL.Path == "/" && p.rewriteURL == "" {
		return
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}

	// If p.rewrite is defined, append it to the trimmed path
	if p.rewriteURL != "" {
		rewritten := p.rewriteURL
		if !strings.HasPrefix(rewritten, "/") {
			rewritten = "/" + rewritten
		}

		// Remove trailing "/" from p.rewrite unless it's just "/"
		if len(rewritten) > 1 && strings.HasSuffix(rewritten, "/") {
			rewritten = strings.TrimSuffix(rewritten, "/")
		}
		req.URL.Path = rewritten + trimmed
		p.logf("Rewriting path to: %s", req.URL.Path)
	} else {
		req.URL.Path = trimmed
	}
}

func (p *URLRewriteProxy) updateRequestHeaders(req *http.Request) {
	originalHost := req.Host
	req.Header.Set(HeaderXForwardedHost, originalHost)
	req.Header.Set(HeaderXForwardedFor, originalHost)
}

func (p *URLRewriteProxy) modifyResponse(resp *http.Response) error {
	p.logf("Received response: %d", resp.StatusCode)
	if isRedirect(resp.StatusCode) {
		return p.handleRedirect(resp)
	}

	p.updateResponseHeaders(resp)
	return nil
}

func (p *URLRewriteProxy) handleRedirect(resp *http.Response) error {
	location := resp.Header.Get(HeaderLocation)
	locURL, err := url.Parse(location)
	if err != nil {
		return &ProxyError{Op: "parse_redirect_url", Err: err}
	}

	p.rewriteRedirectURL(locURL, resp)
	resp.Header.Set(HeaderLocation, locURL.String())
	return nil
}

func (p *URLRewriteProxy) rewriteRedirectURL(locURL *url.URL, resp *http.Response) {
	originalHost := resp.Request.Header.Get(HeaderXForwardedHost)
	locURL.Host = originalHost
	locURL.Scheme = DefaultScheme

	if p.rewriteURL == "" && !strings.HasPrefix(locURL.Path, p.path) {
		locURL.Path = p.path + locURL.Path
	}
}

func (p *URLRewriteProxy) updateResponseHeaders(resp *http.Response) {
	resp.Header.Del(HeaderServer)
	resp.Header.Del(HeaderXPoweredBy)
	resp.Header.Set(HeaderXProxyBy, DefaultProxyLabel)
}

func (p *URLRewriteProxy) logf(format string, args ...interface{}) {
	p.logger.Printf("[PROXY] "+format, args...)
}

func isRedirect(statusCode int) bool {
	switch statusCode {
	case StatusMovedPermanently, StatusFound, StatusSeeOther,
		StatusTemporaryRedirect, StatusPermanentRedirect:
		return true
	default:
		return false
	}
}
