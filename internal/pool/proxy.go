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
	proxy       *httputil.ReverseProxy
	target      *url.URL
	path        string
	rewriteURL  string
	frontendURL string
	logger      *log.Logger
}

type ProxyOption func(*URLRewriteProxy)

func WithLogger(logger *log.Logger) ProxyOption {
	return func(p *URLRewriteProxy) {
		p.logger = logger
	}
}

func NewReverseProxy(target *url.URL, config RouteConfig, frontendHost string, px *httputil.ReverseProxy, opts ...ProxyOption) *URLRewriteProxy {
	proxy := &URLRewriteProxy{
		target:      target,
		path:        config.Path,
		rewriteURL:  config.RewriteURL,
		frontendURL: frontendHost,
		logger:      log.Default(),
		proxy:       px,
	}

	for _, opt := range opts {
		opt(proxy)
	}

	proxy.logf("Creating proxy with target: %s, path: %s, rewriteURL: %s",
		target.String(), config.Path, config.RewriteURL)

	reverseProxy := proxy.proxy
	reverseProxy.Director = proxy.director
	reverseProxy.ModifyResponse = proxy.modifyResponse
	reverseProxy.ErrorHandler = proxy.errorHandler
	proxy.proxy = reverseProxy

	return proxy
}

func (p *URLRewriteProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.logf("Incoming request: %s %s", r.Method, r.URL.Path) // @todo - should be in debug

	if !strings.HasPrefix(r.URL.Path, p.path) {
		p.logf("Path %s does not match prefix %s, returning 404", r.URL.Path, p.path)
		http.NotFound(w, r)
		return
	}

	p.proxy.ServeHTTP(w, r)
}

func (p *URLRewriteProxy) director(req *http.Request) {
	p.logf("Processing request: %s %s", req.Method, req.URL.Path) // debug...

	originalPath := req.URL.Path
	p.updateRequestHeaders(req)
	p.rewriteRequestURL(req)

	p.logf("Rewrote request: %s -> %s://%s%s",
		originalPath, req.URL.Scheme, req.URL.Host, req.URL.Path)
}

func (p *URLRewriteProxy) rewriteRequestURL(req *http.Request) {
	req.URL.Scheme = p.target.Scheme
	req.URL.Host = p.target.Host
	req.Host = p.target.Host

	if p.rewriteURL == "" {
		p.stripPathPrefix(req)
	}
}

func (p *URLRewriteProxy) stripPathPrefix(req *http.Request) {
	path := strings.TrimPrefix(req.URL.Path, p.path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path == "/" && len(strings.TrimPrefix(req.URL.Path, p.path)) == 0 {
		path = "/"
	}
	req.URL.Path = path
}

func (p *URLRewriteProxy) updateRequestHeaders(req *http.Request) {
	originalHost := req.Host
	req.Header.Set(HeaderXForwardedHost, originalHost)
	req.Header.Set(HeaderXForwardedFor, req.RemoteAddr)
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
	p.logf("Processing redirect to: %s", location)

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

	p.logf("Rewrote redirect to: %s", locURL.String())
}

func (p *URLRewriteProxy) updateResponseHeaders(resp *http.Response) {
	resp.Header.Del(HeaderServer)
	resp.Header.Del(HeaderXPoweredBy)
	resp.Header.Set(HeaderXProxyBy, DefaultProxyLabel)
}

func (p *URLRewriteProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	p.logf("Proxy error: %v", err)
	http.Error(w, "Proxy Error", http.StatusBadGateway)
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
