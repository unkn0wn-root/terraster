package pool

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"go.uber.org/zap"
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
	DefaultProxyLabel = "terraster"
)

type ProxyError struct {
	Op  string
	Err error
}

func (e *ProxyError) Error() string {
	return fmt.Sprintf("proxy error during %s: %v", e.Op, e.Err)
}

type RouteConfig struct {
	Path          string // path is proxy path (upstream) (optional)
	RewriteURL    string // rewriteURL is the URL to rewrite to (downstream) (optional)
	Redirect      string // URL to redirect to (optional)
	SkipTLSVerify bool   // skipTLSVerify skips TLS verification (optional)
}

type Transport struct {
	transport http.RoundTripper
}

func NewTransport(transport http.RoundTripper, skipTLSVerify bool) *Transport {
	transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: skipTLSVerify}
	return &Transport{transport: transport}
}

type URLRewriteProxy struct {
	proxy       *httputil.ReverseProxy
	target      *url.URL
	path        string
	rewriteURL  string
	urlRewriter *URLRewriter
	rConfig     RewriteConfig
	logger      *zap.Logger
}

type ProxyOption func(*URLRewriteProxy)

func NewReverseProxy(
	target *url.URL,
	config RouteConfig,
	px *httputil.ReverseProxy,
	logger *zap.Logger,
	opts ...ProxyOption,
) *URLRewriteProxy {
	rewriteConfig := RewriteConfig{
		ProxyPath:  config.Path,
		RewriteURL: config.RewriteURL,
		Redirect:   config.Redirect,
	}

	proxyLogger := logger.With(zap.String("prefix", "PROXY"))
	prx := &URLRewriteProxy{
		target:     target,
		path:       config.Path,
		rewriteURL: config.RewriteURL,
		rConfig:    rewriteConfig,
		logger:     proxyLogger,
		proxy:      px,
	}

	for _, opt := range opts {
		opt(prx)
	}

	if prx.urlRewriter == nil {
		prx.urlRewriter = NewURLRewriter(prx.rConfig, target)
	}

	prx.logger.Info("Creating proxy",
		zap.String("target", target.String()),
		zap.String("path", config.Path),
		zap.String("rewriteURL", config.RewriteURL),
	)

	reverseProxy := prx.proxy
	reverseProxy.Director = prx.director
	reverseProxy.ModifyResponse = prx.modifyResponse
	reverseProxy.Transport = NewTransport(http.DefaultTransport, config.SkipTLSVerify)
	reverseProxy.ErrorHandler = prx.errorHandler
	reverseProxy.BufferPool = NewBufferPool()

	prx.proxy = reverseProxy

	return prx
}

func (p *URLRewriteProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check for redirect first
	if shouldRedirect, redirectPath := p.urlRewriter.shouldRedirect(r); shouldRedirect {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		redirectURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, redirectPath)
		http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
		return
	}

	p.proxy.ServeHTTP(w, r)
}

func (p *URLRewriteProxy) director(req *http.Request) {
	p.updateRequestHeaders(req)
	p.urlRewriter.rewriteRequestURL(req, p.target)
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(req)
}

func (p *URLRewriteProxy) updateRequestHeaders(req *http.Request) {
	originalHost := req.Host
	req.Header.Set(HeaderXForwardedHost, originalHost)
	req.Header.Set(HeaderXForwardedFor, originalHost)
}

func (p *URLRewriteProxy) handleRedirect(resp *http.Response) error {
	location := resp.Header.Get(HeaderLocation)
	locURL, err := url.Parse(location)
	if err != nil {
		return &ProxyError{Op: "parse_redirect_url", Err: err}
	}

	// don't rewrite if the location is not on the same host
	// this is because of external IDPs or authentication providers
	// where you are redirected to a different domain for authentication
	// and then callback to our backend
	if locURL.Host != p.target.Host {
		return nil
	}

	originalHost := resp.Request.Header.Get(HeaderXForwardedHost)
	p.urlRewriter.rewriteRedirectURL(locURL, originalHost)
	resp.Header.Set(HeaderLocation, locURL.String())
	return nil
}

func (p *URLRewriteProxy) modifyResponse(resp *http.Response) error {
	if isRedirect(resp.StatusCode) {
		p.handleRedirect(resp)
	}

	p.updateResponseHeaders(resp)
	return nil
}

func (p *URLRewriteProxy) updateResponseHeaders(resp *http.Response) {
	resp.Header.Del(HeaderServer)
	resp.Header.Del(HeaderXPoweredBy)
	resp.Header.Set(HeaderXProxyBy, DefaultProxyLabel)
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

func (p *URLRewriteProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	p.logger.Error("Unexpected error in proxy", zap.Error(err))
	http.Error(w, "Something went wrong", http.StatusInternalServerError)
}
