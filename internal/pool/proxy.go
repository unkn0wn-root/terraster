package pool

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/unkn0wn-root/terraster/internal/plugin"
	"go.uber.org/zap"
)

// Constants representing various HTTP status codes used for redirection.
const (
	StatusMovedPermanently  = http.StatusMovedPermanently
	StatusFound             = http.StatusFound
	StatusSeeOther          = http.StatusSeeOther
	StatusTemporaryRedirect = http.StatusTemporaryRedirect
	StatusPermanentRedirect = http.StatusPermanentRedirect

	HeaderServer         = "Server"           // The Server header identifies the server software handling the request.
	HeaderLocation       = "Location"         // The Location header is used in redirection or when a new resource has been created.
	HeaderHost           = "Host"             // The Host header specifies the domain name of the server and the TCP port number on which the server is listening.
	HeaderXPoweredBy     = "X-Powered-By"     // The X-Powered-By header indicates technologies supporting the server.
	HeaderXProxyBy       = "X-Proxy-By"       // The X-Proxy-By header identifies the proxy handling the request.
	HeaderXRealIP        = "X-Real-IP"        // The X-Real-IP header identifies the originating IP address of a client
	HeaderXForwardedFor  = "X-Forwarded-For"  // The X-Forwarded-For header identifies the originating IP address of a client connecting to a web server through a proxy.
	HeaderXForwardedHost = "X-Forwarded-Host" // The X-Forwarded-Host header identifies the original host requested by the client.

	DefaultScheme     = "http"
	DefaultProxyLabel = "terraster"

	PluginLoadTime = 5 * time.Second
)

// RouteConfig holds configuration settings for routing requests through the proxy.
type RouteConfig struct {
	Path          string // Path is the proxy path (upstream) used to match incoming requests (optional).
	RewriteURL    string // RewriteURL is the URL to rewrite the incoming request to (downstream) (optional).
	Redirect      string // Redirect is the URL to redirect the request to (optional).
	SkipTLSVerify bool   // SkipTLSVerify determines whether to skip TLS certificate verification for backend connections (optional).
	SNI           string // SNI (Server Name Indication) is the backend virtual host name separate from proxy server name
	HTTP2         bool   // HTTP2 enables proxy to force connect to backend server via HTTP/2 protocol
}

// URLRewriteProxy is a custom reverse proxy that handles URL rewriting and redirection based on RouteConfig.
type URLRewriteProxy struct {
	proxy         *httputil.ReverseProxy // proxy is the underlying reverse proxy handling the HTTP requests.
	target        *url.URL               // target is the destination URL to which the proxy forwards requests.
	path          string                 // path is the URL path prefix that this proxy handles.
	rewriteURL    string                 // rewriteURL specifies the URL to which incoming requests should be rewritten.
	urlRewriter   *URLRewriter           // urlRewriter handles the logic for rewriting request URLs and managing redirects.
	rConfig       RewriteConfig          // rConfig holds the rewrite and redirect configurations.
	logger        *zap.Logger            // logger is used for logging proxy-related activities.
	headerHandler *HeaderHandler         // headerHandler is used to modify request/response headers
	routeSNI      string                 // serverName is the backend virtual host name (SNI) separate from proxy server name
	h2            bool                   // h2 enables connection to backend service via http/2 protocol
	pluginManager *plugin.Manager
}

// ProxyOption defines a function type for applying optional configurations to URLRewriteProxy instances.
type ProxyOption func(*URLRewriteProxy)

// This sets up the reverse proxy with the specified target, route configurations, and applies any additional proxy options.
// The function also configures the reverse proxy's Director, ModifyResponse, Transport, ErrorHandler, and BufferPool.
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
		routeSNI:   config.SNI,
		h2:         config.HTTP2,
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
		zap.Bool("http2_enabled", prx.h2),
	)

	// default timeout when loading plugins. After `x`time, plugins will be skiped
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(PluginLoadTime))
	defer cancel()

	pm := plugin.NewManager(prx.logger)
	if err := pm.Initialize(ctx); err != nil {
		prx.logger.Error("Failed to initialize plugin system", zap.Error(err))
	} else {
		prx.pluginManager = pm
	}

	// Clone the default transport to avoid modifying the global one
	dt := http.DefaultTransport.(*http.Transport).Clone()
	transporter := NewTransport(dt)
	transporter.ConfigureTransport(config.SNI, config.SkipTLSVerify, prx.h2)

	reverseProxy := prx.proxy
	reverseProxy.Director = prx.director
	reverseProxy.ModifyResponse = prx.modifyResponse
	reverseProxy.Transport = transporter
	reverseProxy.ErrorHandler = prx.errorHandler
	reverseProxy.BufferPool = NewBufferPool()

	prx.proxy = reverseProxy

	return prx
}

// ServeHTTP handles incoming HTTP requests by determining whether to redirect or proxy the request.
// If a redirect is necessary based on the URLRewriter's logic, it performs the redirection.
// Otherwise, it forwards the request to the configured backend proxy.
func (p *URLRewriteProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if shouldRedirect, redirectPath := p.urlRewriter.shouldRedirect(r); shouldRedirect {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		redirectURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, redirectPath)
		http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
		return
	}

	// Pass request to external plugin if defined
	// this will allow modification to request object before passing down
	if p.isPluginEnabled() {
		p.pluginManager.ProcessRequest(r)
	}

	p.proxy.ServeHTTP(w, r)
}

// director modifies the incoming HTTP request before it is sent to the backend server.
func (p *URLRewriteProxy) director(req *http.Request) {
	p.updateRequestHeaders(req)
	p.urlRewriter.rewriteRequestURL(req, p.target)
}

// updateRequestHeaders modifies the HTTP request headers before forwarding the request to the backend.
// Sets the X-Forwarded-Host and X-Forwarded-For headers to preserve the original host information.
func (p *URLRewriteProxy) updateRequestHeaders(req *http.Request) {
	remoteAddr := req.RemoteAddr
	req.Header.Set(HeaderXForwardedHost, remoteAddr)
	req.Header.Set(HeaderXRealIP, remoteAddr)

	originalHost := req.Host
	req.Header.Set(HeaderXForwardedFor, originalHost)

	// if backend hostname requires SNI, we need to make sure request
	// host i set to the matching location host name
	// proxy [px.domain.com] -> sni [api1.internal.io]
	// request host header needs to match `api1.internal.io` else SNI will not work
	if p.routeSNI != "" {
		req.Host = p.routeSNI
	}

	// return if handler is not set so we know there aren't any config entries defined
	if p.headerHandler == nil {
		return
	}

	p.headerHandler.ProcessRequestHeaders(req)
}

// handleRedirect processes HTTP redirect responses from the backend server.
// Rewrites the Location header if the redirect is to the same host, ensuring consistent proxy behavior.
func (p *URLRewriteProxy) handleRedirect(resp *http.Response) error {
	location := resp.Header.Get(HeaderLocation)
	locURL, err := url.Parse(location)
	if err != nil {
		return NewProxyError("handle_redirect", fmt.Errorf("invalid redirect URL: %w", err))
	}

	// Ensure that redirects to external hosts are not rewritten.
	// This is important for external identity providers or authentication services.
	if locURL.Host != p.target.Host {
		return nil
	}

	originalHost := resp.Request.Header.Get(HeaderXForwardedHost)
	p.urlRewriter.rewriteRedirectURL(locURL, originalHost)
	resp.Header.Set(HeaderLocation, locURL.String())

	return nil
}

// modifyResponse is a callback function that modifies the HTTP response received from the backend server.
// Handle redirects and updates response headers to remove or set specific headers for security and consistency.
func (p *URLRewriteProxy) modifyResponse(resp *http.Response) error {
	if p.isPluginEnabled() {
		p.pluginManager.ProcessResponse(resp)
	}

	if isRedirect(resp.StatusCode) {
		p.handleRedirect(resp)
	}

	p.updateResponseHeaders(resp)
	return nil
}

// updateResponseHeaders modifies the HTTP response headers before sending the response to the client.
// Removes headers that might leak server information and sets custom proxy headers.
func (p *URLRewriteProxy) updateResponseHeaders(resp *http.Response) {
	resp.Header.Del(HeaderServer)
	resp.Header.Del(HeaderXPoweredBy)
	resp.Header.Set(HeaderXProxyBy, DefaultProxyLabel)

	if !p.h2 {
		// Go will automatically handle keep alive sessions in the backend
		// we are only setting it to inform downstream that the session will be reused
		resp.Header.Set("Connection", "keep-alive")
	}

	// If `Content-Type` is empty, try to determinate it by checking file extension
	// If we still can't determinate Content-Type - don't do anything. Leave it to the downsteam then
	if ct := resp.Header.Get("Content-Type"); ct == "" {
		if path := resp.Request.URL.Path; path != "" {
			resp.Header.Set("Content-Type", TypeByURLPath(path))
		}
	}

	if p.headerHandler == nil {
		return
	}

	p.headerHandler.ProcessResponseHeaders(resp)
}

// isRedirect checks if the provided HTTP status code is one that indicates a redirection.
// It returns true for known redirection status codes, otherwise false.
func isRedirect(statusCode int) bool {
	switch statusCode {
	case StatusMovedPermanently, StatusFound, StatusSeeOther,
		StatusTemporaryRedirect, StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// Logs unexpected errors and sends a generic error response to the client.
func (p *URLRewriteProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	// this is a Go reverseproxy problem since Go doesn't return any meaningful cause
	// and Go maintainers says that it is expected since client has disconnected the session
	// so as for Go 1.23 this is still an issue and we have to live with it
	// We don't want to overflow logs with this error as this can happen quite often
	// so we just ignore it for now until Go team provide a better solution
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		if proxyErr.Code == ErrCodeClientDisconnect {
			return
		}
	}

	// log every error even if error could be non-proxy
	// WriteErrorResponse will handle all non-proxy errors but it should not happen (just in case)
	p.logger.Error("Proxy error",
		zap.Error(err),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
	)

	WriteErrorResponse(w, err)
}

func (p *URLRewriteProxy) isPluginEnabled() bool {
	return p.pluginManager != nil && p.pluginManager.IsEnabled()
}
