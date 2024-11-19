package pool

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"go.uber.org/zap"
)

// Constants representing various HTTP status codes used for redirection.
// These constants are aliases for the standard http.Status codes for clarity and ease of use.
const (
	// StatusMovedPermanently indicates that the resource has been permanently moved to a new URL.
	StatusMovedPermanently = http.StatusMovedPermanently
	// StatusFound indicates that the resource has been found at a different URI.
	StatusFound = http.StatusFound
	// StatusSeeOther indicates that the response can be found under a different URI using a GET request.
	StatusSeeOther = http.StatusSeeOther
	// StatusTemporaryRedirect indicates that the resource resides temporarily under a different URI.
	StatusTemporaryRedirect = http.StatusTemporaryRedirect
	// StatusPermanentRedirect indicates that the resource has been permanently moved to a new URI.
	StatusPermanentRedirect = http.StatusPermanentRedirect

	// Header keys used for manipulating HTTP request and response headers.
	HeaderServer         = "Server"           // The Server header identifies the server software handling the request.
	HeaderXPoweredBy     = "X-Powered-By"     // The X-Powered-By header indicates technologies supporting the server.
	HeaderXProxyBy       = "X-Proxy-By"       // The X-Proxy-By header identifies the proxy handling the request.
	HeaderLocation       = "Location"         // The Location header is used in redirection or when a new resource has been created.
	HeaderXForwardedFor  = "X-Forwarded-For"  // The X-Forwarded-For header identifies the originating IP address of a client connecting to a web server through a proxy.
	HeaderXForwardedHost = "X-Forwarded-Host" // The X-Forwarded-Host header identifies the original host requested by the client.
	HeaderHost           = "Host"             // The Host header specifies the domain name of the server and the TCP port number on which the server is listening.

	// DefaultScheme defines the default URL scheme used when none is specified.
	DefaultScheme = "http"
	// DefaultProxyLabel is a label used to identify the proxy server in response headers.
	DefaultProxyLabel = "terraster"
)

// ProxyError represents an error that occurs during proxy operations.
// It includes the operation during which the error occurred and the underlying error.
type ProxyError struct {
	Op  string // Op describes the operation being performed when the error occurred.
	Err error  // Err is the underlying error that was encountered.
}

// Error implements the error interface for ProxyError.
// It returns a formatted error message including the operation and the underlying error.
func (e *ProxyError) Error() string {
	return fmt.Sprintf("proxy error during %s: %v", e.Op, e.Err)
}

// RouteConfig holds configuration settings for routing requests through the proxy.
// It includes optional path prefixes, URL rewrites, redirection targets, and TLS verification settings.
type RouteConfig struct {
	Path          string // Path is the proxy path (upstream) used to match incoming requests (optional).
	RewriteURL    string // RewriteURL is the URL to rewrite the incoming request to (downstream) (optional).
	Redirect      string // Redirect is the URL to redirect the request to (optional).
	SkipTLSVerify bool   // SkipTLSVerify determines whether to skip TLS certificate verification for backend connections (optional).
}

// Transport wraps an http.RoundTripper to allow for custom transport configurations.
type Transport struct {
	transport http.RoundTripper // transport is the underlying RoundTripper used to execute HTTP requests.
}

// NewTransport creates a new Transport instance with the provided RoundTripper.
// It configures the TLS settings based on the skipTLSVerify parameter.
// If skipTLSVerify is true, the Transport will not verify the server's TLS certificate.
func NewTransport(transport http.RoundTripper, skipTLSVerify bool) *Transport {
	// Type assertion to *http.Transport is necessary to modify TLS settings.
	transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: skipTLSVerify}
	return &Transport{transport: transport}
}

// URLRewriteProxy is a custom reverse proxy that handles URL rewriting and redirection based on RouteConfig.
// It extends the functionality of httputil.ReverseProxy to include custom director and response modification logic.
type URLRewriteProxy struct {
	proxy       *httputil.ReverseProxy // proxy is the underlying reverse proxy handling the HTTP requests.
	target      *url.URL               // target is the destination URL to which the proxy forwards requests.
	path        string                 // path is the URL path prefix that this proxy handles.
	rewriteURL  string                 // rewriteURL specifies the URL to which incoming requests should be rewritten.
	urlRewriter *URLRewriter           // urlRewriter handles the logic for rewriting request URLs and managing redirects.
	rConfig     RewriteConfig          // rConfig holds the rewrite and redirect configurations.
	logger      *zap.Logger            // logger is used for logging proxy-related activities.
}

// ProxyOption defines a function type for applying optional configurations to URLRewriteProxy instances.
type ProxyOption func(*URLRewriteProxy)

// NewReverseProxy initializes and returns a new URLRewriteProxy instance.
// It sets up the reverse proxy with the specified target, route configurations, and applies any additional proxy options.
// The function also configures the reverse proxy's Director, ModifyResponse, Transport, ErrorHandler, and BufferPool.
func NewReverseProxy(
	target *url.URL,
	config RouteConfig,
	px *httputil.ReverseProxy,
	logger *zap.Logger,
	opts ...ProxyOption,
) *URLRewriteProxy {
	// Initialize the rewrite configuration based on the provided RouteConfig.
	rewriteConfig := RewriteConfig{
		ProxyPath:  config.Path,
		RewriteURL: config.RewriteURL,
		Redirect:   config.Redirect,
	}

	// Enhance the logger with a "PROXY" prefix for clearer log messages.
	proxyLogger := logger.With(zap.String("prefix", "PROXY"))
	prx := &URLRewriteProxy{
		target:     target,
		path:       config.Path,
		rewriteURL: config.RewriteURL,
		rConfig:    rewriteConfig,
		logger:     proxyLogger,
		proxy:      px,
	}

	// Apply any additional proxy options provided.
	for _, opt := range opts {
		opt(prx)
	}

	// Initialize the URLRewriter if it hasn't been set by the proxy options.
	if prx.urlRewriter == nil {
		prx.urlRewriter = NewURLRewriter(prx.rConfig, target)
	}

	// Log the creation of the proxy with its target and rewrite configurations.
	prx.logger.Info("Creating proxy",
		zap.String("target", target.String()),
		zap.String("path", config.Path),
		zap.String("rewriteURL", config.RewriteURL),
	)

	// Configure the reverse proxy's Director to modify incoming requests.
	reverseProxy := prx.proxy
	reverseProxy.Director = prx.director
	// Configure the reverse proxy's ModifyResponse to handle response modifications such as redirects.
	reverseProxy.ModifyResponse = prx.modifyResponse
	// Set the custom Transport with TLS verification settings.
	reverseProxy.Transport = NewTransport(http.DefaultTransport, config.SkipTLSVerify)
	// Set the custom ErrorHandler to manage proxy errors gracefully.
	reverseProxy.ErrorHandler = prx.errorHandler
	// Assign a buffer pool to optimize memory usage during request handling.
	reverseProxy.BufferPool = NewBufferPool()

	// Update the proxy's ReverseProxy instance with the configured settings.
	prx.proxy = reverseProxy

	return prx
}

// ServeHTTP handles incoming HTTP requests by determining whether to redirect or proxy the request.
// If a redirect is necessary based on the URLRewriter's logic, it performs the redirection.
// Otherwise, it forwards the request to the configured backend proxy.
func (p *URLRewriteProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Determine if the request should be redirected based on the URLRewriter's rules.
	if shouldRedirect, redirectPath := p.urlRewriter.shouldRedirect(r); shouldRedirect {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		// Construct the full redirect URL preserving the original host and the new redirect path.
		redirectURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, redirectPath)
		// Perform a permanent redirect to the new URL.
		http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
		return
	}

	// If no redirect is needed, proxy the request to the backend server.
	p.proxy.ServeHTTP(w, r)
}

// director modifies the incoming HTTP request before it is sent to the backend server.
// It updates request headers and rewrites the request URL based on the proxy's configuration.
func (p *URLRewriteProxy) director(req *http.Request) {
	p.updateRequestHeaders(req)                    // Update necessary request headers.
	p.urlRewriter.rewriteRequestURL(req, p.target) // Rewrite the request URL to target the backend server.
}

// RoundTrip implements the RoundTripper interface for the Transport type.
// It delegates the RoundTrip call to the underlying RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(req)
}

// updateRequestHeaders modifies the HTTP request headers before forwarding the request to the backend.
// It sets the X-Forwarded-Host and X-Forwarded-For headers to preserve the original host information.
func (p *URLRewriteProxy) updateRequestHeaders(req *http.Request) {
	originalHost := req.Host
	req.Header.Set(HeaderXForwardedHost, originalHost)
	req.Header.Set(HeaderXForwardedFor, originalHost)
}

// handleRedirect processes HTTP redirect responses from the backend server.
// It rewrites the Location header if the redirect is to the same host, ensuring consistent proxy behavior.
func (p *URLRewriteProxy) handleRedirect(resp *http.Response) error {
	location := resp.Header.Get(HeaderLocation) // Retrieve the Location header from the response.
	locURL, err := url.Parse(location)          // Parse the Location URL.
	if err != nil {
		return &ProxyError{Op: "parse_redirect_url", Err: err} // Return a ProxyError if parsing fails.
	}

	// Ensure that redirects to external hosts are not rewritten.
	// This is important for external identity providers or authentication services.
	if locURL.Host != p.target.Host {
		return nil
	}

	originalHost := resp.Request.Header.Get(HeaderXForwardedHost) // Retrieve the original host from request headers.
	p.urlRewriter.rewriteRedirectURL(locURL, originalHost)        // Rewrite the redirect URL based on the original host.
	resp.Header.Set(HeaderLocation, locURL.String())              // Update the Location header with the rewritten URL.
	return nil
}

// modifyResponse is a callback function that modifies the HTTP response received from the backend server.
// It handles redirects and updates response headers to remove or set specific headers for security and consistency.
func (p *URLRewriteProxy) modifyResponse(resp *http.Response) error {
	if isRedirect(resp.StatusCode) { // Check if the response status code indicates a redirect.
		p.handleRedirect(resp) // Handle the redirect by potentially rewriting the Location header.
	}

	p.updateResponseHeaders(resp) // Update response headers as needed.
	return nil
}

// updateResponseHeaders modifies the HTTP response headers before sending the response to the client.
// It removes headers that might leak server information and sets custom proxy headers.
func (p *URLRewriteProxy) updateResponseHeaders(resp *http.Response) {
	resp.Header.Del(HeaderServer)                      // Remove the Server header to prevent disclosing server details.
	resp.Header.Del(HeaderXPoweredBy)                  // Remove the X-Powered-By header to obscure underlying technologies.
	resp.Header.Set(HeaderXProxyBy, DefaultProxyLabel) // Set a custom X-Proxy-By header to identify the proxy.
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

// errorHandler is a custom error handler for the reverse proxy.
// It logs unexpected errors and sends a generic error response to the client.
func (p *URLRewriteProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	p.logger.Error("Unexpected error in proxy", zap.Error(err))           // Log the error with context.
	http.Error(w, "Something went wrong", http.StatusInternalServerError) // Send a generic error response to the client.
}
