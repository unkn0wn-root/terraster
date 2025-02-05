package pool

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// URLRewriter is responsible for rewriting incoming request URLs based on predefined rules.
// It handles path prefix stripping, URL rewriting, and redirects to ensure that requests
// are correctly routed to the appropriate backend services.
type URLRewriter struct {
	path            string // The URL path prefix that should be matched and potentially stripped from incoming requests.
	rewriteURL      string // The target URL to rewrite the incoming request's path to, if specified.
	backendPath     string // The base path of the backend service to which requests are being proxied.
	shouldStripPath bool   // A flag indicating whether the path prefix should be stripped from the incoming request's URL.
	redirect        string // The URL to which requests should be redirected, if redirection is configured.
}

// Rewrite holds configuration settings for URL rewriting and redirection.
// It defines how incoming request paths should be transformed before being forwarded
// to the backend services.
type Rewrite struct {
	ProxyPath  string // The path prefix that the proxy should handle and potentially strip from incoming requests.
	RewriteURL string // The URL to which the incoming request's path should be rewritten.
	Redirect   string // The URL to redirect the request to, if redirection is enabled.
}

// NewURLRewriter initializes and returns a new instance of URLRewriter based on the provided configuration.
// Determines whether the path prefix should be stripped and sets up the necessary rewrite and redirect rules.
func NewURLRewriter(config Rewrite, backendURL *url.URL) *URLRewriter {
	backendPath := backendURL.Path
	if backendPath == "" {
		backendPath = "/"
	}

	normalizedFrontend := path.Clean("/" + config.ProxyPath)
	normalizedBackend := path.Clean(backendPath)

	shouldStripPath := true
	if normalizedFrontend != "/" && normalizedBackend != "/" {
		shouldStripPath = normalizedFrontend != normalizedBackend
	}

	return &URLRewriter{
		path:            config.ProxyPath,
		rewriteURL:      config.RewriteURL,
		backendPath:     backendPath,
		shouldStripPath: shouldStripPath,
		redirect:        config.Redirect,
	}
}

// shouldRedirect determines whether the incoming HTTP request should be redirected based on the URLRewriter's configuration.
// checks if redirection is enabled and if the request matches the criteria for redirection.
func (r *URLRewriter) shouldRedirect(req *http.Request) (bool, string) {
	if r.redirect == "" {
		return false, ""
	}

	if r.path == "/" && req.URL.Path == "/" {
		return true, r.redirect
	}

	return false, ""
}

// rewriteRequestURL modifies the incoming HTTP request's URL to target the backend service.
// updates the scheme and host, and conditionally strips the path prefix based on the URLRewriter's settings.
func (r *URLRewriter) rewriteRequestURL(req *http.Request, targetURL *url.URL) {
	req.URL.Scheme = targetURL.Scheme
	req.URL.Host = targetURL.Host

	if r.shouldStripPath {
		r.stripPathPrefix(req)
	}
}

// stripPathPrefix removes the configured path prefix from the incoming HTTP request's URL path.
func (r *URLRewriter) stripPathPrefix(req *http.Request) {
	trimmed := strings.TrimPrefix(req.URL.Path, r.path)
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}

	if r.path == "/" && req.URL.Path == "/" && r.rewriteURL == "" {
		return
	}

	if r.rewriteURL == "" {
		req.URL.Path = trimmed
	} else {
		ru := r.rewriteURL
		if !strings.HasPrefix(ru, "/") {
			ru = "/" + ru
		}

		if len(ru) > 1 && strings.HasSuffix(ru, "/") {
			ru = strings.TrimSuffix(ru, "/")
		}
		req.URL.Path = ru + trimmed
	}
}

// rewriteRedirectURL modifies the Location header in HTTP redirect responses to ensure consistency with the original host.
// Updates the host and path of the redirect URL based on the original request and the URLRewriter's configuration.
func (r *URLRewriter) rewriteRedirectURL(locURL *url.URL, originalHost string) {
	locURL.Host = originalHost

	// If no rewrite URL is specified and the redirect path does not already start with the proxy path,
	// prepend the proxy path to the redirect URL's path.
	if r.rewriteURL == "" && !strings.HasPrefix(locURL.Path, r.path) && r.shouldStripPath {
		locURL.Path = r.path + locURL.Path
	}
}
