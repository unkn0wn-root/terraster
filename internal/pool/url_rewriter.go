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

// RewriteConfig holds configuration settings for URL rewriting and redirection.
// It defines how incoming request paths should be transformed before being forwarded
// to the backend services.
type RewriteConfig struct {
	ProxyPath  string // The path prefix that the proxy should handle and potentially strip from incoming requests.
	RewriteURL string // The URL to which the incoming request's path should be rewritten.
	Redirect   string // The URL to redirect the request to, if redirection is enabled.
}

// NewURLRewriter initializes and returns a new instance of URLRewriter based on the provided configuration.
// It determines whether the path prefix should be stripped and sets up the necessary rewrite and redirect rules.
//
// Parameters:
// - config: RewriteConfig defines the rules for path matching, rewriting, and redirection.
// - backendURL: *url.URL represents the target backend service's URL.
//
// Returns:
// - *URLRewriter: A configured URLRewriter instance ready to handle URL transformations.
func NewURLRewriter(config RewriteConfig, backendURL *url.URL) *URLRewriter {
	backendPath := backendURL.Path
	if backendPath == "" {
		backendPath = "/" // Default to root path if backend path is not specified.
	}

	// Clean and normalize the frontend and backend paths to ensure consistent matching.
	normalizedFrontend := path.Clean("/" + config.ProxyPath)
	normalizedBackend := path.Clean(backendPath)

	// Determine whether the path prefix should be stripped based on the normalized paths.
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
// It checks if redirection is enabled and if the request matches the criteria for redirection.
//
// Parameters:
// - req: *http.Request represents the incoming HTTP request.
//
// Returns:
// - bool: Indicates whether a redirect should occur.
// - string: The path to redirect the request to, if redirection is needed.
func (r *URLRewriter) shouldRedirect(req *http.Request) (bool, string) {
	if r.redirect == "" {
		return false, "" // Redirection is not configured.
	}
	// Redirect only if the request is to the root path.
	if r.path == "/" && req.URL.Path == "/" {
		return true, r.redirect
	}

	return false, "" // No redirection needed for other paths.
}

// rewriteRequestURL modifies the incoming HTTP request's URL to target the backend service.
// It updates the scheme and host, and conditionally strips the path prefix based on the URLRewriter's settings.
//
// Parameters:
// - req: *http.Request represents the incoming HTTP request to be rewritten.
// - targetURL: *url.URL is the backend service's URL to which the request should be forwarded.
func (r *URLRewriter) rewriteRequestURL(req *http.Request, targetURL *url.URL) {
	req.URL.Scheme = targetURL.Scheme // Update the request's scheme (e.g., http, https).
	req.URL.Host = targetURL.Host     // Update the request's host to match the backend service.

	if r.shouldStripPath {
		r.stripPathPrefix(req) // Strip the path prefix if configured to do so.
	}
}

// stripPathPrefix removes the configured path prefix from the incoming HTTP request's URL path.
// It adjusts the path based on whether a rewrite URL is specified.
//
// Parameters:
// - req: *http.Request represents the incoming HTTP request whose URL path is to be modified.
func (r *URLRewriter) stripPathPrefix(req *http.Request) {
	if !r.shouldStripPath {
		return // Path prefix stripping is not enabled.
	}

	// Remove the configured path prefix from the request's URL path.
	trimmed := strings.TrimPrefix(req.URL.Path, r.path)
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed // Ensure the path starts with a "/".
	}

	// Handle special cases where no rewriting is needed.
	if r.path == "/" && req.URL.Path == "/" && r.rewriteURL == "" {
		return
	}

	if r.rewriteURL == "" {
		req.URL.Path = trimmed // Update the request's path without rewriting.
	} else {
		ru := r.rewriteURL
		if !strings.HasPrefix(ru, "/") {
			ru = "/" + ru // Ensure the rewrite URL starts with a "/".
		}

		// Remove trailing "/" from the rewrite URL unless it's the root path.
		if len(ru) > 1 && strings.HasSuffix(ru, "/") {
			ru = strings.TrimSuffix(ru, "/")
		}
		req.URL.Path = ru + trimmed // Combine the rewrite URL with the trimmed path.
	}
}

// rewriteRedirectURL modifies the Location header in HTTP redirect responses to ensure consistency with the original host.
// It updates the host and path of the redirect URL based on the original request and the URLRewriter's configuration.
//
// Parameters:
// - locURL: *url.URL is the URL specified in the Location header of the redirect response.
// - originalHost: string is the original host from the incoming request, used to maintain consistency in redirects.
func (r *URLRewriter) rewriteRedirectURL(locURL *url.URL, originalHost string) {
	locURL.Host = originalHost // Update the redirect URL's host to match the original request's host.

	// If no rewrite URL is specified and the redirect path does not already start with the proxy path,
	// prepend the proxy path to the redirect URL's path.
	if r.rewriteURL == "" && !strings.HasPrefix(locURL.Path, r.path) && r.shouldStripPath {
		locURL.Path = r.path + locURL.Path
	}
}
