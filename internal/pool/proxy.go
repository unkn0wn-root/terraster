package pool

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	StatusMovedPermanently  = http.StatusMovedPermanently
	StatusFound             = http.StatusFound
	StatusSeeOther          = http.StatusSeeOther
	StatusTemporaryRedirect = http.StatusTemporaryRedirect
	StatusPermanentRedirect = http.StatusPermanentRedirect
)

type RouteConfig struct {
	Path       string // The route path (e.g., "/api")
	RewriteURL string // The URL to rewrite to (e.g., "/v1")
}

type URLRewriteProxy struct {
	Proxy      *httputil.ReverseProxy
	Path       string
	RewriteURL string
}

func NewReverseProxy(
	target *url.URL,
	config RouteConfig,
	proxy *httputil.ReverseProxy,
) *URLRewriteProxy {
	rewriteProxy := &URLRewriteProxy{
		Proxy:      proxy,
		Path:       config.Path,
		RewriteURL: config.RewriteURL,
	}

	proxy.Director = rewriteProxy.createDirector(target)
	proxy.ModifyResponse = rewriteProxy.modifyResponse

	return rewriteProxy
}

// createDirector creates a director function that handles path rewriting
func (urp *URLRewriteProxy) createDirector(target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		rewriteRequestURL(req, target)

		if urp.Path != "" && strings.HasPrefix(req.URL.Path, urp.Path) {
			newPath := strings.TrimPrefix(req.URL.Path, urp.Path)

			// Ensure path starts with /
			if !strings.HasPrefix(newPath, "/") {
				newPath = "/" + newPath
			}

			// Apply rewrite URL if configured
			if urp.RewriteURL != "" {
				newPath = ensurePrefix(newPath, urp.RewriteURL)
			}

			req.URL.Path = newPath
		}
	}
}

// modifyResponse handles the rewriting of response headers and redirects
func (urp *URLRewriteProxy) modifyResponse(resp *http.Response) error {
	if isRedirect(resp.StatusCode) {
		if err := urp.handleRedirect(resp); err != nil {
			log.Printf("[ERROR] Failed to handle redirect: %v", err)
		}
	}

	urp.modifyHeaders(resp)
	return nil
}

// handleRedirect processes redirect responses
func (urp *URLRewriteProxy) handleRedirect(resp *http.Response) error {
	location := resp.Header.Get("Location")
	if location == "" || urp.Path == "" {
		return nil
	}

	newLocation, err := urp.rewriteLocation(location)
	if err != nil {
		return err
	}

	if newLocation != "" && newLocation != location {
		resp.Header.Set("Location", newLocation)
	}

	return nil
}

// modifyHeaders updates response headers
func (urp *URLRewriteProxy) modifyHeaders(resp *http.Response) {
	resp.Header.Del("Server")
	resp.Header.Del("X-Powered-By")
	resp.Header.Set("X-Proxy-By", "go-load-balancer")
}

// rewriteLocation handles rewriting of the Location header
func (urp *URLRewriteProxy) rewriteLocation(location string) (string, error) {
	parsedURL, err := url.Parse(location)
	if err != nil {
		return "", err
	}

	// Remove rewrite URL if present
	if urp.RewriteURL != "" {
		parsedURL.Path = strings.TrimPrefix(parsedURL.Path, urp.RewriteURL)
		if !strings.HasPrefix(parsedURL.Path, "/") {
			parsedURL.Path = "/" + parsedURL.Path
		}
	}

	// Add original path
	if !strings.HasPrefix(parsedURL.Path, urp.Path) {
		parsedURL.Path = urp.Path + parsedURL.Path
	}

	if parsedURL.IsAbs() {
		return parsedURL.String(), nil
	}

	newPath := parsedURL.Path
	if parsedURL.RawQuery != "" {
		newPath += "?" + parsedURL.RawQuery
	}
	return newPath, nil
}

// isRedirect checks if the status code is a redirect
func isRedirect(statusCode int) bool {
	switch statusCode {
	case StatusMovedPermanently,
		StatusFound,
		StatusSeeOther,
		StatusTemporaryRedirect,
		StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func rewriteRequestURL(req *http.Request, target *url.URL) {
	targetQuery := target.RawQuery
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.URL.Path, req.URL.RawPath = joinURLPath(target, req.URL)
	if targetQuery == "" || req.URL.RawQuery == "" {
		req.URL.RawQuery = targetQuery + req.URL.RawQuery
	} else {
		req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// helper function to concatenate the target path with the request path.
func joinURLPath(a, b *url.URL) (path, rawpath string) {
	if a.RawPath == "" && b.RawPath == "" {
		return singleJoiningSlash(a.Path, b.Path), ""
	}
	// Same as singleJoiningSlash, but uses EscapedPath to determine
	// whether a slash should be added
	apath := a.EscapedPath()
	bpath := b.EscapedPath()

	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")

	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	}
	return a.Path + b.Path, apath + bpath
}

// ensurePrefix ensures that a path starts with the given prefix
func ensurePrefix(path, prefix string) string {
	path = "/" + strings.TrimLeft(path, "/")
	if prefix == "" {
		return path
	}

	prefix = "/" + strings.Trim(prefix, "/")
	if path == "/" {
		return prefix
	}

	return prefix + path
}
