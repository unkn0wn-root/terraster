package pool

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

type URLRewriter struct {
	path            string
	rewriteURL      string
	backendPath     string
	shouldStripPath bool
	redirect        string
}

type RewriteConfig struct {
	ProxyPath  string
	RewriteURL string
	Redirect   string
}

func NewURLRewriter(config RewriteConfig, backendURL *url.URL) *URLRewriter {
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

func (r *URLRewriter) shouldRedirect(req *http.Request) (bool, string) {
	if r.redirect == "" {
		return false, ""
	}

	if r.path == "/" && req.URL.Path == "/" {
		return true, r.redirect
	}

	return false, ""
}

func (r *URLRewriter) rewriteRequestURL(req *http.Request, targetURL *url.URL) {
	req.URL.Scheme = targetURL.Scheme
	req.URL.Host = targetURL.Host
	req.Host = targetURL.Host

	if r.shouldStripPath {
		r.stripPathPrefix(req)
	}
}

func (r *URLRewriter) stripPathPrefix(req *http.Request) {
	if !r.shouldStripPath {
		return
	}

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

		// Remove trailing "/" from r.rewrite unless it's just "/"
		if len(ru) > 1 && strings.HasSuffix(ru, "/") {
			ru = strings.TrimSuffix(ru, "/")
		}
		req.URL.Path = ru + trimmed
	}
}

func (r *URLRewriter) rewriteRedirectURL(locURL *url.URL, originalHost string) {
	locURL.Host = originalHost

	if r.rewriteURL == "" && !strings.HasPrefix(locURL.Path, r.path) && r.shouldStripPath {
		locURL.Path = r.path + locURL.Path
	}
}
