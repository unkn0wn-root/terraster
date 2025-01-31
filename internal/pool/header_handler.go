package pool

import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/unkn0wn-root/terraster/internal/config"
)

// HeaderHandler manages request and response header modifications
type HeaderHandler struct {
	headerConfig config.HeaderConfig
	placeholders map[string]func(*http.Request) string
}

// NewHeaderHandler creates a new HeaderHandler
func NewHeaderHandler(cfg config.HeaderConfig) *HeaderHandler {
	return &HeaderHandler{
		headerConfig: cfg,
		placeholders: map[string]func(*http.Request) string{
			"${remote_addr}": func(r *http.Request) string { return r.RemoteAddr },
			"${host}":        func(r *http.Request) string { return r.Host },
			"${uri}":         func(r *http.Request) string { return r.RequestURI },
			"${method}":      func(r *http.Request) string { return r.Method },
		},
	}
}

// ProcessRequestHeaders modifies the request headers
func (h *HeaderHandler) ProcessRequestHeaders(req *http.Request) {
	for _, header := range h.headerConfig.RemoveRequestHeaders {
		req.Header.Del(header)
	}

	for key, value := range h.headerConfig.RequestHeaders {
		processedValue := h.processPlaceholders(value, req)
		req.Header.Set(key, processedValue)
	}
}

// ProcessResponseHeaders modifies the response headers
func (h *HeaderHandler) ProcessResponseHeaders(resp *http.Response) {
	for _, header := range h.headerConfig.RemoveResponseHeaders {
		resp.Header.Del(header)
	}

	for key, value := range h.headerConfig.ResponseHeaders {
		processedValue := h.processPlaceholders(value, resp.Request)
		resp.Header.Set(key, processedValue)
	}
}

// processPlaceholders replaces placeholder values with actual request values
func (h *HeaderHandler) processPlaceholders(value string, req *http.Request) string {
	if req == nil {
		return value
	}

	result := value
	for placeholder, getter := range h.placeholders {
		if strings.Contains(value, placeholder) {
			result = strings.ReplaceAll(result, placeholder, getter(req))
		}
	}

	return result
}

func contentType(path string) string {
	ext := filepath.Ext(path)
	// Whitelist of allowed content types
	switch ext {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".pdf":
		return "application/pdf"
	case ".doc":
		return "application/msword"
	case ".docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".xls":
		return "application/vnd.ms-excel"
	case ".xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	default:
		return "application/octet-stream" // fallback to octet-stream if we can't determinate content type
	}
}
