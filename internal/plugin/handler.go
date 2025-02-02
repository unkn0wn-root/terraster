package plugin

import (
	"context"
	"net/http"
)

// Handler defines the interface that all plugins must implement
type Handler interface {
	// ProcessRequest processes the request before it's sent to the backend
	ProcessRequest(ctx context.Context, req *http.Request) *Result

	// ProcessResponse processes the response before it's sent back to the client
	ProcessResponse(ctx context.Context, resp *http.Response) *Result

	Name() string
	Priority() int
	Cleanup() error
}
