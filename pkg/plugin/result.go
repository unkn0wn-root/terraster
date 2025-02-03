package plugin

import (
	"encoding/json"
	"net/http"
	"sync"
)

// Result represents the outcome of plugin processing
type Result struct {
	action       Action
	StatusCode   int
	ResponseBody []byte
	Headers      http.Header
}

// Common static results
var (
	ResultContinue = &Result{action: Continue}
	ResultModify   = &Result{action: Modify}
)

// Pool for Result objects
var resultPool = sync.Pool{
	New: func() interface{} {
		return &Result{
			Headers: make(http.Header),
		}
	},
}

// NewResult creates a new result with options
func NewResult(action Action, opts ...ResultOption) *Result {
	if action == Continue && len(opts) == 0 {
		return ResultContinue
	}
	if action == Modify && len(opts) == 0 {
		return ResultModify
	}

	r := resultPool.Get().(*Result)
	r.action = action

	// Clear headers map instead of reallocating
	for k := range r.Headers {
		delete(r.Headers, k)
	}

	// Reset other fields
	r.StatusCode = 0
	r.ResponseBody = nil

	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Action returns the result action
func (r *Result) Action() Action {
	return r.action
}

// Release returns the result to the pool
func (r *Result) Release() {
	if r == ResultContinue || r == ResultModify {
		return
	}
	resultPool.Put(r)
}

// ResultOption is a function that modifies a result
type ResultOption func(*Result)

// WithStatus sets the status code
func WithStatus(code int) ResultOption {
	return func(r *Result) {
		r.StatusCode = code
	}
}

// WithHeaders adds headers
func WithHeaders(headers http.Header) ResultOption {
	return func(r *Result) {
		for k, vals := range headers {
			r.Headers[k] = vals
		}
	}
}

// WithJSONResponse sets a JSON response body
func WithJSONResponse(v interface{}) ResultOption {
	return func(r *Result) {
		if data, err := json.Marshal(v); err == nil {
			r.ResponseBody = data
			r.Headers.Set("Content-Type", "application/json")
		}
	}
}
