package util

import (
	"context"
	"net/http"
)

type contextKey int

const (
	RetryKey contextKey = iota
	BackendKey
)

func GetRetryFromContext(r *http.Request) int {
	if retry, ok := r.Context().Value(RetryKey).(int); ok {
		return retry
	}
	return 0
}

func SetRetryInContext(r *http.Request) *http.Request {
	retry := GetRetryFromContext(r)
	ctx := context.WithValue(r.Context(), RetryKey, retry+1)
	return r.WithContext(ctx)
}

func GetBackendFromContext(r *http.Request) string {
	if backend, ok := r.Context().Value(BackendKey).(string); ok {
		return backend
	}
	return ""
}

func SetBackendInContext(r *http.Request, backend string) *http.Request {
	ctx := context.WithValue(r.Context(), BackendKey, backend)
	return r.WithContext(ctx)
}
