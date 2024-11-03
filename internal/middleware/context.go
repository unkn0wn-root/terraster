package middleware

type contextKey int

const (
	BackendKey contextKey = iota
	RetryKey
)
