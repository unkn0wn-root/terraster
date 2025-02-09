package cerr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"syscall"
)

// Common proxy error types
var (
	ErrBackendUnavailable = errors.New("server unavailable")
	ErrBackendTimeout     = errors.New("server timeout")
	ErrInvalidRedirect    = errors.New("invalid redirect received from server")
)

// Retry header constants define the retry mechanism configuration.
const (
	RetryAfter    = "Retry-After"
	RetryAfterSec = 5
)

// ErrorResponse represents the structure of error responses sent to clients
type ErrorResponse struct {
	Status     string `json:"status"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

// ProxyErrorCode represents specific error conditions in the proxy
type ProxyErrorCode int

const (
	ErrCodeUnknown ProxyErrorCode = iota
	ErrCodeBackendConnFailed
	ErrCodeBackendTimeout
	ErrCodeInvalidResponse
	ErrCodeTLSError
	ErrCodeClientDisconnect
)

// ProxyError represents a detailed error that occurs during proxy operations
type ProxyError struct {
	Op         string
	Code       ProxyErrorCode
	Message    string
	Err        error
	Retryable  bool
	StatusCode int
}

func (e *ProxyError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Op, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Op, e.Message)
}

func (e *ProxyError) Unwrap() error {
	return e.Err
}

// IsTemporaryError determines if an error is temporary and the request can be retried
func IsTemporaryError(err error) bool {
	// Check our custom error first
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		return proxyErr.Retryable
	}

	// Check for network operation timeouts
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Check for specific network errors
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// Check for specific syscall errors
		var syscallErr syscall.Errno
		if errors.As(opErr.Err, &syscallErr) {
			switch syscallErr {
			case
				syscall.ECONNREFUSED,
				syscall.ECONNRESET,
				syscall.ETIMEDOUT,
				syscall.EPIPE,
				syscall.ECONNABORTED,
				syscall.EHOSTDOWN,
				syscall.ENETUNREACH,
				syscall.EHOSTUNREACH:
				return true
			}
		}

		// Check for DNS temporary errors
		var dnsErr *net.DNSError
		if errors.As(opErr.Err, &dnsErr) {
			return dnsErr.IsTemporary
		}
	}

	return false
}

// NewProxyError creates a new ProxyError with appropriate defaults based on the error type
func NewProxyError(op string, err error) *ProxyError {
	pe := &ProxyError{
		Op:         op,
		Err:        err,
		Code:       ErrCodeUnknown,
		StatusCode: http.StatusBadGateway,
		Retryable:  false,
	}

	switch {
	case errors.Is(err, context.Canceled):
		pe.Code = ErrCodeClientDisconnect
		pe.Message = "Request canceled by client"
		pe.StatusCode = 499 // Client closed request
		pe.Retryable = false

	case errors.Is(err, ErrBackendUnavailable):
		pe.Code = ErrCodeBackendConnFailed
		pe.Message = "Backend server unavailable"
		pe.StatusCode = http.StatusBadGateway
		pe.Retryable = true

	case errors.Is(err, ErrBackendTimeout):
		pe.Code = ErrCodeBackendTimeout
		pe.Message = "Backend server timeout"
		pe.StatusCode = http.StatusGatewayTimeout
		pe.Retryable = true

	default:
		// Check for network errors
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			pe.Retryable = IsTemporaryError(err)

			// Handle DNS errors specifically
			var dnsErr *net.DNSError
			if errors.As(opErr.Err, &dnsErr) {
				pe.Code = ErrCodeBackendConnFailed
				pe.Message = fmt.Sprintf("DNS error: %s", dnsErr.Error())
				pe.StatusCode = http.StatusBadGateway
				pe.Retryable = dnsErr.IsTemporary
				return pe
			}

			// Handle syscall errors
			var syscallErr syscall.Errno
			if errors.As(opErr.Err, &syscallErr) {
				switch syscallErr {
				case syscall.ECONNREFUSED:
					pe.Message = "Connection refused by backend"
				case syscall.ECONNRESET:
					pe.Message = "Connection reset by backend"
				case syscall.ETIMEDOUT:
					pe.Code = ErrCodeBackendTimeout
					pe.Message = "Connection timed out"
					pe.StatusCode = http.StatusGatewayTimeout
				default:
					pe.Message = fmt.Sprintf("Network error: %s", syscallErr.Error())
				}
				pe.Code = ErrCodeBackendConnFailed
				return pe
			}
		}

		// Handle standard net.Error timeouts
		var netErr net.Error
		if errors.As(err, &netErr) {
			if netErr.Timeout() {
				pe.Code = ErrCodeBackendTimeout
				pe.Message = "Network timeout"
				pe.StatusCode = http.StatusGatewayTimeout
				pe.Retryable = true
			} else {
				pe.Code = ErrCodeBackendConnFailed
				pe.Message = "Network error"
				pe.Retryable = IsTemporaryError(err)
			}
			return pe
		}

		// Generic error handling
		pe.Message = fmt.Sprintf("Unexpected error: %v", err)
	}

	return pe
}

// WriteErrorResponse writes a structured error response to the client
func WriteErrorResponse(w http.ResponseWriter, err error) {
	var pe *ProxyError
	if !errors.As(err, &pe) {
		pe = NewProxyError("unknown", err)
	}

	response := ErrorResponse{
		Status:  "error",
		Message: pe.Message,
	}

	// tell the client to retry after some time if error is recoverable
	if pe.Retryable {
		response.RetryAfter = RetryAfterSec
		w.Header().Set(RetryAfter, strconv.Itoa(RetryAfterSec))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(pe.StatusCode)
	json.NewEncoder(w).Encode(response)
}
