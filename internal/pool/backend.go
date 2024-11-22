package pool

import (
	"net/url"
	"sync/atomic"

	"github.com/unkn0wn-root/terraster/internal/config"
)

type Backend struct {
	URL             *url.URL                  // The URL of the backend server, including scheme, host, and port.
	Host            string                    // The hostname extracted from the URL, used for logging and identification.
	Alive           atomic.Bool               // Atomic flag indicating whether the backend is currently alive and reachable.
	Weight          int                       // The weight assigned to the backend for load balancing purposes.
	CurrentWeight   atomic.Int32              // The current weight used in certain load balancing algorithms (e.g., weighted round-robin).
	Proxy           *URLRewriteProxy          // The proxy instance responsible for handling HTTP requests to this backend.
	ConnectionCount int32                     // The current number of active connections to this backend.
	MaxConnections  int32                     // The maximum number of concurrent connections allowed to this backend.
	SuccessCount    int32                     // The total number of successful requests processed by this backend.
	FailureCount    int32                     // The total number of failed requests processed by this backend.
	HealthCheckCfg  *config.HealthCheckConfig // Configuration settings for health checks specific to this backend.
}

// GetURL returns the string representation of the backend's URL.
func (b *Backend) GetURL() string {
	return b.URL.String()
}

// GetWeight retrieves the current weight assigned to the backend.
// The weight influences the load balancing decision, determining the proportion of traffic this backend receives.
func (b *Backend) GetWeight() int {
	return b.Weight
}

// GetCurrentWeight fetches the current weight of the backend.
func (b *Backend) GetCurrentWeight() int {
	return int(b.CurrentWeight.Load())
}

// SetCurrentWeight sets the current weight of the backend to the specified value.
func (b *Backend) SetCurrentWeight(weight int) {
	b.CurrentWeight.Store(int32(weight))
}

// GetConnectionCount returns the current number of active connections to the backend.
func (b *Backend) GetConnectionCount() int {
	return int(atomic.LoadInt32(&b.ConnectionCount))
}

// IsAlive checks whether the backend is currently marked as alive.
// An alive backend is considered healthy and eligible to receive traffic.
func (b *Backend) IsAlive() bool {
	return b.Alive.Load()
}

// SetAlive updates the alive status of the backend.
func (b *Backend) SetAlive(alive bool) {
	b.Alive.Store(alive)
}

// IncrementConnections attempts to increment the active connection count for the backend.
// It ensures that the connection count does not exceed the maximum allowed.
// Returns true if the increment was successful, or false if the backend is at maximum capacity.
func (b *Backend) IncrementConnections() bool {
	for {
		current := atomic.LoadInt32(&b.ConnectionCount)
		if current >= int32(b.MaxConnections) {
			return false
		}

		if atomic.CompareAndSwapInt32(&b.ConnectionCount, current, current+1) {
			return true
		}
	}
}

// DecrementConnections decrements the active connection count for the backend.
// This should be called when a connection to the backend is closed or terminated.
// It ensures that the connection count accurately reflects the current load.
func (b *Backend) DecrementConnections() {
	atomic.AddInt32(&b.ConnectionCount, -1)
}
