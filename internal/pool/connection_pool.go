package pool

import (
	"net/http"
	"sync"
	"time"
)

// ConnectionPool manages a pool of HTTP clients to efficiently handle multiple HTTP requests.
// It controls the number of idle and open connections, ensuring optimal resource usage and performance.
// The pool allows reuse of HTTP clients, reducing the overhead of creating new clients for each request.
type ConnectionPool struct {
	maxIdle     int               // maxIdle defines the maximum number of idle HTTP clients that can be held in the pool.
	maxOpen     int               // maxOpen specifies the maximum number of HTTP clients that can be open at any given time.
	idleTimeout time.Duration     // idleTimeout determines how long an idle HTTP client remains in the pool before being discarded.
	mu          sync.Mutex        // mu is a mutex that guards access to the pool's internal state to ensure thread safety.
	conns       chan *http.Client // conns is a buffered channel that holds the idle HTTP clients available for reuse.
	numOpen     int               // numOpen tracks the current number of open HTTP clients managed by the pool.
}

// NewConnectionPool initializes and returns a new instance of ConnectionPool.
// It sets up the pool with specified maximum idle and open connections, and an idle timeout duration.
// The pool uses a buffered channel to manage idle HTTP clients, facilitating efficient retrieval and return of clients.
func NewConnectionPool(maxIdle, maxOpen int, idleTimeout time.Duration) *ConnectionPool {
	return &ConnectionPool{
		maxIdle:     maxIdle,
		maxOpen:     maxOpen,
		idleTimeout: idleTimeout,
		conns:       make(chan *http.Client, maxIdle),
	}
}

// Get retrieves an HTTP client from the ConnectionPool.
// If an idle client is available in the pool, it returns that client.
// If no idle clients are available and the number of open clients is below maxOpen,
// it creates a new HTTP client, increments the open client count, and returns the new client.
// If the pool has reached its maximum number of open clients, it waits until a client becomes available.
func (p *ConnectionPool) Get() *http.Client {
	select {
	case client := <-p.conns:
		return client
	default:
		p.mu.Lock()
		if p.numOpen >= p.maxOpen {
			p.mu.Unlock()
			// Pool has reached its maximum number of open clients; wait for a client to become available.
			return <-p.conns
		}

		p.numOpen++
		p.mu.Unlock()

		return p.createClient()
	}
}

// Put returns an HTTP client back to the ConnectionPool after use.
// If the pool has not reached its maximum number of idle clients, the client is placed back into the pool for reuse.
// If the pool is already full, the client is discarded, and the count of open clients is decremented accordingly.
func (p *ConnectionPool) Put(client *http.Client) {
	select {
	case p.conns <- client:
	default:
		p.mu.Lock()
		p.numOpen--
		p.mu.Unlock()
	}
}

// createClient initializes and configures a new HTTP client.
// The client is configured with a custom Transport that sets connection limits and timeouts.
// This function is called internally by the ConnectionPool when a new client needs to be created.
func (p *ConnectionPool) createClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,              // Maximum number of idle (keep-alive) connections across all hosts.
			MaxIdleConnsPerHost: 100,              // Maximum number of idle (keep-alive) connections per host.
			IdleConnTimeout:     90 * time.Second, // Time after which idle connections are closed.
		},
		Timeout: 30 * time.Second,
	}
}
