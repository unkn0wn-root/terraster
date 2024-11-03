package pool

import (
	"net/http"
	"sync"
	"time"
)

type ConnectionPool struct {
	maxIdle     int
	maxOpen     int
	idleTimeout time.Duration
	mu          sync.Mutex
	conns       chan *http.Client
	numOpen     int
}

func NewConnectionPool(maxIdle, maxOpen int, idleTimeout time.Duration) *ConnectionPool {
	return &ConnectionPool{
		maxIdle:     maxIdle,
		maxOpen:     maxOpen,
		idleTimeout: idleTimeout,
		conns:       make(chan *http.Client, maxIdle),
	}
}

func (p *ConnectionPool) Get() *http.Client {
	select {
	case client := <-p.conns:
		return client
	default:
		p.mu.Lock()
		if p.numOpen >= p.maxOpen {
			p.mu.Unlock()
			// Wait for an available connection
			return <-p.conns
		}
		p.numOpen++
		p.mu.Unlock()
		return p.createClient()
	}
}

func (p *ConnectionPool) Put(client *http.Client) {
	select {
	case p.conns <- client:
		// Connection returned to pool
	default:
		// Pool is full, close the connection
		p.mu.Lock()
		p.numOpen--
		p.mu.Unlock()
	}
}

func (p *ConnectionPool) createClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
}
