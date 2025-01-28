package algorithm

import (
	"math/rand"
	"net/http"
	"sync/atomic"
)

type BoundedLeastConnections struct {
	sampleSize int
}

func NewBoundedLeastConnections(sampleSize int) *BoundedLeastConnections {
	return &BoundedLeastConnections{
		sampleSize: sampleSize,
	}
}

func (blc *BoundedLeastConnections) Name() string {
	return "bounded-least-connections"
}

func (blc *BoundedLeastConnections) NextServer(pool ServerPool, _ *http.Request, w http.ResponseWriter) *Server {
	backends := pool.GetBackends()
	if len(backends) == 0 {
		return nil
	}

	// Get sample of servers
	sampleSize := min(blc.sampleSize, len(backends))
	indices := rand.Perm(len(backends))[:sampleSize]

	var selectedServer *Server
	minConn := int32(-1)

	for _, idx := range indices {
		server := backends[idx]
		if !server.Alive.Load() {
			continue
		}

		connections := atomic.LoadInt32(&server.ConnectionCount)
		if minConn == -1 || connections < minConn {
			minConn = connections
			selectedServer = server
		}
	}

	return selectedServer
}
