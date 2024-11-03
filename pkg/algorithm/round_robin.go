package algorithm

import (
	"net/http"
	"sync/atomic"
)

type RoundRobin struct{}

func (rr *RoundRobin) Name() string {
	return "round-robin"
}

func (rr *RoundRobin) NextServer(pool ServerPool, _ *http.Request) *Server {
	servers := pool.GetBackends()
	if len(servers) == 0 {
		return nil
	}

	next := atomic.AddUint64(&pool.GetCurrentIndex(), 1)
	idx := next % uint64(len(servers))

	l := uint64(len(servers))
	for i := uint64(0); i < l; i++ {
		serverIdx := (idx + i) % l
		if servers[serverIdx].Alive {
			return servers[serverIdx]
		}
	}

	return nil
}
