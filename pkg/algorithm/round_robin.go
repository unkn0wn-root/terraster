package algorithm

import (
	"net/http"
)

type RoundRobin struct{}

func (rr *RoundRobin) Name() string {
	return "round-robin"
}

func (rr *RoundRobin) NextServer(pool ServerPool, _ *http.Request, w *http.ResponseWriter) *Server {
	servers := pool.GetBackends()
	if len(servers) == 0 {
		return nil
	}

	currentIdx := pool.GetCurrentIndex()
	next := currentIdx + 1
	pool.SetCurrentIndex(next)

	idx := next % uint64(len(servers))
	l := uint64(len(servers))

	for i := uint64(0); i < l; i++ {
		serverIdx := (idx + i) % l
		server := servers[serverIdx]
		if server.Alive.Load() && server.CanAcceptConnection() {
			return server
		}

	}

	return nil
}
