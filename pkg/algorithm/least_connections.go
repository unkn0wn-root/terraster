package algorithm

import (
	"net/http"
)

type LeastConnections struct{}

func (lc *LeastConnections) Name() string {
	return "least-connections"
}

func (lc *LeastConnections) NextServer(pool ServerPool, _ *http.Request, w *http.ResponseWriter) *Server {
	servers := pool.GetBackends()
	if len(servers) == 0 {
		return nil
	}

	var selectedServer *Server
	var minConn int32 = -1

	for _, server := range servers {
		if !server.Alive.Load() || !server.CanAcceptConnection() {
			continue
		}

		if minConn == -1 || server.ConnectionCount < minConn {
			minConn = server.ConnectionCount
			selectedServer = server
		}
	}

	return selectedServer
}
