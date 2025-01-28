package algorithm

import (
	"hash/fnv"
	"net/http"
	"strings"
)

type IPHash struct{}

func (ih *IPHash) Name() string {
	return "ip-hash"
}

func (ih *IPHash) NextServer(pool ServerPool, r *http.Request, w *http.ResponseWriter) *Server {
	servers := pool.GetBackends()
	if len(servers) == 0 {
		return nil
	}

	// Get IP from request
	ip := strings.Split(r.RemoteAddr, ":")[0]

	// Generate hash
	h := fnv.New32a()
	h.Write([]byte(ip))
	hash := h.Sum32()

	available := make([]*Server, 0)
	for _, server := range servers {
		if server.Alive.Load() {
			available = append(available, server)
		}
	}

	if len(available) == 0 {
		return nil
	}

	return available[hash%uint32(len(available))]
}
