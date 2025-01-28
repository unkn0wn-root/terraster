package algorithm

import (
	"net/http"
)

type WeightedRoundRobin struct {
	currentWeight int
}

func (wrr *WeightedRoundRobin) Name() string {
	return "weighted-round-robin"
}

func (wrr *WeightedRoundRobin) NextServer(pool ServerPool, _ *http.Request, w *http.ResponseWriter) *Server {
	servers := pool.GetBackends()
	if len(servers) == 0 {
		return nil
	}

	var totalWeight int32 = 0
	var maxWeight int32 = -1
	var selectedServer *Server

	// First pass: calculate total weight and find max weight server
	for _, server := range servers {
		if !server.Alive.Load() || !server.CanAcceptConnection() {
			continue
		}

		sw := int32(server.Weight)

		currentWeight := server.CurrentWeight.Load()
		newWeight := currentWeight + sw
		server.CurrentWeight.Store(newWeight)

		totalWeight += sw

		if selectedServer == nil || newWeight > maxWeight {
			selectedServer = server
			maxWeight = newWeight
		}
	}

	// If we found a server, decrease its current_weight
	if selectedServer != nil {
		newWeight := selectedServer.CurrentWeight.Load() - totalWeight
		selectedServer.CurrentWeight.Store(newWeight)
		return selectedServer
	}

	return nil
}
