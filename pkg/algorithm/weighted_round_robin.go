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

func (wrr *WeightedRoundRobin) NextServer(pool ServerPool, _ *http.Request) *Server {
	servers := pool.GetBackends()
	if len(servers) == 0 {
		return nil
	}

	totalWeight := 0
	maxWeight := -1
	var bestServer *Server

	for _, server := range servers {
		if !server.Alive {
			continue
		}

		server.CurrentWeight += server.Weight
		totalWeight += server.Weight

		if server.CurrentWeight > maxWeight {
			maxWeight = server.CurrentWeight
			bestServer = server
		}
	}

	if bestServer == nil {
		return nil
	}

	bestServer.CurrentWeight -= totalWeight
	return bestServer
}
