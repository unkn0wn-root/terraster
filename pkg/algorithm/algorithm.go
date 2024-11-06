package algorithm

import (
	"net/http"
	"time"
)

type Algorithm interface {
	NextServer(pool ServerPool, r *http.Request) *Server
	Name() string
}

type ServerPool interface {
	GetBackends() []*Server
	GetCurrentIndex() uint64
	SetCurrentIndex(idx uint64)
}

type Server struct {
	URL              string
	Weight           int
	CurrentWeight    int
	ConnectionCount  int32
	Alive            bool
	LastResponseTime time.Duration
}

func CreateAlgorithm(name string) Algorithm {
	switch name {
	case "round-robin":
		return &RoundRobin{}
	case "weighted-round-robin":
		return &WeightedRoundRobin{}
	case "least-connections":
		return &LeastConnections{}
	case "ip-hash":
		return &IPHash{}
	case "least-response-time":
		return NewLeastResponseTime()
	default:
		return &RoundRobin{} // default algorithm
	}
}
