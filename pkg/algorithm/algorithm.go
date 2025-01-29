package algorithm

import (
	"net/http"
	"sync/atomic"
	"time"
)

type Algorithm interface {
	NextServer(pool ServerPool, r *http.Request, w *http.ResponseWriter) *Server
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
	CurrentWeight    atomic.Int32
	ConnectionCount  int32
	MaxConnections   int32
	Alive            atomic.Bool
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
	case "sticky-session":
		return NewSessionAffinity()
	default:
		return &RoundRobin{} // default algorithm
	}
}

func (b *Server) CanAcceptConnection() bool {
	return atomic.LoadInt32(&b.ConnectionCount) < int32(b.MaxConnections)
}
