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
