package pool

import (
	"net/url"
	"sync/atomic"
)

type Backend struct {
	URL             *url.URL
	Host            string
	Alive           atomic.Bool
	Weight          int
	CurrentWeight   atomic.Int32
	Proxy           *URLRewriteProxy
	ConnectionCount int32
	MaxConnections  int32
}

func (b *Backend) GetURL() string {
	return b.URL.String()
}

func (b *Backend) GetWeight() int {
	return b.Weight
}

func (b *Backend) GetCurrentWeight() int {
	return int(b.CurrentWeight.Load())
}

func (b *Backend) SetCurrentWeight(weight int) {
	b.CurrentWeight.Store(int32(weight))
}

func (b *Backend) GetConnectionCount() int {
	return int(atomic.LoadInt32(&b.ConnectionCount))
}

func (b *Backend) IsAlive() bool {
	return b.Alive.Load()
}

func (b *Backend) SetAlive(alive bool) {
	b.Alive.Store(alive)
}

func (b *Backend) IncrementConnections() bool {
	for {
		current := atomic.LoadInt32(&b.ConnectionCount)
		if current >= int32(b.MaxConnections) {
			return false
		}
		if atomic.CompareAndSwapInt32(&b.ConnectionCount, current, current+1) {
			return true
		}
	}
}

func (b *Backend) DecrementConnections() {
	atomic.AddInt32(&b.ConnectionCount, -1)
}
