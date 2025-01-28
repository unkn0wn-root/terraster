package algorithm

import (
	"net/http"
	"sync"
	"time"
)

type LeastResponseTime struct {
	mu             sync.RWMutex
	responseTimes  map[string]time.Duration
	decay          float64
	updateInterval time.Duration
}

func NewLeastResponseTime() *LeastResponseTime {
	lrt := &LeastResponseTime{
		responseTimes:  make(map[string]time.Duration),
		decay:          0.8,
		updateInterval: time.Second * 10,
	}
	go lrt.periodicCleanup()
	return lrt
}

func (lrt *LeastResponseTime) Name() string {
	return "least-response-time"
}

func (lrt *LeastResponseTime) NextServer(
	pool ServerPool,
	_ *http.Request,
	w *http.ResponseWriter,
) *Server {
	backends := pool.GetBackends()
	if len(backends) == 0 {
		return nil
	}

	var selectedServer *Server
	minTime := time.Duration(-1)

	lrt.mu.RLock()
	defer lrt.mu.RUnlock()

	for _, server := range backends {
		if !server.Alive.Load() {
			continue
		}

		responseTime, exists := lrt.responseTimes[server.URL]
		if !exists {
			return server // Prefer untested servers
		}

		// Consider both response time and current connections
		adjustedTime := responseTime * time.Duration(server.ConnectionCount+1)

		if minTime == -1 || adjustedTime < minTime {
			minTime = adjustedTime
			selectedServer = server
		}
	}

	return selectedServer
}

func (lrt *LeastResponseTime) UpdateResponseTime(serverURL string, duration time.Duration) {
	lrt.mu.Lock()
	defer lrt.mu.Unlock()

	current, exists := lrt.responseTimes[serverURL]
	if !exists {
		lrt.responseTimes[serverURL] = duration
		return
	}

	// Exponential moving average
	lrt.responseTimes[serverURL] = time.Duration(float64(current)*lrt.decay + float64(duration)*(1-lrt.decay))
}

func (lrt *LeastResponseTime) periodicCleanup() {
	ticker := time.NewTicker(lrt.updateInterval)
	for range ticker.C {
		lrt.mu.Lock()
		for server := range lrt.responseTimes {
			// Remove stale entries
			if _, exists := lrt.responseTimes[server]; !exists {
				delete(lrt.responseTimes, server)
			}
		}
		lrt.mu.Unlock()
	}
}
