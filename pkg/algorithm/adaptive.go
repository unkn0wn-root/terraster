package algorithm

import (
	"net/http"
	"sync"
	"time"
)

type AdaptiveLoadBalancer struct {
	mu                 sync.RWMutex
	algorithms         map[string]Algorithm
	stats              map[string]*AlgorithmStats
	currentAlgo        string
	evaluationInterval time.Duration
}

type AlgorithmStats struct {
	ResponseTimes []time.Duration
	ErrorCount    int
	RequestCount  int
}

func NewAdaptiveLoadBalancer() *AdaptiveLoadBalancer {
	alb := &AdaptiveLoadBalancer{
		algorithms: map[string]Algorithm{
			"round-robin":   &RoundRobin{},
			"least-conn":    &LeastConnections{},
			"response-time": NewLeastResponseTime(),
		},
		stats:              make(map[string]*AlgorithmStats),
		currentAlgo:        "round-robin",
		evaluationInterval: time.Minute,
	}

	go alb.periodicEvaluation()
	return alb
}

func (alb *AdaptiveLoadBalancer) NextServer(pool ServerPool, r *http.Request, w *http.ResponseWriter) *Server {
	alb.mu.RLock()
	algo := alb.algorithms[alb.currentAlgo]
	alb.mu.RUnlock()

	return algo.NextServer(pool, r, w)
}

func (alb *AdaptiveLoadBalancer) RecordMetrics(algorithm string, responseTime time.Duration, isError bool) {
	alb.mu.Lock()
	defer alb.mu.Unlock()

	if _, exists := alb.stats[algorithm]; !exists {
		alb.stats[algorithm] = &AlgorithmStats{}
	}

	stats := alb.stats[algorithm]
	stats.ResponseTimes = append(stats.ResponseTimes, responseTime)
	stats.RequestCount++
	if isError {
		stats.ErrorCount++
	}
}

func (alb *AdaptiveLoadBalancer) periodicEvaluation() {
	ticker := time.NewTicker(alb.evaluationInterval)
	for range ticker.C {
		alb.evaluateAlgorithms()
	}
}

func (alb *AdaptiveLoadBalancer) evaluateAlgorithms() {
	alb.mu.Lock()
	defer alb.mu.Unlock()

	var bestAlgo string
	bestScore := 0.0

	for algo, stats := range alb.stats {
		score := alb.calculateScore(stats)
		if score > bestScore {
			bestScore = score
			bestAlgo = algo
		}
	}

	if bestAlgo != "" {
		alb.currentAlgo = bestAlgo
	}

	// Reset stats
	alb.stats = make(map[string]*AlgorithmStats)
}

func (alb *AdaptiveLoadBalancer) calculateScore(stats *AlgorithmStats) float64 {
	if stats.RequestCount == 0 {
		return 0
	}

	// Calculate average response time
	var totalTime time.Duration
	for _, rt := range stats.ResponseTimes {
		totalTime += rt
	}
	avgResponseTime := totalTime / time.Duration(len(stats.ResponseTimes))

	// Calculate error rate
	errorRate := float64(stats.ErrorCount) / float64(stats.RequestCount)

	// Score formula: higher is better
	// We want low response times and low error rates
	responseTimeScore := 1.0 / float64(avgResponseTime)
	errorScore := 1.0 - errorRate

	return responseTimeScore*0.7 + errorScore*0.3
}
