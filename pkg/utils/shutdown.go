package utils

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type GracefulShutdown struct {
	timeout  time.Duration
	handlers []func(context.Context) error
	mu       sync.Mutex
}

func NewGracefulShutdown(timeout time.Duration) *GracefulShutdown {
	return &GracefulShutdown{
		timeout:  timeout,
		handlers: make([]func(context.Context) error, 0),
	}
}

func (gs *GracefulShutdown) AddHandler(handler func(context.Context) error) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.handlers = append(gs.handlers, handler)
}

func (gs *GracefulShutdown) Wait() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutdown signal received, initiating graceful shutdown...")

	ctx, cancel := context.WithTimeout(context.Background(), gs.timeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, handler := range gs.handlers {
		wg.Add(1)
		go func(h func(context.Context) error) {
			defer wg.Done()
			if err := h(ctx); err != nil {
				log.Printf("Error during shutdown: %v", err)
			}
		}(handler)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		log.Println("Shutdown timeout exceeded, forcing exit")
	case <-done:
		log.Println("Graceful shutdown completed")
	}
}
