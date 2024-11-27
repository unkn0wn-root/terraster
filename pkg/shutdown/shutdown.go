package shutdown

import (
	"context"
	"log"
	"sync"
)

type GracefulShutdown struct {
	handlers []func(context.Context) error
	mu       sync.Mutex
}

func NewGracefulShutdown() *GracefulShutdown {
	return &GracefulShutdown{
		handlers: make([]func(context.Context) error, 0),
	}
}

func (gs *GracefulShutdown) AddHandler(handler func(context.Context) error) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.handlers = append(gs.handlers, handler)
}

func (gs *GracefulShutdown) Shutdown(ctx context.Context) error {
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
		return ctx.Err()
	case <-done:
		return nil
	}
}
