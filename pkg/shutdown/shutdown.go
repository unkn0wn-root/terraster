package shutdown

import (
	"context"
	"fmt"
	"log"
	"sync"
)

type Manager struct {
	handlers []func(context.Context) error
	mu       sync.Mutex
}

func NewManager() *Manager {
	return &Manager{
		handlers: make([]func(context.Context) error, 0),
	}
}

func (sh *Manager) AddHandler(handler func(context.Context) error) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.handlers = append(sh.handlers, handler)
}

func (sh *Manager) Shutdown(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, handler := range sh.handlers {
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

func (sh *Manager) RegisterShutdown(name string, shutdown func(context.Context) error) {
	sh.AddHandler(func(ctx context.Context) error {
		if err := shutdown(ctx); err != nil {
			return fmt.Errorf("%s shutdown: %w", name, err)
		}
		return nil
	})
}
