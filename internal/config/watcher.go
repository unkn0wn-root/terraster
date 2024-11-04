package config

import (
	"log"
	"sync"

	"github.com/fsnotify/fsnotify"
)

type ConfigWatcher struct {
	watcher    *fsnotify.Watcher
	configPath string
	onChange   func(*Config)
	mu         sync.RWMutex
	done       chan struct{}
}

func NewConfigWatcher(configPath string, onChange func(*Config)) (*ConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	cw := &ConfigWatcher{
		watcher:    watcher,
		configPath: configPath,
		onChange:   onChange,
		done:       make(chan struct{}),
	}

	if err := watcher.Add(configPath); err != nil {
		watcher.Close()
		return nil, err
	}

	go cw.watch()
	return cw, nil
}

func (cw *ConfigWatcher) watch() {
	for {
		select {
		case event, ok := <-cw.watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				if config, err := Load(cw.configPath); err == nil {
					log.Printf("Reloading config")
					cw.onChange(config)
				} else {
					log.Printf("Error reloading config: %v", err)
				}
			}
		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Config watcher error: %v", err)
		case <-cw.done:
			return
		}
	}
}

func (cw *ConfigWatcher) Close() error {
	close(cw.done)
	return cw.watcher.Close()
}
