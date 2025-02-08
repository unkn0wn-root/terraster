package stls

import (
	"crypto/tls"
	"fmt"
	"sync"
)

// TLSManager manages TLS configurations for virtual services sharing the same port
type TLSManager struct {
	mu       sync.RWMutex
	configs  map[string]*tls.Config
	defaults *tls.Config
}

// NewTLSManager creates a new TLS configuration manager
func NewTLSManager(defaultConfig *tls.Config) *TLSManager {
	return &TLSManager{
		configs:  make(map[string]*tls.Config),
		defaults: defaultConfig,
	}
}

// AddConfig adds or updates TLS configuration for a specific host
func (tm *TLSManager) AddConfig(host string, config *tls.Config) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.configs[host] = config
}

// GetConfig retrieves TLS configuration for a given host
func (tm *TLSManager) GetConfig(host string) *tls.Config {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if config, exists := tm.configs[host]; exists {
		return config
	}
	return tm.defaults
}

// GetCertificate is a callback function for TLS config that selects the appropriate
// certificate based on the ClientHelloInfo
func (tm *TLSManager) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if clientHello == nil || clientHello.ServerName == "" {
		return nil, fmt.Errorf("no SNI information available")
	}

	config := tm.GetConfig(clientHello.ServerName)
	if config == nil || config.GetCertificate == nil {
		return nil, fmt.Errorf("no certificate provider for host: %s", clientHello.ServerName)
	}

	return config.GetCertificate(clientHello)
}
