package service

import (
	"fmt"
	"os"

	"github.com/unkn0wn-root/go-load-balancer/internal/config"
)

func (m *Manager) validateTLSConfig(service config.Service) error {
	// check if any location requires HTTPS
	requiresHTTPS := false
	if service.HTTPRedirect {
		requiresHTTPS = true
	}

	// validate TLS configuration
	if requiresHTTPS {
		if service.TLS == nil {
			return fmt.Errorf("service %q (host: %s) has locations requiring HTTPS but no TLS configuration provided",
				service.Name, service.Host)
		}

		if service.TLS.CertFile == "" {
			return fmt.Errorf("service %q (host: %s) missing certificate file in TLS configuration",
				service.Name, service.Host)
		}

		if service.TLS.KeyFile == "" {
			return fmt.Errorf("service %q (host: %s) missing key file in TLS configuration",
				service.Name, service.Host)
		}

		// Verify that the certificate files exist
		if _, err := os.Stat(service.TLS.CertFile); os.IsNotExist(err) {
			return fmt.Errorf("service %q (host: %s) certificate file not found: %s",
				service.Name, service.Host, service.TLS.CertFile)
		}

		if _, err := os.Stat(service.TLS.KeyFile); os.IsNotExist(err) {
			return fmt.Errorf("service %q (host: %s) key file not found: %s",
				service.Name, service.Host, service.TLS.KeyFile)
		}
	}

	return nil
}
