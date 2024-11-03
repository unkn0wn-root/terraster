package crypto

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type CertManager struct {
	manager *autocert.Manager
	cache   CertCache
	domains []string
	certDir string
	mu      sync.RWMutex
	certs   map[string]*tls.Certificate
}

type CertCache interface {
	Get(key string) ([]byte, error)
	Put(key string, data []byte) error
	Delete(key string) error
}

func NewCertManager(domains []string, certDir string, cache CertCache) *CertManager {
	cm := &CertManager{
		domains: domains,
		certDir: certDir,
		cache:   cache,
		certs:   make(map[string]*tls.Certificate),
	}

	cm.manager = &autocert.Manager{
		Cache:      cache,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: cm.hostPolicy,
	}

	go cm.periodicCertCheck()
	return cm
}

func (cm *CertManager) hostPolicy(_ context.Context, host string) error {
	for _, domain := range cm.domains {
		if host == domain {
			return nil
		}
	}
	return fmt.Errorf("host %q not configured", host)
}

func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	if cert, ok := cm.certs[hello.ServerName]; ok {
		cm.mu.RUnlock()
		return cert, nil
	}
	cm.mu.RUnlock()

	cert, err := cm.manager.GetCertificate(hello)
	if err != nil {
		return nil, err
	}

	cm.mu.Lock()
	cm.certs[hello.ServerName] = cert
	cm.mu.Unlock()

	return cert, nil
}

func (cm *CertManager) periodicCertCheck() {
	ticker := time.NewTicker(24 * time.Hour)
	for range ticker.C {
		cm.mu.Lock()
		for domain, cert := range cm.certs {
			if cert.Leaf.NotAfter.Sub(time.Now()) < 30*24*time.Hour {
				// Certificate expires in less than 30 days
				log.Printf("Certificate for %s expires soon, requesting renewal", domain)
				delete(cm.certs, domain)
			}
		}
		cm.mu.Unlock()
	}
}
