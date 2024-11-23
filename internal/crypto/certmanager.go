package crypto

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/acme/autocert"

	"github.com/unkn0wn-root/terraster/internal/config"
)

type CertCache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, data []byte) error
	Delete(ctx context.Context, key string) error
}

type InMemoryCertCache struct {
	mu    sync.RWMutex
	cache map[string][]byte
}

func NewInMemoryCertCache() *InMemoryCertCache {
	return &InMemoryCertCache{
		cache: make(map[string][]byte),
	}
}

func (c *InMemoryCertCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, exists := c.cache[key]
	if !exists {
		return nil, fmt.Errorf("no cache entry for %s", key)
	}
	return data, nil
}

func (c *InMemoryCertCache) Put(ctx context.Context, key string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = data
	return nil
}

func (c *InMemoryCertCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, key)
	return nil
}

type certStatus struct {
	exists    bool
	isValid   bool
	expiresAt time.Time
	error     error
}

type CertManager struct {
	manager          *autocert.Manager
	cache            CertCache
	domains          []string
	certDir          string
	certs            sync.Map // map[string]*tls.Certificate
	logger           *zap.Logger
	config           *config.Config
	checkInterval    time.Duration
	expirationThresh time.Duration
	stopChan         chan struct{}
}

func NewCertManager(
	domains []string,
	certDir string,
	cache CertCache,
	cfg *config.Config,
	logger *zap.Logger,
) *CertManager {
	cm := &CertManager{
		domains:  domains,
		certDir:  certDir,
		cache:    cache,
		logger:   logger,
		config:   cfg,
		stopChan: make(chan struct{}),
	}

	checkInterval := cfg.CertManager.CheckInterval
	if checkInterval == 0 {
		checkInterval = 24 * time.Hour
	}

	expirationThresh := cfg.CertManager.ExpirationThresh
	if expirationThresh == 0 {
		expirationThresh = 30 * 24 * time.Hour // 30 days
	}

	cm.checkInterval = checkInterval
	cm.expirationThresh = expirationThresh

	cm.manager = &autocert.Manager{
		Cache:      cache,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: cm.hostPolicy,
	}

	// Load local certificates during initialization
	cm.loadLocalCertificates()

	// Start periodic certificate check
	go cm.periodicCertCheck()

	return cm
}

// hostPolicy ensures that only configured domains are allowed.
func (cm *CertManager) hostPolicy(ctx context.Context, host string) error {
	for _, domain := range cm.domains {
		if host == domain {
			return nil
		}
	}

	return fmt.Errorf("host %q not configured", host)
}

// loadLocalCertificates loads local TLS certificates and stores them in the certs map.
func (cm *CertManager) loadLocalCertificates() {
	for _, svc := range cm.config.Services {
		if svc.TLS != nil && svc.TLS.Enabled {
			cert, err := tls.LoadX509KeyPair(svc.TLS.CertFile, svc.TLS.KeyFile)
			if err != nil {
				cm.logger.Warn("Failed to load local certificate. Will use autocert",
					zap.String("host", svc.Host),
					zap.Error(err))
				continue
			}
			cm.certs.Store(svc.Host, &cert)
			cm.logger.Info("Loaded local certificate", zap.String("host", svc.Host))
		}
	}
}

// GetCertificate retrieves the TLS certificate for the given client hello.
func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Try local certificate first (if any)
	if cert, ok := cm.certs.Load(hello.ServerName); ok {
		return cert.(*tls.Certificate), nil
	}

	// If not found, fetch using autocert - slow path
	// You should own domain and configure Let's Encrypt to accept fetching certs
	cert, err := cm.manager.GetCertificate(hello)
	if err != nil {
		return nil, err
	}

	cm.certs.Store(hello.ServerName, cert)

	return cert, nil
}

// periodicCertCheck periodically checks for certificate expirations.
func (cm *CertManager) periodicCertCheck() {
	if cm.domains == nil || len(cm.domains) == 0 {
		cm.logger.Warn("No domains configured for certificate check. Stopping periodic check.")
		return
	}

	ticker := time.NewTicker(cm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cm.checkCerts()
		case <-cm.stopChan:
			cm.logger.Info("Stopping periodic certificate check")
			return
		}
	}
}

func (cm *CertManager) validateCertificate(cert *tls.Certificate) certStatus {
	if cert == nil {
		return certStatus{
			exists:  false,
			error:   fmt.Errorf("certificate is nil"),
			isValid: false,
		}
	}

	// Parse the Leaf certificate if it's not already parsed
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return certStatus{
				exists:  true,
				error:   fmt.Errorf("failed to parse certificate: %w", err),
				isValid: false,
			}
		}
		cert.Leaf = leaf
	}

	now := time.Now()
	status := certStatus{
		exists:    true,
		isValid:   now.Before(cert.Leaf.NotAfter) && now.After(cert.Leaf.NotBefore),
		expiresAt: cert.Leaf.NotAfter,
	}

	return status
}

func (cm *CertManager) checkCerts() {
	now := time.Now()
	var checkErrors []error

	cm.certs.Range(func(key, value interface{}) bool {
		domain := key.(string)
		cert := value.(*tls.Certificate)

		status := cm.validateCertificate(cert)
		if !status.exists {
			cm.logger.Warn("No certificate found for domain",
				zap.String("domain", domain),
				zap.Error(status.error))
			checkErrors = append(checkErrors, fmt.Errorf("domain %s: %w", domain, status.error))
			return true
		}

		if status.error != nil {
			cm.logger.Error("Certificate validation failed",
				zap.String("domain", domain),
				zap.Error(status.error))
			checkErrors = append(checkErrors, fmt.Errorf("domain %s: %w", domain, status.error))
			return true
		}

		if !status.isValid {
			cm.logger.Error("Invalid certificate",
				zap.String("domain", domain),
				zap.Time("expires_at", status.expiresAt))
			return true
		}

		timeLeft := status.expiresAt.Sub(now)
		if timeLeft < cm.expirationThresh {
			cm.logger.Warn("Certificate approaching expiration",
				zap.String("domain", domain),
				zap.Time("expires_at", status.expiresAt),
				zap.Duration("time_left", timeLeft))
		} else {
			cm.logger.Debug("Certificate valid",
				zap.String("domain", domain),
				zap.Time("expires_at", status.expiresAt),
				zap.Duration("time_left", timeLeft))
		}

		return true
	})

	if len(checkErrors) > 0 {
		cm.logger.Error("Certificate check completed with errors",
			zap.Int("error_count", len(checkErrors)),
			zap.Errors("errors", checkErrors))
	}
}

func (cm *CertManager) Stop() {
	close(cm.stopChan)
}
