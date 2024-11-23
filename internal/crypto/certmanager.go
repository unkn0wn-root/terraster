package certmanager

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
	"github.com/wneessen/go-mail"
)

// Alerter defines the interface for certificate expiration alerting
type Alerter interface {
	Alert(domain string, expiry time.Time) error
}

type EmailAlerter struct {
	client    *mail.Client
	fromEmail string
	toEmails  []string
	logger    *zap.Logger
}

func NewEmailAlerter(cfg AlertingConfig, logger *zap.Logger) (*EmailAlerter, error) {
	client, err := mail.NewClient(cfg.SMTPHost,
		mail.WithPort(cfg.SMTPPort),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(cfg.FromEmail),
		mail.WithPassword(cfg.FromPass),
		mail.WithTLSPolicy(mail.TLSMandatory),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create mail client: %w", err)
	}

	return &EmailAlerter{
		client:    client,
		fromEmail: cfg.FromEmail,
		toEmails:  cfg.ToEmails,
		logger:    logger,
	}, nil
}

// NoopAlerter implements Alerter but does nothing
type NoopAlerter struct{}

func (n *NoopAlerter) Alert(domain string, expiry time.Time) error {
	return nil
}

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
	alerter          Alerter
	checkInterval    time.Duration
	expirationThresh time.Duration
	stopChan         chan struct{}
}

type AlertingConfig struct {
	Enabled   bool
	SMTPHost  string
	SMTPPort  int
	FromEmail string
	FromPass  string
	ToEmails  []string
}

func NewCertManager(
	domains []string,
	certDir string,
	cache CertCache,
	ctx context.Context,
	cfg *config.Config,
	alerting AlertingConfig,
	logger *zap.Logger,
) (*CertManager, error) {
	var alerter Alerter = &NoopAlerter{}
	if alerting.Enabled {
		emailAlerter, err := NewEmailAlerter(alerting, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create email alerter: %w", err)
		}
		alerter = emailAlerter
	}

	checkInterval := cfg.CertManager.CheckInterval
	if checkInterval == 0 {
		checkInterval = 24 * time.Hour // 24 hours
	}

	expirationThresh := cfg.CertManager.ExpirationThresh
	if expirationThresh == 0 {
		expirationThresh = 30 * 24 * time.Hour // 30 days
	}

	cm := &CertManager{
		domains:  domains,
		certDir:  certDir,
		cache:    cache,
		alerter:  alerter,
		logger:   logger,
		config:   cfg,
		stopChan: make(chan struct{}),
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
	go cm.periodicCertCheck(ctx)

	return cm, nil
}

func NewAlertingConfig(cfg *config.Config) AlertingConfig {
	return AlertingConfig{
		Enabled:   cfg.CertManager.Alerting.Enabled,
		SMTPHost:  cfg.CertManager.Alerting.SMTPHost,
		SMTPPort:  cfg.CertManager.Alerting.SMTPPort,
		FromEmail: cfg.CertManager.Alerting.FromEmail,
		FromPass:  cfg.CertManager.Alerting.FromPass,
		ToEmails:  cfg.CertManager.Alerting.ToEmails,
	}
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
func (cm *CertManager) periodicCertCheck(ctx context.Context) {
	if cm.domains == nil || len(cm.domains) == 0 {
		cm.logger.Warn("No domains configured for certificate check. Periodic check will not run.")
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
		case <-ctx.Done():
			cm.logger.Info("Context cancelled. Stopping periodic certificate check")
			return
		}
	}
}

// validateCertificate validates the given certificate.
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

// checkCerts checks the certificates for expiration and sends alerts if necessary.
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
			daysLeft := int(timeLeft.Hours() / 24)
			cm.logger.Warn("Certificate approaching expiration",
				zap.String("domain", domain),
				zap.Time("expires_at", status.expiresAt),
				zap.Int("time_left", daysLeft))

			if err := cm.alerter.Alert(domain, status.expiresAt); err != nil {
				cm.logger.Error("Failed to send alert",
					zap.String("domain", domain),
					zap.Error(err))
			}

			return true
		}

		cm.logger.Debug("Certificate valid",
			zap.String("domain", domain),
			zap.Time("expires_at", status.expiresAt),
			zap.Duration("time_left", timeLeft))

		return true
	})

	if len(checkErrors) > 0 {
		cm.logger.Error("Certificate check completed with errors",
			zap.Int("error_count", len(checkErrors)),
			zap.Errors("errors", checkErrors))
	}
}

func (e *EmailAlerter) Alert(domain string, expiry time.Time) error {
	msg := mail.NewMsg()
	if err := msg.From(e.fromEmail); err != nil {
		return fmt.Errorf("failed to set From address: %w", err)
	}

	if err := msg.To(e.toEmails...); err != nil {
		return fmt.Errorf("failed to set To address: %w", err)
	}

	msg.Subject(fmt.Sprintf("Certificate Expiration Warning - %s", domain))
	msg.SetBodyString(mail.TypeTextPlain, fmt.Sprintf(
		"The TLS certificate for %s will expire on %s.\n\nPlease renew the certificate before expiration to prevent service interruption.",
		domain,
		expiry.Format(time.RFC3339),
	))

	if err := e.client.DialAndSend(msg); err != nil {
		return fmt.Errorf("failed to send alert email: %w", err)
	}

	return nil
}

func (cm *CertManager) Stop() {
	close(cm.stopChan)
}
