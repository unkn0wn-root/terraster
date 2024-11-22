package crypto

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/smtp"
	"strings"
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

// cache certs in memory here
type InMemoryCertCache struct {
	mu    sync.RWMutex
	cache map[string][]byte
}

func NewInMemoryCertCache() *InMemoryCertCache {
	return &InMemoryCertCache{
		cache: make(map[string][]byte),
	}
}

// Get retrieves certificate data from the cache.
func (c *InMemoryCertCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, exists := c.cache[key]
	if !exists {
		return nil, fmt.Errorf("no cache entry for %s", key)
	}
	return data, nil
}

// Put stores certificate data in the cache.
func (c *InMemoryCertCache) Put(ctx context.Context, key string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = data
	return nil
}

// Delete removes certificate data from the cache.
func (c *InMemoryCertCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, key)
	return nil
}

// CertManager manages TLS certificates using autocert with integrated alerting.
type CertManager struct {
	manager    *autocert.Manager
	cache      CertCache
	domains    []string
	certDir    string
	certs      sync.Map // map[string]*tls.Certificate
	alerting   AlertingConfig
	alertMutex sync.RWMutex
	logger     *zap.Logger
	config     *config.Config
}

// AlertingConfig holds SMTP settings for alerting.
type AlertingConfig struct {
	Enabled   bool
	SMTPHost  string
	SMTPPort  int
	FromEmail string
	FromPass  string
	ToEmails  []string
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

// NewCertManager creates a new instance of CertManager with integrated alerting.
func NewCertManager(
	domains []string,
	certDir string,
	cache CertCache,
	alerting AlertingConfig,
	cfg *config.Config,
	logger *zap.Logger,
) *CertManager {
	cm := &CertManager{
		domains:  domains,
		certDir:  certDir,
		cache:    cache,
		alerting: alerting,
		logger:   logger,
		config:   cfg,
	}

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

func (cm *CertManager) loadLocalCertificates() {
	for _, svc := range cm.config.Services {
		if svc.TLS != nil && svc.TLS.Enabled {
			cert, err := tls.LoadX509KeyPair(svc.TLS.CertFile, svc.TLS.KeyFile)
			if err != nil {
				cm.logger.Warn("Failed to load local certificate, will use autocert",
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
	// You should own domain and configure let's encrypt to accept fetching certs
	cert, err := cm.manager.GetCertificate(hello)
	if err != nil {
		return nil, err
	}

	cm.certs.Store(hello.ServerName, cert)

	return cert, nil
}

// periodicCertCheck periodically checks for certificate expirations.
func (cm *CertManager) periodicCertCheck() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		<-ticker.C
		cm.checkCerts()
	}
}

// checkCerts checks each certificate's remaining validity and triggers alerts if necessary.
func (cm *CertManager) checkCerts() {
	now := time.Now()
	threshold := 30 * 24 * time.Hour // 30 days

	cm.certs.Range(func(key, value interface{}) bool {
		domain := key.(string)
		cert := value.(*tls.Certificate)

		// Parse the Leaf certificate if it's not already parsed
		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				// Log the error and skip alerting for this certificate
				cm.logger.Error("Failed to parse certificate", zap.String("domain", domain), zap.Error(err))
				return true
			}
			cert.Leaf = leaf
		}

		timeLeft := cert.Leaf.NotAfter.Sub(now)
		if timeLeft < threshold {
			cm.sendAlert(domain, cert.Leaf.NotAfter)
		}

		return true
	})
}

// sendAlert sends an email alert about the certificate expiration.
func (cm *CertManager) sendAlert(domain string, expiry time.Time) {
	cm.alertMutex.RLock()
	defer cm.alertMutex.RUnlock()

	if !cm.alerting.Enabled {
		return
	}

	// Prepare email content
	subject := fmt.Sprintf("Certificate Expiration Warning for %s", domain)
	body := fmt.Sprintf("The TLS certificate for %s is expiring on %s.", domain, expiry.Format(time.RFC3339))

	// Construct the email message
	msg := "From: " + cm.alerting.FromEmail + "\n" +
		"To: " + strings.Join(cm.alerting.ToEmails, ",") + "\n" +
		"Subject: " + subject + "\n\n" +
		body

	// Set up authentication information.
	// @TODO: This should handle gmail, 365 and so on.
	auth := smtp.PlainAuth("", cm.alerting.FromEmail, cm.alerting.FromPass, cm.alerting.SMTPHost)

	// Connect to the SMTP server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	addr := fmt.Sprintf("%s:%d", cm.alerting.SMTPHost, cm.alerting.SMTPPort)
	err := smtp.SendMail(addr, auth, cm.alerting.FromEmail, cm.alerting.ToEmails, []byte(msg))
	if err != nil {
		// Log the error or handle it as needed.
		cm.logger.Error("Failed to send alert email", zap.String("domain", domain), zap.Error(err))
	}
}
