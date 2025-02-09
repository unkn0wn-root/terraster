package pool

import (
	"crypto/tls"
	"net/http"
	"time"

	pxErr "github.com/unkn0wn-root/terraster/internal/cerr"
)

const (
	// DefaultMaxIdleConnsPerHost is the maximum number of idle connections to keep per-host
	DefaultMaxIdleConnsPerHost = 32

	// DefaultIdleConnTimeout is the maximum amount of time an idle connection will remain idle before closing
	DefaultIdleConnTimeout = 30 * time.Second
)

// Transport provides a custom implementation of http.RoundTripper that wraps
// the standard http.Transport with additional configuration options for TLS,
// connection pooling, and HTTP/2 support.
type Transport struct {
	transport *http.Transport
}

// NewTransport creates and returns a new Transport instance with default configuration.
// The default configuration includes:
// - Connection pooling with DefaultMaxIdleConnsPerHost idle connections per host
// - Idle connection timeout set to DefaultIdleConnTimeout
// - Initialized TLS configuration
func NewTransport(tr *http.Transport) *Transport {
	tr.MaxIdleConnsPerHost = DefaultMaxIdleConnsPerHost
	tr.IdleConnTimeout = DefaultIdleConnTimeout

	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}

	return &Transport{
		transport: tr,
	}
}

// ConfigureTransport sets up TLS and HTTP/2 settings for the transport.
// It configures SNI (Server Name Indication), TLS verification, and HTTP/2 support.
// When h2 is false, the transport will be configured to use HTTP/1.1 exclusively
func (t *Transport) ConfigureTransport(serverName string, skipTLSVerify bool, h2 bool) {
	t.transport.TLSClientConfig.InsecureSkipVerify = skipTLSVerify
	t.transport.TLSClientConfig.ServerName = serverName

	if !h2 {
		t.transport.ForceAttemptHTTP2 = false
		t.transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
		t.transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	} else {
		// Enable HTTP/2 explicitly even if passed transporter can be DefaultTransporter which already has this enabled
		t.transport.ForceAttemptHTTP2 = true
	}
}

// RoundTrip implements the RoundTripper interface for the Transport type.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	r, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, pxErr.NewProxyError("round_trip", err)
	}

	return r, nil
}

// GetTransport returns the underlying http.Transport.
func (t *Transport) GetTransport() http.RoundTripper {
	return t.transport
}
