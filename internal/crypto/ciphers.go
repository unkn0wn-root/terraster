package certmanager

import "crypto/tls"

// default ciphers for terraster
var TerrasterCiphers = []uint16{
	// TLS 1.3 ciphers
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_CHACHA20_POLY1305_SHA256,

	// ECDSA ciphers (TLS 1.2)
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

	// RSA ciphers (TLS 1.2)
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

	// Prevent downgrade attacks
	tls.TLS_FALLBACK_SCSV,
}
