// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"sync/atomic"
	"time"
)

// MTLSProvider implements mutual TLS authentication.
// Thread-safe using atomic operations.
type MTLSProvider struct {
	// Configuration paths for file-based loading
	certFile atomic.Pointer[string]
	keyFile  atomic.Pointer[string]
	caFile   atomic.Pointer[string]

	// In-memory certificate data
	certPEM atomic.Pointer[[]byte]
	keyPEM  atomic.Pointer[[]byte]
	caPEM   atomic.Pointer[[]byte]

	// Cached TLS config
	tlsConfig atomic.Pointer[tls.Config]

	// Certificate expiration
	notAfter atomic.Int64

	// Server name for TLS verification
	serverName atomic.Pointer[string]
}

// MTLSOption configures an MTLSProvider.
type MTLSOption func(*MTLSProvider)

// WithCertFile sets the path to the client certificate file.
func WithCertFile(path string) MTLSOption {
	return func(p *MTLSProvider) {
		p.certFile.Store(&path)
	}
}

// WithKeyFile sets the path to the client private key file.
func WithKeyFile(path string) MTLSOption {
	return func(p *MTLSProvider) {
		p.keyFile.Store(&path)
	}
}

// WithCAFile sets the path to the CA certificate file for server verification.
func WithCAFile(path string) MTLSOption {
	return func(p *MTLSProvider) {
		p.caFile.Store(&path)
	}
}

// WithCertPEM sets the client certificate from PEM data.
func WithCertPEM(certPEM []byte) MTLSOption {
	return func(p *MTLSProvider) {
		p.certPEM.Store(&certPEM)
	}
}

// WithKeyPEM sets the client private key from PEM data.
func WithKeyPEM(keyPEM []byte) MTLSOption {
	return func(p *MTLSProvider) {
		p.keyPEM.Store(&keyPEM)
	}
}

// WithCAPEM sets the CA certificate from PEM data for server verification.
func WithCAPEM(caPEM []byte) MTLSOption {
	return func(p *MTLSProvider) {
		p.caPEM.Store(&caPEM)
	}
}

// WithServerName sets the server name for TLS verification.
func WithServerName(name string) MTLSOption {
	return func(p *MTLSProvider) {
		p.serverName.Store(&name)
	}
}

// NewMTLSProvider creates a new mTLS authentication provider.
// Returns an error if the certificates cannot be loaded.
func NewMTLSProvider(opts ...MTLSOption) (*MTLSProvider, error) {
	p := &MTLSProvider{}

	for _, opt := range opts {
		opt(p)
	}

	// Load certificates and build TLS config
	if err := p.loadCertificates(); err != nil {
		return nil, err
	}

	return p, nil
}

// GetToken returns ErrNoToken since mTLS doesn't use tokens.
func (p *MTLSProvider) GetToken(ctx context.Context) (string, error) {
	return "", ErrNoToken
}

// GetTLSConfig returns the TLS configuration for mTLS authentication.
func (p *MTLSProvider) GetTLSConfig() *tls.Config {
	return p.tlsConfig.Load()
}

// Refresh reloads certificates from files or memory.
// This is useful when certificates are rotated.
func (p *MTLSProvider) Refresh(ctx context.Context) error {
	return p.loadCertificates()
}

// IsExpired checks if the client certificate has expired.
func (p *MTLSProvider) IsExpired() bool {
	notAfter := p.notAfter.Load()
	if notAfter == 0 {
		return false
	}
	return time.Now().Unix() >= notAfter
}

// Type returns AuthTypeMTLS.
func (p *MTLSProvider) Type() AuthType {
	return AuthTypeMTLS
}

// NotAfter returns the certificate expiration time as Unix timestamp.
// Returns 0 if no certificate is loaded.
func (p *MTLSProvider) NotAfter() int64 {
	return p.notAfter.Load()
}

// ExpiresIn returns the duration until the certificate expires.
// Returns 0 if no certificate is loaded or the certificate is already expired.
func (p *MTLSProvider) ExpiresIn() time.Duration {
	notAfter := p.notAfter.Load()
	if notAfter == 0 {
		return 0
	}

	remaining := notAfter - time.Now().Unix()
	if remaining <= 0 {
		return 0
	}

	return time.Duration(remaining) * time.Second
}

// loadCertificates loads the certificates and builds the TLS config.
func (p *MTLSProvider) loadCertificates() error {
	// Load client certificate and key
	cert, err := p.loadClientCertificate()
	if err != nil {
		return err
	}

	// Load CA certificate pool
	caPool, err := p.loadCAPool()
	if err != nil {
		return err
	}

	// Extract expiration from the certificate
	if len(cert.Certificate) > 0 {
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			p.notAfter.Store(x509Cert.NotAfter.Unix())
		}
	}

	// Build TLS config enforcing TLS 1.3 minimum
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	// Set server name if configured
	if serverNamePtr := p.serverName.Load(); serverNamePtr != nil {
		tlsConfig.ServerName = *serverNamePtr
	}

	p.tlsConfig.Store(tlsConfig)
	return nil
}

// loadClientCertificate loads the client certificate and key.
func (p *MTLSProvider) loadClientCertificate() (tls.Certificate, error) {
	// Check in-memory credentials
	certPEMPtr := p.certPEM.Load()
	keyPEMPtr := p.keyPEM.Load()

	// Check file-based credentials
	certFilePtr := p.certFile.Load()
	keyFilePtr := p.keyFile.Load()

	hasCertPEM := certPEMPtr != nil
	hasKeyPEM := keyPEMPtr != nil
	hasCertFile := certFilePtr != nil && *certFilePtr != ""
	hasKeyFile := keyFilePtr != nil && *keyFilePtr != ""

	// Try in-memory first if both are provided
	if hasCertPEM && hasKeyPEM {
		cert, err := tls.X509KeyPair(*certPEMPtr, *keyPEMPtr)
		if err != nil {
			return tls.Certificate{}, ErrCertificateLoadFailed{Err: err}
		}
		return cert, nil
	}

	// Check for partial in-memory configuration (cert without key or vice versa)
	if hasCertPEM && !hasKeyPEM && !hasKeyFile {
		return tls.Certificate{}, ErrNoPrivateKey
	}
	if hasKeyPEM && !hasCertPEM && !hasCertFile {
		return tls.Certificate{}, ErrNoCertificate
	}

	// Try from files
	if !hasCertFile && !hasCertPEM {
		return tls.Certificate{}, ErrNoCertificate
	}

	if !hasKeyFile && !hasKeyPEM {
		return tls.Certificate{}, ErrNoPrivateKey
	}

	// Load from files
	cert, err := tls.LoadX509KeyPair(*certFilePtr, *keyFilePtr)
	if err != nil {
		return tls.Certificate{}, ErrCertificateLoadFailed{
			Path: *certFilePtr,
			Err:  err,
		}
	}

	return cert, nil
}

// loadCAPool loads the CA certificate pool for server verification.
func (p *MTLSProvider) loadCAPool() (*x509.CertPool, error) {
	// Try in-memory first
	caPEMPtr := p.caPEM.Load()
	if caPEMPtr != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(*caPEMPtr) {
			return nil, ErrCALoadFailed{Err: ErrInvalidCertificate{Reason: "failed to parse CA PEM"}}
		}
		return pool, nil
	}

	// Try from file
	caFilePtr := p.caFile.Load()
	if caFilePtr == nil || *caFilePtr == "" {
		// No CA specified, use system pool
		pool, err := x509.SystemCertPool()
		if err != nil {
			// Fall back to empty pool
			return x509.NewCertPool(), nil
		}
		return pool, nil
	}

	caPEM, err := os.ReadFile(*caFilePtr)
	if err != nil {
		return nil, ErrCALoadFailed{
			Path: *caFilePtr,
			Err:  err,
		}
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, ErrCALoadFailed{
			Path: *caFilePtr,
			Err:  ErrInvalidCertificate{Reason: "failed to parse CA PEM"},
		}
	}

	return pool, nil
}

// Ensure MTLSProvider implements Provider interface.
var _ Provider = (*MTLSProvider)(nil)
