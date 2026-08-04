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

// Package ca provides the go-trusted-ca SDK adapter for go-trusted-platform.
// This package wraps the go-trusted-ca SDK client to provide unified access
// to Certificate Authority services through a clean abstraction layer.
//
// The adapter supports multiple transport modes:
//   - Embedded: In-process access without network overhead
//   - gRPC: High-performance service-to-service communication
//   - REST: HTTP/HTTPS for web clients and external systems
//   - QUIC: Low-latency UDP-based transport
//   - Unix: Unix socket for local IPC
//   - MCP: Model Context Protocol for AI/LLM integration
//
// Mode is inferred from configuration:
//   - If Backend is specified -> remote mode (connects to external CA cluster)
//   - If Backend is NOT specified -> embedded mode (in-process)
package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"sync"
	"sync/atomic"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// CertificateAuthority is an alias for the go-trusted-ca CertificateAuthority interface.
type CertificateAuthority = trustedca.CACertificateAuthority

// CertificateRequest is an alias for the go-trusted-ca CertificateRequest type.
type CertificateRequest = trustedca.CACertificateRequest

// Adapter wraps the go-trusted-ca SDK client providing unified access to
// Certificate Authority services. It supports both embedded and remote operation
// modes, determined by configuration.
//
// The adapter is thread-safe and manages the SDK client lifecycle.
type Adapter struct {
	client   trustedca.Client
	embedded CertificateAuthority
	config   *Config
	logger   *logging.Logger

	started atomic.Bool
	closed  atomic.Bool
	mu      sync.RWMutex
}

// NewAdapter creates a new CA adapter with the given configuration.
// The adapter is not started until Start() is called.
func NewAdapter(cfg *Config, logger *logging.Logger) (*Adapter, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		return nil, ErrNilLogger
	}

	return &Adapter{
		config: cfg,
		logger: logger,
	}, nil
}

// Start initializes the adapter and establishes connection to the CA.
// For embedded mode, embeddedCA must be provided.
// For remote modes, embeddedCA should be nil.
func (a *Adapter) Start(ctx context.Context, embeddedCA CertificateAuthority) error {
	if a.closed.Load() {
		return ErrAdapterClosed
	}
	if a.started.Load() {
		return nil // Already started
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Double-check after acquiring lock
	if a.started.Load() {
		return nil
	}

	if a.config.Transport == TransportEmbedded {
		if embeddedCA == nil {
			return ErrEmbeddedServiceRequired
		}
		a.embedded = embeddedCA
	} else {
		client, err := a.createClient()
		if err != nil {
			return err
		}
		a.client = client
	}

	a.started.Store(true)

	a.logger.Info("CA adapter started",
		"transport", a.config.Transport,
		"embedded", a.IsEmbedded())

	return nil
}

// Stop closes the adapter and releases resources.
func (a *Adapter) Stop(ctx context.Context) error {
	if !a.started.Load() {
		return nil
	}
	if a.closed.Load() {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.closed.Store(true)

	if a.client != nil {
		if err := a.client.Close(); err != nil {
			a.logger.Warn("error closing CA client", "error", err)
			return err
		}
	}

	a.logger.Info("CA adapter stopped")
	return nil
}

// createClient creates the SDK client based on transport mode.
func (a *Adapter) createClient() (trustedca.Client, error) {
	var opts []trustedca.Option

	// Set timeout if configured
	if a.config.RequestTimeout > 0 {
		opts = append(opts, trustedca.WithTimeout(a.config.RequestTimeout))
	}

	// Set TLS config if provided — TLS is mandatory for remote transports.
	if a.config.TLS != nil {
		opts = append(opts, trustedca.WithTLS(trustedca.TLSConfig{
			CertFile: a.config.TLS.ClientCert,
			KeyFile:  a.config.TLS.ClientKey,
			CAFile:   a.config.TLS.CACert,
		}))
	}

	switch a.config.Transport {
	case TransportUnix:
		return a.createUnixClient(opts)
	case TransportGRPC:
		return a.createGRPCClient(opts)
	case TransportREST:
		return a.createRESTClient(opts)
	case TransportQUIC:
		return a.createQUICClient(opts)
	case TransportMCP:
		return a.createMCPClient(opts)
	default:
		return nil, ErrUnsupportedTransport{Transport: a.config.Transport}
	}
}

// createUnixClient creates an SDK client for Unix socket transport.
func (a *Adapter) createUnixClient(opts []trustedca.Option) (trustedca.Client, error) {
	if a.config.UnixSocket == "" {
		return nil, ErrMissingUnixSocket
	}
	opts = append(opts, trustedca.WithUnix(a.config.UnixSocket))
	return trustedca.NewClient(a.config.UnixSocket, opts...)
}

// createGRPCClient creates an SDK client for gRPC transport.
func (a *Adapter) createGRPCClient(opts []trustedca.Option) (trustedca.Client, error) {
	if a.config.Address == "" {
		return nil, ErrMissingAddress
	}
	// gRPC is the default transport in the SDK
	return trustedca.NewClient(a.config.Address, opts...)
}

// createRESTClient creates an SDK client for REST/HTTP transport.
func (a *Adapter) createRESTClient(opts []trustedca.Option) (trustedca.Client, error) {
	if a.config.Address == "" {
		return nil, ErrMissingAddress
	}
	opts = append(opts, trustedca.WithREST())
	return trustedca.NewClient(a.config.Address, opts...)
}

// createQUICClient creates an SDK client for QUIC transport.
func (a *Adapter) createQUICClient(opts []trustedca.Option) (trustedca.Client, error) {
	if a.config.Address == "" {
		return nil, ErrMissingAddress
	}
	opts = append(opts, trustedca.WithQUIC())
	return trustedca.NewClient(a.config.Address, opts...)
}

// createMCPClient creates an SDK client for MCP transport.
func (a *Adapter) createMCPClient(opts []trustedca.Option) (trustedca.Client, error) {
	if a.config.Address == "" {
		return nil, ErrMissingAddress
	}
	opts = append(opts, trustedca.WithMCP())
	return trustedca.NewClient(a.config.Address, opts...)
}

// Client returns the underlying SDK client.
// Returns nil if the adapter is not started, closed, or in embedded mode.
func (a *Adapter) Client() trustedca.Client {
	if !a.started.Load() || a.closed.Load() {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.client
}

// Config returns the adapter configuration.
func (a *Adapter) Config() *Config {
	return a.config
}

// IsStarted returns true if the adapter has been started.
func (a *Adapter) IsStarted() bool {
	return a.started.Load()
}

// IsClosed returns true if the adapter has been closed.
func (a *Adapter) IsClosed() bool {
	return a.closed.Load()
}

// IsEmbedded returns true if using embedded (in-process) transport.
func (a *Adapter) IsEmbedded() bool {
	return a.config.Transport == TransportEmbedded
}

// IsRemote returns true if using a remote transport (Unix, gRPC, REST, QUIC, MCP).
func (a *Adapter) IsRemote() bool {
	return !a.IsEmbedded()
}

// Transport returns the transport type being used.
func (a *Adapter) Transport() Transport {
	return a.config.Transport
}

// =============================================================================
// Embedded CA Operations
// These methods delegate directly to the embedded CertificateAuthority interface
// when in embedded mode.
// =============================================================================

// CA returns the embedded CertificateAuthority interface.
// Returns nil if the adapter is not started, closed, or in remote mode.
func (a *Adapter) CA() CertificateAuthority {
	if !a.started.Load() || a.closed.Load() {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.embedded
}

// =============================================================================
// Certificate Operations
// =============================================================================

// SignCSR signs a Certificate Signing Request and returns the issued certificate.
// In embedded mode, delegates directly to the CA.
// In remote mode, uses the SDK client (via ACME workflow).
//
// Returns ErrNilRequest if the request argument is nil in embedded mode (where
// the request fields are dereferenced to build SignOptions).
func (a *Adapter) SignCSR(ctx context.Context, csrPEM []byte, request *CertificateRequest) (*x509.Certificate, error) {
	if !a.started.Load() {
		return nil, ErrAdapterNotStarted
	}
	if a.closed.Load() {
		return nil, ErrAdapterClosed
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.IsEmbedded() {
		if a.embedded == nil {
			return nil, ErrCANotInitialized
		}
		if request == nil {
			return nil, ErrNilRequest
		}
		opts := &quicbaasca.SignOptions{
			ValidityDays: request.Valid,
			KeyUsage:     request.KeyUsage,
			ExtKeyUsage:  request.ExtKeyUsage,
			Subject:      &request.Subject,
			SANS:         request.SANS,
			Signer:       request.Signer,
			IssuerCert:   request.IssuerCert,
		}
		return a.embedded.SignCSR(ctx, csrPEM, opts)
	}

	// Remote mode - CSR signing goes through ACME workflow
	// The SDK client provides ACME operations, not direct CSR signing
	return nil, newAdapterError("SignCSR", "direct CSR signing not supported in remote mode, use ACME workflow")
}

// IssueCertificate issues a certificate directly without ACME protocol.
// Only available in embedded mode.
//
// Returns ErrNilRequest if the request argument is nil in embedded mode.
func (a *Adapter) IssueCertificate(ctx context.Context, request *CertificateRequest) (*x509.Certificate, error) {
	if !a.started.Load() {
		return nil, ErrAdapterNotStarted
	}
	if a.closed.Load() {
		return nil, ErrAdapterClosed
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.IsEmbedded() {
		if a.embedded == nil {
			return nil, ErrCANotInitialized
		}
		if request == nil {
			return nil, ErrNilRequest
		}
		issued, err := a.embedded.IssueCertificate(ctx, request)
		if err != nil {
			return nil, err
		}
		if issued == nil {
			return nil, ErrNilCertificate
		}
		return issued.Certificate, nil
	}

	return nil, newAdapterError("IssueCertificate", "direct certificate issuance not supported in remote mode, use ACME workflow")
}

// Revoke revokes a certificate.
// In embedded mode, delegates directly to the CA.
// In remote mode, uses the SDK client's certificate revocation.
//
// Returns ErrNilCertificate if certificate is nil in embedded mode.
func (a *Adapter) Revoke(ctx context.Context, certificate *x509.Certificate, keyAttrs *xkmssdk.KeyAttributes) error {
	if !a.started.Load() {
		return ErrAdapterNotStarted
	}
	if a.closed.Load() {
		return ErrAdapterClosed
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.IsEmbedded() {
		if a.embedded == nil {
			return ErrCANotInitialized
		}
		if certificate == nil {
			return ErrNilCertificate
		}
		return a.embedded.RevokeCert(ctx, certificate, quicbaasca.RevokeOptions{
			DeleteKeys: keyAttrs != nil,
		})
	}

	// Remote mode - use SDK client for revocation
	// Note: SDK revocation requires different parameters, this is a simplified mapping
	return newAdapterError("Revoke", "direct revocation not supported in remote mode, use SDK Certificate().Revoke()")
}

// Verify verifies a certificate against the CA's trust chain.
// In embedded mode, delegates directly to the CA.
//
// Returns ErrNilCertificate if certificate is nil in embedded mode.
func (a *Adapter) Verify(certificate *x509.Certificate, xsigner crypto.Signer) ([][]*x509.Certificate, error) {
	if !a.started.Load() {
		return nil, ErrAdapterNotStarted
	}
	if a.closed.Load() {
		return nil, ErrAdapterClosed
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.IsEmbedded() {
		if a.embedded == nil {
			return nil, ErrCANotInitialized
		}
		if certificate == nil {
			return nil, ErrNilCertificate
		}
		return a.embedded.Verify(certificate, xsigner)
	}

	return nil, newAdapterError("Verify", "certificate verification not supported in remote mode")
}

// CABundle returns the complete CA certificate chain in PEM format.
func (a *Adapter) CABundle(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
	if !a.started.Load() {
		return nil, ErrAdapterNotStarted
	}
	if a.closed.Load() {
		return nil, ErrAdapterClosed
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.IsEmbedded() {
		if a.embedded == nil {
			return nil, ErrCANotInitialized
		}
		return a.embedded.CABundleFiltered(storeType, keyAlgorithm)
	}

	// Remote mode - fetch CA bundle from server
	// The SDK client doesn't have a direct CABundle method,
	// but this could be implemented via Directory or a custom endpoint
	return nil, newAdapterError("CABundle", "CA bundle retrieval not supported in remote mode via SDK")
}

// TrustedRoot returns the root CA certificate.
func (a *Adapter) TrustedRoot() (*x509.Certificate, error) {
	if !a.started.Load() {
		return nil, ErrAdapterNotStarted
	}
	if a.closed.Load() {
		return nil, ErrAdapterClosed
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.IsEmbedded() {
		if a.embedded == nil {
			return nil, ErrCANotInitialized
		}
		return a.embedded.TrustedRoot()
	}

	return nil, newAdapterError("TrustedRoot", "direct root certificate access not supported in remote mode")
}

// TrustedIntermediate returns the intermediate CA certificate.
func (a *Adapter) TrustedIntermediate() (*x509.Certificate, error) {
	if !a.started.Load() {
		return nil, ErrAdapterNotStarted
	}
	if a.closed.Load() {
		return nil, ErrAdapterClosed
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.IsEmbedded() {
		if a.embedded == nil {
			return nil, ErrCANotInitialized
		}
		return a.embedded.TrustedIntermediate()
	}

	return nil, newAdapterError("TrustedIntermediate", "direct intermediate certificate access not supported in remote mode")
}

// Signer returns a crypto.Signer for the CA's signing key.
// Only available in embedded mode.
func (a *Adapter) Signer(ctx context.Context) (crypto.Signer, error) {
	if !a.started.Load() {
		return nil, ErrAdapterNotStarted
	}
	if a.closed.Load() {
		return nil, ErrAdapterClosed
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.IsEmbedded() {
		if a.embedded == nil {
			return nil, ErrCANotInitialized
		}
		return a.embedded.Signer(ctx)
	}

	return nil, newAdapterError("Signer", "direct signer access not supported in remote mode")
}

// Certificate retrieves a previously issued certificate.
// The attrs argument may be nil; the embedded CA's behavior governs nil handling.
func (a *Adapter) Certificate(ctx context.Context, attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	if !a.started.Load() {
		return nil, ErrAdapterNotStarted
	}
	if a.closed.Load() {
		return nil, ErrAdapterClosed
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.IsEmbedded() {
		if a.embedded == nil {
			return nil, ErrCANotInitialized
		}
		return a.embedded.Certificate(ctx, attrs)
	}

	return nil, newAdapterError("Certificate", "direct certificate retrieval not supported in remote mode, use SDK Certificate().Get()")
}

// ImportCertificate imports a certificate into the CA's certificate store.
//
// Returns ErrNilCertificate if certificate is nil in embedded mode.
func (a *Adapter) ImportCertificate(ctx context.Context, certificate *x509.Certificate) error {
	if !a.started.Load() {
		return ErrAdapterNotStarted
	}
	if a.closed.Load() {
		return ErrAdapterClosed
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.IsEmbedded() {
		if a.embedded == nil {
			return ErrCANotInitialized
		}
		if certificate == nil {
			return ErrNilCertificate
		}
		return a.embedded.ImportCertificate(ctx, certificate)
	}

	return newAdapterError("ImportCertificate", "certificate import not supported in remote mode")
}

// =============================================================================
// ACME Client Operations (Remote Mode)
// These methods provide access to ACME protocol operations via the SDK client.
// =============================================================================

// Account returns the ACME Account client for account management.
// Only available in remote mode.
func (a *Adapter) Account() trustedca.AccountClient {
	if client := a.Client(); client != nil {
		return client.Account()
	}
	return nil
}

// Order returns the ACME Order client for certificate order lifecycle.
// Only available in remote mode.
func (a *Adapter) Order() trustedca.OrderClient {
	if client := a.Client(); client != nil {
		return client.Order()
	}
	return nil
}

// Authorization returns the ACME Authorization client for domain authorization.
// Only available in remote mode.
func (a *Adapter) Authorization() trustedca.AuthorizationClient {
	if client := a.Client(); client != nil {
		return client.Authorization()
	}
	return nil
}

// Challenge returns the ACME Challenge client for challenge verification.
// Only available in remote mode.
func (a *Adapter) Challenge() trustedca.ChallengeClient {
	if client := a.Client(); client != nil {
		return client.Challenge()
	}
	return nil
}

// CertificateClient returns the ACME Certificate client for certificate operations.
// Only available in remote mode.
func (a *Adapter) CertificateClient() trustedca.CertificateClient {
	if client := a.Client(); client != nil {
		return client.Certificate()
	}
	return nil
}

// Directory returns the ACME Directory client for directory resource.
// Only available in remote mode.
func (a *Adapter) Directory() trustedca.DirectoryClient {
	if client := a.Client(); client != nil {
		return client.Directory()
	}
	return nil
}

// Nonce returns the ACME Nonce client for replay protection.
// Only available in remote mode.
func (a *Adapter) Nonce() trustedca.NonceClient {
	if client := a.Client(); client != nil {
		return client.Nonce()
	}
	return nil
}
