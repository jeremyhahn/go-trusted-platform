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

// Package quicbaaskms provides the QuicBaaS KMS SDK adapter for go-trusted-platform.
// This package wraps the go-quicbaas SDK client to provide unified access
// to key management and cryptographic operations through a clean abstraction layer.
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
//   - If Backend is specified -> remote mode (connects to external service)
//   - If Backend is NOT specified -> embedded mode (in-process)
package quicbaaskms

import (
	"context"
	"sync"
	"sync/atomic"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// QuicBaaSServicer is the interface for the embedded QuicBaaS service.
// This is used by the adapter when running in embedded mode.
type QuicBaaSServicer = service.QuicBaaS

// Adapter wraps the go-quicbaas SDK client providing unified access to
// KMS (Key Management Service) and Crypto operations.
//
// The adapter is thread-safe and manages the SDK client lifecycle.
type Adapter struct {
	client quicbaas.Client
	config *Config
	logger *logging.Logger

	started atomic.Bool
	closed  atomic.Bool
	mu      sync.RWMutex
}

// NewAdapter creates a new QuicBaaS KMS adapter with the given configuration.
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

// Start initializes the adapter and establishes connection to QuicBaaS.
// For embedded mode, embeddedService must be provided.
// For remote modes, embeddedService should be nil.
func (a *Adapter) Start(ctx context.Context, embeddedService QuicBaaSServicer) error {
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

	client, err := a.createClient(embeddedService)
	if err != nil {
		return err
	}

	a.client = client
	a.started.Store(true)

	a.logger.Info("QuicBaaS KMS adapter started",
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
			a.logger.Warn("error closing QuicBaaS KMS client", "error", err)
			return err
		}
	}

	a.logger.Info("QuicBaaS KMS adapter stopped")
	return nil
}

// createClient creates the SDK client based on transport mode.
func (a *Adapter) createClient(embeddedService QuicBaaSServicer) (quicbaas.Client, error) {
	switch a.config.Transport {
	case TransportEmbedded:
		return a.createEmbeddedClient(embeddedService)
	case TransportUnix:
		return a.createUnixClient()
	case TransportGRPC:
		return a.createGRPCClient()
	case TransportREST:
		return a.createRESTClient()
	case TransportQUIC:
		return a.createQUICClient()
	case TransportMCP:
		return a.createMCPClient()
	default:
		return nil, ErrUnsupportedTransport{Transport: a.config.Transport}
	}
}

// createEmbeddedClient creates an SDK client for embedded (in-process) mode.
func (a *Adapter) createEmbeddedClient(svc QuicBaaSServicer) (quicbaas.Client, error) {
	if svc == nil {
		return nil, ErrEmbeddedServiceRequired
	}

	opts := []quicbaas.Option{
		quicbaas.WithEmbedded(svc),
	}
	if a.config.RequestTimeout > 0 {
		opts = append(opts, quicbaas.WithTimeout(a.config.RequestTimeout))
	}

	return quicbaas.NewClient("embedded", opts...)
}

// createUnixClient creates an SDK client for Unix socket transport.
func (a *Adapter) createUnixClient() (quicbaas.Client, error) {
	if a.config.UnixSocket == "" {
		return nil, ErrMissingUnixSocket
	}

	opts := []quicbaas.Option{
		quicbaas.WithUnix(a.config.UnixSocket),
	}
	if a.config.RequestTimeout > 0 {
		opts = append(opts, quicbaas.WithTimeout(a.config.RequestTimeout))
	}
	a.appendTLSOptions(&opts)

	return quicbaas.NewClient(a.config.UnixSocket, opts...)
}

// createGRPCClient creates an SDK client for gRPC transport.
func (a *Adapter) createGRPCClient() (quicbaas.Client, error) {
	if a.config.Address == "" {
		return nil, ErrMissingAddress
	}

	opts := []quicbaas.Option{}
	if a.config.RequestTimeout > 0 {
		opts = append(opts, quicbaas.WithTimeout(a.config.RequestTimeout))
	}
	a.appendTLSOptions(&opts)
	a.appendPoolOptions(&opts)

	// gRPC is the default transport
	return quicbaas.NewClient(a.config.Address, opts...)
}

// createRESTClient creates an SDK client for REST/HTTP transport.
func (a *Adapter) createRESTClient() (quicbaas.Client, error) {
	if a.config.Address == "" {
		return nil, ErrMissingAddress
	}

	opts := []quicbaas.Option{
		quicbaas.WithREST(),
	}
	if a.config.RequestTimeout > 0 {
		opts = append(opts, quicbaas.WithTimeout(a.config.RequestTimeout))
	}
	a.appendTLSOptions(&opts)

	return quicbaas.NewClient(a.config.Address, opts...)
}

// createQUICClient creates an SDK client for QUIC transport.
func (a *Adapter) createQUICClient() (quicbaas.Client, error) {
	if a.config.Address == "" {
		return nil, ErrMissingAddress
	}

	opts := []quicbaas.Option{
		quicbaas.WithQUIC(),
	}
	if a.config.RequestTimeout > 0 {
		opts = append(opts, quicbaas.WithTimeout(a.config.RequestTimeout))
	}
	a.appendTLSOptions(&opts)

	return quicbaas.NewClient(a.config.Address, opts...)
}

// createMCPClient creates an SDK client for MCP transport.
func (a *Adapter) createMCPClient() (quicbaas.Client, error) {
	if a.config.Address == "" {
		return nil, ErrMissingAddress
	}

	opts := []quicbaas.Option{
		quicbaas.WithMCP(),
	}
	if a.config.RequestTimeout > 0 {
		opts = append(opts, quicbaas.WithTimeout(a.config.RequestTimeout))
	}
	a.appendTLSOptions(&opts)

	return quicbaas.NewClient(a.config.Address, opts...)
}

// appendTLSOptions adds TLS configuration options if TLS is configured.
// TLS is mandatory for remote transports — insecure connections are not permitted.
func (a *Adapter) appendTLSOptions(opts *[]quicbaas.Option) {
	if a.config.TLS == nil {
		return
	}

	if a.config.TLS.CACert != "" || a.config.TLS.ClientCert != "" {
		*opts = append(*opts, quicbaas.WithTLS(quicbaas.TLSConfig{
			CAFile:   a.config.TLS.CACert,
			CertFile: a.config.TLS.ClientCert,
			KeyFile:  a.config.TLS.ClientKey,
		}))
	}
}

// appendPoolOptions adds connection pool options if pooling is configured.
func (a *Adapter) appendPoolOptions(opts *[]quicbaas.Option) {
	if a.config.Pool == nil {
		return
	}

	if a.config.Pool.MinConnections > 0 && a.config.Pool.MaxConnections > 0 {
		*opts = append(*opts, quicbaas.WithConnectionPool(
			a.config.Pool.MinConnections,
			a.config.Pool.MaxConnections,
		))
	}

	if a.config.Pool.MaxIdleTime > 0 {
		*opts = append(*opts, quicbaas.WithPoolMaxAge(a.config.Pool.MaxIdleTime))
	}
}

// Client returns the underlying SDK client.
// Returns nil if the adapter is not started or closed.
func (a *Adapter) Client() quicbaas.Client {
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
// Health Operations
// =============================================================================

// Health checks the health of the QuicBaaS KMS service.
func (a *Adapter) Health(ctx context.Context) (*quicbaas.HealthResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}

	healthClient := client.Health()
	if healthClient == nil {
		return nil, ErrAdapterNotStarted
	}

	resp, err := healthClient.Readiness(ctx)
	if err != nil {
		return nil, ErrHealthCheckFailed{Cause: err}
	}

	return resp, nil
}

// Ping performs a simple connectivity check.
func (a *Adapter) Ping(ctx context.Context) error {
	client := a.Client()
	if client == nil {
		return ErrAdapterNotStarted
	}

	healthClient := client.Health()
	if healthClient == nil {
		return ErrAdapterNotStarted
	}

	if err := healthClient.Ping(ctx); err != nil {
		return ErrHealthCheckFailed{Cause: err}
	}

	return nil
}

// =============================================================================
// KMS Operations
// =============================================================================

// GenerateKey generates a new cryptographic key.
func (a *Adapter) GenerateKey(ctx context.Context, req *quicbaas.GenerateKeyRequest) (*quicbaas.GenerateKeyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}

	kmsClient := client.Security().KMS()
	if kmsClient == nil {
		return nil, ErrAdapterNotStarted
	}

	resp, err := kmsClient.GenerateKey(ctx, req)
	if err != nil {
		return nil, ErrKeyGenerationFailed{Name: req.Name, Cause: err}
	}

	return resp, nil
}

// GetKey retrieves information about a key.
func (a *Adapter) GetKey(ctx context.Context, keyID string) (*quicbaas.KeyInfo, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}

	kmsClient := client.Security().KMS()
	if kmsClient == nil {
		return nil, ErrAdapterNotStarted
	}

	keyInfo, err := kmsClient.GetKey(ctx, keyID)
	if err != nil {
		return nil, ErrKeyNotFound{KeyID: keyID}
	}

	return keyInfo, nil
}

// ListKeys lists all keys.
func (a *Adapter) ListKeys(ctx context.Context) (*quicbaas.ListKeysResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}

	kmsClient := client.Security().KMS()
	if kmsClient == nil {
		return nil, ErrAdapterNotStarted
	}

	return kmsClient.ListKeys(ctx)
}

// RotateKey rotates a key to a new version.
func (a *Adapter) RotateKey(ctx context.Context, keyID string) (*quicbaas.RotateKeyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}

	kmsClient := client.Security().KMS()
	if kmsClient == nil {
		return nil, ErrAdapterNotStarted
	}

	resp, err := kmsClient.RotateKey(ctx, keyID)
	if err != nil {
		return nil, ErrKeyRotationFailed{KeyID: keyID, Cause: err}
	}

	return resp, nil
}

// DeleteKey deletes a key.
func (a *Adapter) DeleteKey(ctx context.Context, keyID string) error {
	client := a.Client()
	if client == nil {
		return ErrAdapterNotStarted
	}

	kmsClient := client.Security().KMS()
	if kmsClient == nil {
		return ErrAdapterNotStarted
	}

	if err := kmsClient.DeleteKey(ctx, keyID); err != nil {
		return ErrKeyDeletionFailed{KeyID: keyID, Cause: err}
	}

	return nil
}

// =============================================================================
// Crypto Operations
// =============================================================================

// Sign signs data using the specified key.
func (a *Adapter) Sign(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}

	cryptoClient := client.Security().Crypto()
	if cryptoClient == nil {
		return nil, ErrAdapterNotStarted
	}

	resp, err := cryptoClient.Sign(ctx, req)
	if err != nil {
		return nil, ErrSigningFailed{KeyID: req.KeyID, Cause: err}
	}

	return resp, nil
}

// Verify verifies a signature using the specified key.
func (a *Adapter) Verify(ctx context.Context, req *quicbaas.VerifyRequest) (*quicbaas.VerifyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}

	cryptoClient := client.Security().Crypto()
	if cryptoClient == nil {
		return nil, ErrAdapterNotStarted
	}

	resp, err := cryptoClient.Verify(ctx, req)
	if err != nil {
		return nil, ErrVerificationFailed{KeyID: req.KeyID, Cause: err}
	}

	return resp, nil
}

// Encrypt encrypts plaintext using the specified key.
func (a *Adapter) Encrypt(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}

	cryptoClient := client.Security().Crypto()
	if cryptoClient == nil {
		return nil, ErrAdapterNotStarted
	}

	resp, err := cryptoClient.Encrypt(ctx, req)
	if err != nil {
		return nil, ErrEncryptionFailed{KeyID: req.KeyID, Cause: err}
	}

	return resp, nil
}

// Decrypt decrypts ciphertext using the specified key.
func (a *Adapter) Decrypt(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}

	cryptoClient := client.Security().Crypto()
	if cryptoClient == nil {
		return nil, ErrAdapterNotStarted
	}

	resp, err := cryptoClient.Decrypt(ctx, req)
	if err != nil {
		return nil, ErrDecryptionFailed{KeyID: req.KeyID, Cause: err}
	}

	return resp, nil
}

// =============================================================================
// SDK Client Accessors (for advanced usage)
// =============================================================================

// KMS returns the underlying KMS client for advanced operations.
// Returns nil if the adapter is not started or closed.
func (a *Adapter) KMS() quicbaas.KMSClient {
	client := a.Client()
	if client == nil {
		return nil
	}
	return client.Security().KMS()
}

// Crypto returns the underlying Crypto client for advanced operations.
// Returns nil if the adapter is not started or closed.
func (a *Adapter) Crypto() quicbaas.CryptoClient {
	client := a.Client()
	if client == nil {
		return nil
	}
	return client.Security().Crypto()
}

// HealthClient returns the underlying Health client for advanced operations.
// Returns nil if the adapter is not started or closed.
func (a *Adapter) HealthClient() quicbaas.HealthClient {
	client := a.Client()
	if client == nil {
		return nil
	}
	return client.Health()
}
