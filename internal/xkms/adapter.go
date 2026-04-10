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

// Package xkms provides the XKMS SDK adapter for go-trusted-platform.
// This package wraps the go-xkms SDK client to provide unified access
// to all XKMS operations through a clean abstraction layer.
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
package xkms

import (
	"context"
	"crypto/tls"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// XKMSServicer is the interface for the embedded XKMS service.
// This is used by the adapter when running in embedded mode.
type XKMSServicer = xkms.XKMSServicer

// Adapter wraps the go-xkms SDK client providing unified access to all
// XKMS operations including key management, cryptographic operations,
// certificate management, and TPM/Software/PKCS#11 backend operations.
//
// The adapter is thread-safe and manages the SDK client lifecycle.
type Adapter struct {
	client xkms.Client
	config *Config
	logger *logging.Logger

	started atomic.Bool
	closed  atomic.Bool
	mu      sync.RWMutex
}

// NewAdapter creates a new XKMS adapter with the given configuration.
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

// Start initializes the adapter and establishes connection to XKMS.
// For embedded mode, embeddedService must be provided.
// For remote modes, embeddedService should be nil.
func (a *Adapter) Start(ctx context.Context, embeddedService XKMSServicer) error {
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

	// Connect to the service (for remote transports)
	if a.config.Transport != TransportEmbedded {
		if err := client.Connect(ctx); err != nil {
			return ErrConnectionFailed{
				Address:   a.config.Address,
				Transport: a.config.Transport,
				Cause:     err,
			}
		}
	}

	a.client = client
	a.started.Store(true)

	a.logger.Info("XKMS adapter started",
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
			a.logger.Warn("error closing XKMS client", "error", err)
			return err
		}
	}

	a.logger.Info("XKMS adapter stopped")
	return nil
}

// createClient creates the SDK client based on transport mode.
func (a *Adapter) createClient(embeddedService XKMSServicer) (xkms.Client, error) {
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
func (a *Adapter) createEmbeddedClient(svc XKMSServicer) (xkms.Client, error) {
	if svc == nil {
		return nil, ErrEmbeddedServiceRequired
	}

	return xkms.NewEmbedded(svc)
}

// applyTLSConfig applies the platform TLS configuration to the SDK backend config.
func (a *Adapter) applyTLSConfig(cfg *xkms.BackendConfig) {
	if a.config.TLS == nil {
		return
	}
	cfg.TLSEnabled = true
	cfg.TLSCAFile = a.config.TLS.CACert
	cfg.TLSCertFile = a.config.TLS.ClientCert
	cfg.TLSKeyFile = a.config.TLS.ClientKey
	cfg.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}

// createUnixClient creates an SDK client for Unix socket transport.
func (a *Adapter) createUnixClient() (xkms.Client, error) {
	if a.config.UnixSocket == "" {
		return nil, ErrMissingUnixSocket
	}

	cfg := &xkms.BackendConfig{
		Protocol: xkms.ProtocolUnix,
		Address:  a.config.UnixSocket,
	}

	a.applyTLSConfig(cfg)

	return xkms.New(cfg)
}

// createGRPCClient creates an SDK client for gRPC transport.
func (a *Adapter) createGRPCClient() (xkms.Client, error) {
	if a.config.Address == "" {
		return nil, ErrMissingAddress
	}

	cfg := &xkms.BackendConfig{
		Protocol: xkms.ProtocolGRPC,
		Address:  a.config.Address,
	}

	a.applyTLSConfig(cfg)

	return xkms.New(cfg)
}

// createRESTClient creates an SDK client for REST/HTTP transport.
func (a *Adapter) createRESTClient() (xkms.Client, error) {
	if a.config.Address == "" {
		return nil, ErrMissingAddress
	}

	cfg := &xkms.BackendConfig{
		Protocol: xkms.ProtocolREST,
		Address:  a.config.Address,
	}

	a.applyTLSConfig(cfg)

	return xkms.New(cfg)
}

// createQUICClient creates an SDK client for QUIC transport.
func (a *Adapter) createQUICClient() (xkms.Client, error) {
	if a.config.Address == "" {
		return nil, ErrMissingAddress
	}

	cfg := &xkms.BackendConfig{
		Protocol:   xkms.ProtocolQUIC,
		Address:    a.config.Address,
		TLSEnabled: true, // QUIC always uses TLS
	}

	if a.config.TLS != nil {
		cfg.TLSCAFile = a.config.TLS.CACert
		cfg.TLSCertFile = a.config.TLS.ClientCert
		cfg.TLSKeyFile = a.config.TLS.ClientKey
		cfg.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	return xkms.New(cfg)
}

// createMCPClient creates an SDK client for MCP transport.
func (a *Adapter) createMCPClient() (xkms.Client, error) {
	if a.config.Address == "" {
		return nil, ErrMissingAddress
	}

	cfg := &xkms.BackendConfig{
		Protocol: xkms.ProtocolMCP,
		Address:  a.config.Address,
	}

	a.applyTLSConfig(cfg)

	return xkms.New(cfg)
}

// Client returns the underlying SDK client.
// Returns nil if the adapter is not started or closed.
func (a *Adapter) Client() xkms.Client {
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

// Health checks the health of the XKMS service.
func (a *Adapter) Health(ctx context.Context) (*xkms.HealthResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.Health(ctx)
}

// =============================================================================
// Backend Operations
// =============================================================================

// ListBackends returns a list of available key storage backends.
func (a *Adapter) ListBackends(ctx context.Context) (*xkms.ListBackendsResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.ListBackends(ctx)
}

// GetBackend returns information about a specific backend.
func (a *Adapter) GetBackend(ctx context.Context, backendID string) (*xkms.BackendInfo, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.GetBackend(ctx, backendID)
}

// =============================================================================
// Key Operations
// =============================================================================

// GenerateKey generates a new key in the specified backend.
func (a *Adapter) GenerateKey(ctx context.Context, req *xkms.GenerateKeyRequest) (*xkms.GenerateKeyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.GenerateKey(ctx, req)
}

// ListKeys returns a list of keys in the specified backend.
func (a *Adapter) ListKeys(ctx context.Context, backend string) (*xkms.ListKeysResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.ListKeys(ctx, backend)
}

// GetKey returns information about a specific key.
func (a *Adapter) GetKey(ctx context.Context, backend, keyID string) (*xkms.GetKeyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.GetKey(ctx, backend, keyID)
}

// DeleteKey deletes a key from the specified backend.
func (a *Adapter) DeleteKey(ctx context.Context, backend, keyID string) (*xkms.DeleteKeyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.DeleteKey(ctx, backend, keyID)
}

// =============================================================================
// Cryptographic Operations
// =============================================================================

// Sign signs data with the specified key.
func (a *Adapter) Sign(ctx context.Context, req *xkms.SignRequest) (*xkms.SignResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.Sign(ctx, req)
}

// Verify verifies a signature.
func (a *Adapter) Verify(ctx context.Context, req *xkms.VerifyRequest) (*xkms.VerifyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.Verify(ctx, req)
}

// Encrypt encrypts data with the specified key (symmetric encryption).
func (a *Adapter) Encrypt(ctx context.Context, req *xkms.EncryptRequest) (*xkms.EncryptResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.Encrypt(ctx, req)
}

// Decrypt decrypts data with the specified key (symmetric decryption).
func (a *Adapter) Decrypt(ctx context.Context, req *xkms.DecryptRequest) (*xkms.DecryptResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.Decrypt(ctx, req)
}

// EncryptAsym encrypts data with RSA public key (asymmetric encryption).
func (a *Adapter) EncryptAsym(ctx context.Context, req *xkms.EncryptAsymRequest) (*xkms.EncryptAsymResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.EncryptAsym(ctx, req)
}

// =============================================================================
// Certificate Operations
// =============================================================================

// GetCertificate returns the certificate for a key.
func (a *Adapter) GetCertificate(ctx context.Context, backend, keyID string) (*xkms.GetCertificateResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.GetCertificate(ctx, backend, keyID)
}

// SaveCertificate saves a certificate for a key.
func (a *Adapter) SaveCertificate(ctx context.Context, req *xkms.SaveCertificateRequest) error {
	client := a.Client()
	if client == nil {
		return ErrAdapterNotStarted
	}
	return client.SaveCertificate(ctx, req)
}

// DeleteCertificate deletes a certificate.
func (a *Adapter) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	client := a.Client()
	if client == nil {
		return ErrAdapterNotStarted
	}
	return client.DeleteCertificate(ctx, backend, keyID)
}

// CertificateExists checks if a certificate exists for a key.
func (a *Adapter) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	client := a.Client()
	if client == nil {
		return false, ErrAdapterNotStarted
	}
	return client.CertificateExists(ctx, backend, keyID)
}

// ListCertificates lists all certificates in the specified backend.
func (a *Adapter) ListCertificates(ctx context.Context, backend string) (*xkms.ListCertificatesResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.ListCertificates(ctx, backend)
}

// SaveCertificateChain saves a certificate chain for a key.
func (a *Adapter) SaveCertificateChain(ctx context.Context, req *xkms.SaveCertificateChainRequest) error {
	client := a.Client()
	if client == nil {
		return ErrAdapterNotStarted
	}
	return client.SaveCertificateChain(ctx, req)
}

// GetCertificateChain returns the certificate chain for a key.
func (a *Adapter) GetCertificateChain(ctx context.Context, backend, keyID string) (*xkms.GetCertificateChainResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.GetCertificateChain(ctx, backend, keyID)
}

// GetTLSCertificate returns the TLS certificate bundle for a key.
func (a *Adapter) GetTLSCertificate(ctx context.Context, backend, keyID string) (*xkms.GetTLSCertificateResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.GetTLSCertificate(ctx, backend, keyID)
}

// =============================================================================
// Import/Export Operations
// =============================================================================

// ImportKey imports a key into the specified backend.
func (a *Adapter) ImportKey(ctx context.Context, req *xkms.ImportKeyRequest) (*xkms.ImportKeyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.ImportKey(ctx, req)
}

// ExportKey exports a key from the specified backend.
func (a *Adapter) ExportKey(ctx context.Context, req *xkms.ExportKeyRequest) (*xkms.ExportKeyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.ExportKey(ctx, req)
}

// RotateKey rotates a key by generating a new version.
func (a *Adapter) RotateKey(ctx context.Context, req *xkms.RotateKeyRequest) (*xkms.RotateKeyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.RotateKey(ctx, req)
}

// GetImportParameters gets the parameters needed to import a key.
func (a *Adapter) GetImportParameters(ctx context.Context, req *xkms.GetImportParametersRequest) (*xkms.GetImportParametersResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.GetImportParameters(ctx, req)
}

// WrapKey wraps key material for secure transport.
func (a *Adapter) WrapKey(ctx context.Context, req *xkms.WrapKeyRequest) (*xkms.WrapKeyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.WrapKey(ctx, req)
}

// UnwrapKey unwraps key material.
func (a *Adapter) UnwrapKey(ctx context.Context, req *xkms.UnwrapKeyRequest) (*xkms.UnwrapKeyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.UnwrapKey(ctx, req)
}

// CopyKey copies a key from one backend to another.
func (a *Adapter) CopyKey(ctx context.Context, req *xkms.CopyKeyRequest) (*xkms.CopyKeyResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.CopyKey(ctx, req)
}

// =============================================================================
// Sealing Operations (TPM2/Hardware-backed encryption)
// =============================================================================

// Seal seals data using the backend's sealing mechanism (e.g., TPM2).
func (a *Adapter) Seal(ctx context.Context, req *xkms.SealRequest) (*xkms.SealResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.Seal(ctx, req)
}

// Unseal unseals previously sealed data.
func (a *Adapter) Unseal(ctx context.Context, req *xkms.UnsealRequest) (*xkms.UnsealResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.Unseal(ctx, req)
}

// CanSeal checks if the backend supports sealing operations.
func (a *Adapter) CanSeal(ctx context.Context, backend string) (*xkms.CanSealResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.CanSeal(ctx, backend)
}

// =============================================================================
// User Management Operations
// =============================================================================

// ListUsers returns a list of all users.
func (a *Adapter) ListUsers(ctx context.Context) (*xkms.ListUsersResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.ListUsers(ctx)
}

// GetUser returns information about a specific user.
func (a *Adapter) GetUser(ctx context.Context, username string) (*xkms.GetUserResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.GetUser(ctx, username)
}

// DeleteUser deletes a user.
func (a *Adapter) DeleteUser(ctx context.Context, username string) error {
	client := a.Client()
	if client == nil {
		return ErrAdapterNotStarted
	}
	return client.DeleteUser(ctx, username)
}

// EnableUser enables a user account.
func (a *Adapter) EnableUser(ctx context.Context, username string) error {
	client := a.Client()
	if client == nil {
		return ErrAdapterNotStarted
	}
	return client.EnableUser(ctx, username)
}

// DisableUser disables a user account.
func (a *Adapter) DisableUser(ctx context.Context, username string) error {
	client := a.Client()
	if client == nil {
		return ErrAdapterNotStarted
	}
	return client.DisableUser(ctx, username)
}

// ListUserCredentials returns a list of credentials for a user.
func (a *Adapter) ListUserCredentials(ctx context.Context, username string) (*xkms.ListUserCredentialsResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.ListUserCredentials(ctx, username)
}

// =============================================================================
// Authentication Flow Operations (FIDO2/WebAuthn)
// =============================================================================

// BeginRegistration begins a WebAuthn registration flow.
func (a *Adapter) BeginRegistration(ctx context.Context, req *xkms.BeginRegistrationRequest) (*xkms.BeginRegistrationResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.BeginRegistration(ctx, req)
}

// FinishRegistration completes a WebAuthn registration flow.
func (a *Adapter) FinishRegistration(ctx context.Context, req *xkms.FinishRegistrationRequest) (*xkms.FinishRegistrationResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.FinishRegistration(ctx, req)
}

// BeginAuthentication begins a WebAuthn authentication flow.
func (a *Adapter) BeginAuthentication(ctx context.Context, req *xkms.BeginAuthenticationRequest) (*xkms.BeginAuthenticationResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.BeginAuthentication(ctx, req)
}

// FinishAuthentication completes a WebAuthn authentication flow.
func (a *Adapter) FinishAuthentication(ctx context.Context, req *xkms.FinishAuthenticationRequest) (*xkms.FinishAuthenticationResponse, error) {
	client := a.Client()
	if client == nil {
		return nil, ErrAdapterNotStarted
	}
	return client.FinishAuthentication(ctx, req)
}
