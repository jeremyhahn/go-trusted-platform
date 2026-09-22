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

// Package quicbaas provides the QuicBaaS SDK adapter for go-trusted-platform.
// This package wraps the go-quicbaas SDK client to provide unified access
// to all QuicBaaS services through a clean abstraction layer.
//
// The adapter supports multiple transport modes:
//   - Embedded: In-process access without network overhead
//   - gRPC: High-performance service-to-service communication
//   - REST: HTTP/HTTPS for web clients and external systems
//   - QUIC: Low-latency UDP-based transport
//   - Unix: Unix socket for local IPC
//
// Mode is inferred from configuration:
//   - If Backend is specified → remote mode (connects to external cluster)
//   - If Backend is NOT specified → embedded mode (in-process)
package quicbaas

import (
	"context"
	"sync"
	"sync/atomic"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// ClientFactory is a function type that creates a QuicBaaS SDK client.
// This allows injection of mock clients for testing.
type ClientFactory func(address string, opts ...quicbaas.Option) (quicbaas.Client, error)

// defaultClientFactory is the production client factory using the SDK.
var defaultClientFactory ClientFactory = quicbaas.NewClient

// Adapter wraps the go-quicbaas SDK client providing unified access to all
// 28 QuicBaaS services. It supports both embedded and remote operation modes,
// determined by configuration.
//
// The adapter is thread-safe and manages the SDK client lifecycle.
type Adapter struct {
	client        quicbaas.Client
	config        *Config
	logger        *logging.Logger
	clientFactory ClientFactory

	started atomic.Bool
	closed  atomic.Bool
	mu      sync.RWMutex
}

// NewAdapter creates a new QuicBaaS adapter with the given configuration.
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
		config:        cfg,
		logger:        logger,
		clientFactory: defaultClientFactory,
	}, nil
}

// Start initializes the adapter and establishes connection to QuicBaaS.
// For embedded mode, embeddedService must be provided.
// For remote modes, embeddedService should be nil.
func (a *Adapter) Start(ctx context.Context, embeddedService service.QuicBaaS) error {
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

	a.logger.Info("QuicBaaS adapter started",
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
			a.logger.Warn("error closing QuicBaaS client", "error", err)
			return err
		}
	}

	a.logger.Info("QuicBaaS adapter stopped")
	return nil
}

// createClient creates the SDK client based on transport mode.
func (a *Adapter) createClient(embeddedService service.QuicBaaS) (quicbaas.Client, error) {
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
	default:
		return nil, ErrUnsupportedTransport{Transport: a.config.Transport}
	}
}

// createEmbeddedClient creates an SDK client for embedded (in-process) mode.
func (a *Adapter) createEmbeddedClient(svc service.QuicBaaS) (quicbaas.Client, error) {
	if svc == nil {
		return nil, ErrEmbeddedServiceRequired
	}

	opts := []quicbaas.Option{
		quicbaas.WithEmbedded(svc),
	}
	if a.config.RequestTimeout > 0 {
		opts = append(opts, quicbaas.WithTimeout(a.config.RequestTimeout))
	}

	return a.clientFactory("embedded", opts...)
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

	return a.clientFactory(a.config.UnixSocket, opts...)
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

	// gRPC is the default transport
	return a.clientFactory(a.config.Address, opts...)
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

	return a.clientFactory(a.config.Address, opts...)
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

	return a.clientFactory(a.config.Address, opts...)
}

// appendTLSOptions wires the configured mTLS material into the SDK client
// options. The client certificate (config.TLS.ClientCert / ClientKey) is the
// platform's cluster service identity: when it carries a SPIFFE "svc" SAN in
// the broker's pinned trust domain, the broker's default-deny authorization
// gate short-circuits on the verified mTLS chain — no platform token is
// required for these service-to-service calls.
//
// TLS is mandatory for remote transports (enforced by Config.Validate, which
// requires CACert). The client certificate is optional at this layer: brokers
// that do not enforce default-deny still accept a CA-only (server-auth) TLS
// connection. When no TLS config is present (embedded transport) this is a
// no-op. A malformed certificate pair is rejected when the SDK applies the
// option in the client factory, surfacing as a construction error rather than
// silently dropping the service identity.
func (a *Adapter) appendTLSOptions(opts *[]quicbaas.Option) {
	if a.config.TLS == nil {
		return
	}
	if a.config.TLS.CACert == "" && a.config.TLS.ClientCert == "" {
		return
	}

	*opts = append(*opts, quicbaas.WithTLS(quicbaas.TLSConfig{
		CAFile:   a.config.TLS.CACert,
		CertFile: a.config.TLS.ClientCert,
		KeyFile:  a.config.TLS.ClientKey,
	}))
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

// IsRemote returns true if using a remote transport (Unix, gRPC, REST, QUIC).
func (a *Adapter) IsRemote() bool {
	return !a.IsEmbedded()
}

// Transport returns the transport type being used.
func (a *Adapter) Transport() Transport {
	return a.config.Transport
}

// =============================================================================
// Core Data Operations
// =============================================================================

// KV returns the KV client for key-value operations.
func (a *Adapter) KV() quicbaas.KVClient {
	if client := a.Client(); client != nil {
		return client.KV()
	}
	return nil
}

// Batch returns the Batch client for atomic batch operations.
func (a *Adapter) Batch() quicbaas.BatchClient {
	if client := a.Client(); client != nil {
		return client.Batch()
	}
	return nil
}

// Transaction returns the Transaction client for compare-and-swap operations.
func (a *Adapter) Transaction() quicbaas.TransactionClient {
	if client := a.Client(); client != nil {
		return client.Transaction()
	}
	return nil
}

// Query returns the Query client for secondary index queries.
func (a *Adapter) Query() quicbaas.QueryClient {
	if client := a.Client(); client != nil {
		return client.Query()
	}
	return nil
}

// =============================================================================
// Cluster Operations
// =============================================================================

// Cluster returns the Cluster client for cluster management.
func (a *Adapter) Cluster() quicbaas.ClusterClient {
	if client := a.Client(); client != nil {
		return client.Cluster()
	}
	return nil
}

// Health returns the Health client for health checks.
func (a *Adapter) Health() quicbaas.HealthClient {
	if client := a.Client(); client != nil {
		return client.Health()
	}
	return nil
}

// Operations returns the Operations client for cluster operations.
func (a *Adapter) Operations() quicbaas.OperationsClient {
	if client := a.Client(); client != nil {
		return client.Operations()
	}
	return nil
}

// Cache returns the Cache client for cache management.
func (a *Adapter) Cache() quicbaas.CacheClient {
	if client := a.Client(); client != nil {
		return client.Cache()
	}
	return nil
}

// =============================================================================
// Security Operations
// =============================================================================

// Auth returns the Auth client for authentication.
func (a *Adapter) Auth() quicbaas.AuthClient {
	if client := a.Client(); client != nil {
		return client.Security().Auth()
	}
	return nil
}

// Seal returns the Seal client for seal/unseal operations.
func (a *Adapter) Seal() quicbaas.SealClient {
	if client := a.Client(); client != nil {
		return client.Security().Seal()
	}
	return nil
}

// KMS returns the KMS client for key management.
func (a *Adapter) KMS() quicbaas.KMSClient {
	if client := a.Client(); client != nil {
		return client.Security().KMS()
	}
	return nil
}

// Secrets returns the Secrets client for secret storage.
func (a *Adapter) Secrets() quicbaas.SecretsClient {
	if client := a.Client(); client != nil {
		return client.Security().Secrets()
	}
	return nil
}

// Crypto returns the Crypto client for encryption/decryption operations.
func (a *Adapter) Crypto() quicbaas.CryptoClient {
	if client := a.Client(); client != nil {
		return client.Security().Crypto()
	}
	return nil
}

// RBAC returns the RBAC client for role-based access control.
func (a *Adapter) RBAC() quicbaas.RBACClient {
	if client := a.Client(); client != nil {
		return client.Security().RBAC()
	}
	return nil
}

// DynamicSecrets returns the DynamicSecrets client for dynamic credentials.
func (a *Adapter) DynamicSecrets() quicbaas.DynamicSecretsClient {
	if client := a.Client(); client != nil {
		return client.Security().DynamicSecrets()
	}
	return nil
}

// Certificate returns the Certificate client for X.509 certificate management.
func (a *Adapter) Certificate() quicbaas.CertificateClient {
	if client := a.Client(); client != nil {
		return client.Security().Certificate()
	}
	return nil
}

// DEK returns the Data Encryption Key client for per-tenant DEK management.
func (a *Adapter) DEK() quicbaas.DEKClient {
	if client := a.Client(); client != nil {
		return client.Security().DEK()
	}
	return nil
}

// =============================================================================
// IAM Operations
// =============================================================================

// IAM returns the IAM client for identity and access management.
//
// The SDK reaches IAM through Identity(), so this accessor traverses TWO hops
// where the others traverse one, and both have to be guarded. A client whose
// Identity() is nil -- any client observed before its service wiring
// completes -- would otherwise panic the caller rather than return the nil
// every other accessor here returns.
func (a *Adapter) IAM() quicbaas.IAMClient {
	client := a.Client()
	if client == nil {
		return nil
	}
	identity := client.Identity()
	if identity == nil {
		return nil
	}
	return identity.IAM()
}

// =============================================================================
// Specialized Data Operations
// =============================================================================

// Vector returns the Vector client for vector similarity search.
func (a *Adapter) Vector() quicbaas.VectorClient {
	if client := a.Client(); client != nil {
		return client.Vector()
	}
	return nil
}

// TimeSeries returns the TimeSeries client for time-series data.
func (a *Adapter) TimeSeries() quicbaas.TimeSeriesClient {
	if client := a.Client(); client != nil {
		return client.TimeSeries()
	}
	return nil
}

// Backup returns the Backup client for backup/restore operations.
func (a *Adapter) Backup() quicbaas.BackupClient {
	if client := a.Client(); client != nil {
		return client.Backup()
	}
	return nil
}

// ObjectStorage returns the ObjectStorage client for distributed object storage.
func (a *Adapter) ObjectStorage() quicbaas.ObjectStorageClient {
	if client := a.Client(); client != nil {
		return client.ObjectStorage()
	}
	return nil
}

// ObjectStorageAdmin returns the ObjectStorageAdmin client for admin operations.
func (a *Adapter) ObjectStorageAdmin() quicbaas.ObjectStorageAdminClient {
	if client := a.Client(); client != nil {
		return client.ObjectStorageAdmin()
	}
	return nil
}

// ObjectTransfer returns the ObjectTransfer client for peer-to-peer data transfer.
func (a *Adapter) ObjectTransfer() quicbaas.ObjectTransferClient {
	if client := a.Client(); client != nil {
		return client.ObjectTransfer()
	}
	return nil
}

// ParameterStore returns the ParameterStore client for hierarchical parameters.
func (a *Adapter) ParameterStore() quicbaas.ParameterStoreClient {
	if client := a.Client(); client != nil {
		return client.ParameterStore()
	}
	return nil
}

// =============================================================================
// Scheduler Operations
// =============================================================================

// Scheduler returns the Scheduler client for job scheduling.
func (a *Adapter) Scheduler() quicbaas.SchedulerClient {
	if client := a.Client(); client != nil {
		return client.Scheduler()
	}
	return nil
}

// =============================================================================
// Messaging Operations
// =============================================================================

// Messaging returns the Messaging client for pub/sub and notifications.
func (a *Adapter) Messaging() quicbaas.MessagingClient {
	if client := a.Client(); client != nil {
		return client.Messaging()
	}
	return nil
}

// =============================================================================
// AI/ML Operations
// =============================================================================

// Embedding returns the Embedding client for embedding generation.
func (a *Adapter) Embedding() quicbaas.EmbeddingClient {
	if client := a.Client(); client != nil {
		return client.Embedding()
	}
	return nil
}

// Ollama returns the Ollama client for local LLM/embedding operations.
func (a *Adapter) Ollama() quicbaas.OllamaClient {
	if client := a.Client(); client != nil {
		return client.Ollama()
	}
	return nil
}
