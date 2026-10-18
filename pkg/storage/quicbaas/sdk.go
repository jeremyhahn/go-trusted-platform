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

package quicbaas

import (
	"sync"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// SDKClient wraps the go-quicbaas SDK client to provide multi-transport access
// to QuicBaaS services. It supports embedded, Unix socket, gRPC, REST, and QUIC
// transports while maintaining a unified interface.
//
// For embedded mode (default), the client wraps an existing QuicBaaS service
// instance for in-process access without network overhead.
//
// For remote transports (Unix, gRPC, REST, QUIC), the client connects to an
// external QuicBaaS server.
type SDKClient struct {
	client quicbaas.Client
	config *Config

	mu     sync.RWMutex
	closed bool
}

// NewSDKClient creates a new SDK client based on the config transport mode.
// For embedded mode, the embeddedService parameter must be provided.
// For remote transports, embeddedService should be nil.
//
// Note: this entry point does NOT wire the qrdb sub-client's in-process
// transport. SDK callers that need Security().Barrier(),
// Security().Ceremony(), or Security().Credentials() to dispatch in-process
// against an embedded server MUST use NewSDKClientWithEmbeddedServer
// instead. Calling Security().Ceremony() on a client built here under
// embedded transport will return a "TransportEmbedded requires
// WithEmbeddedQRDB(...)" configuration error on the first qrdb-backed call.
func NewSDKClient(cfg *Config, embeddedService service.QuicBaaS) (*SDKClient, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	client, err := buildClient(cfg, embeddedService, nil)
	if err != nil {
		return nil, err
	}

	return &SDKClient{
		client: client,
		config: cfg,
	}, nil
}

// NewSDKClientWithEmbeddedServer creates an SDK client whose qrdb sub-client
// dispatches in-process against the supplied embedded server. This is the
// constructor the factory uses in embedded mode so that platformd's gate
// /init handler (and every other Security().Ceremony() / Security().Credentials()
// / Security().Barrier() caller) reaches the embedded server's qrdb services
// without trying to dial a network address.
//
// For non-embedded transports, embeddedServer is ignored and behaviour
// matches NewSDKClient. For embedded transport, both the embedded service
// (passed via embeddedServer.Service()) AND the qrdb servicers (pulled
// from embeddedServer.Server()) are wired into the SDK client. Returns
// EmbeddedQRDBWiringError when the qrdb wiring cannot be assembled (for
// example, when the embedded server has not started yet).
func NewSDKClientWithEmbeddedServer(cfg *Config, embeddedServer *EmbeddedServer) (*SDKClient, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var (
		svc service.QuicBaaS
		es  *EmbeddedServer
	)
	if cfg.Transport == TransportEmbedded {
		if embeddedServer == nil {
			return nil, ErrEmbeddedServiceRequired{}
		}
		svc = embeddedServer.Service()
		es = embeddedServer
	}

	client, err := buildClient(cfg, svc, es)
	if err != nil {
		return nil, err
	}

	return &SDKClient{
		client: client,
		config: cfg,
	}, nil
}

// buildClient dispatches transport construction. embeddedService and
// embeddedServer are only consulted when cfg.Transport == TransportEmbedded;
// remote transports ignore both parameters.
func buildClient(cfg *Config, embeddedService service.QuicBaaS, embeddedServer *EmbeddedServer) (quicbaas.Client, error) {
	var (
		client quicbaas.Client
		err    error
	)
	switch cfg.Transport {
	case TransportEmbedded:
		client, err = createEmbeddedSDKClient(cfg, embeddedService, embeddedServer)
	case TransportUnix:
		client, err = createUnixSDKClient(cfg)
	case TransportGRPC:
		client, err = createGRPCSDKClient(cfg)
	case TransportREST:
		client, err = createRESTSDKClient(cfg)
	case TransportQUIC:
		client, err = createQUICSDKClient(cfg)
	default:
		return nil, ErrUnsupportedTransport{Transport: cfg.Transport}
	}

	if err != nil {
		return nil, ErrConnectionFailed{Cause: err}
	}
	return client, nil
}

// createEmbeddedSDKClient creates an SDK client for embedded (in-process) mode.
// When embeddedServer is non-nil, WithEmbeddedQRDB is wired so the qrdb
// sub-client dispatches in-process; when nil, the qrdb sub-client is left
// uninstalled and Security().Ceremony() calls return a configuration error
// on first use.
func createEmbeddedSDKClient(cfg *Config, svc service.QuicBaaS, embeddedServer *EmbeddedServer) (quicbaas.Client, error) {
	if svc == nil {
		return nil, ErrEmbeddedServiceRequired{}
	}

	// Use the address field if set, otherwise use the conventional embedded
	// label so log output and error messages identify the transport mode.
	address := cfg.Address
	if address == "" {
		address = "embedded"
	}

	opts := []quicbaas.Option{
		quicbaas.WithEmbedded(svc),
		quicbaas.WithTimeout(cfg.RequestTimeout),
	}

	// Wire the qrdb sub-client to dispatch in-process against the embedded
	// server's per-shard baasTransport (via the BaaS KV + Admin adapters)
	// plus the bootstrap ceremony services. Without WithEmbeddedQRDB the
	// qrdb sub-client has no listener to dial in embedded mode and any
	// Security().Ceremony() / Security().Credentials() / Security().Barrier()
	// call fails with a "produced zero addresses" transport error — which
	// is exactly what blocks platformd's gate /init handler.
	if embeddedServer != nil {
		qrdbOpt, err := embeddedQRDBOption(embeddedServer)
		if err != nil {
			return nil, err
		}
		opts = append(opts, qrdbOpt)
	}

	client, err := quicbaas.NewClient(address, opts...)
	if err != nil {
		return nil, err
	}
	return withVectorAvailability(cfg, client), nil
}

// createUnixSDKClient creates an SDK client for Unix socket transport.
func createUnixSDKClient(cfg *Config) (quicbaas.Client, error) {
	opts := []quicbaas.Option{
		quicbaas.WithUnix(cfg.UnixSocket),
		quicbaas.WithTimeout(cfg.RequestTimeout),
	}

	// Address is not used for Unix transport, socket path is in options
	return quicbaas.NewClient(cfg.UnixSocket, opts...)
}

// createGRPCSDKClient creates an SDK client for gRPC transport.
func createGRPCSDKClient(cfg *Config) (quicbaas.Client, error) {
	opts := []quicbaas.Option{
		quicbaas.WithTimeout(cfg.RequestTimeout),
	}

	// gRPC is the default transport, no special option needed
	return quicbaas.NewClient(cfg.Address, opts...)
}

// createRESTSDKClient creates an SDK client for REST/HTTP transport.
func createRESTSDKClient(cfg *Config) (quicbaas.Client, error) {
	opts := []quicbaas.Option{
		quicbaas.WithREST(),
		quicbaas.WithTimeout(cfg.RequestTimeout),
	}

	return quicbaas.NewClient(cfg.Address, opts...)
}

// createQUICSDKClient creates an SDK client for QUIC transport.
func createQUICSDKClient(cfg *Config) (quicbaas.Client, error) {
	opts := []quicbaas.Option{
		quicbaas.WithQUIC(),
		quicbaas.WithTimeout(cfg.RequestTimeout),
	}

	return quicbaas.NewClient(cfg.Address, opts...)
}

// Client returns the underlying quicbaas SDK client.
// Returns nil if the SDK client is closed.
func (s *SDKClient) Client() quicbaas.Client {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil
	}
	return s.client
}

// Config returns the configuration used to create this client.
func (s *SDKClient) Config() *Config {
	return s.config
}

// Transport returns the transport type being used.
func (s *SDKClient) Transport() Transport {
	return s.config.Transport
}

// IsEmbedded returns true if this client uses embedded (in-process) transport.
func (s *SDKClient) IsEmbedded() bool {
	return s.config.Transport == TransportEmbedded
}

// IsClosed returns true if the client has been closed.
func (s *SDKClient) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// Close closes the SDK client and releases resources.
// For embedded mode, this does NOT stop the underlying QuicBaaS server.
func (s *SDKClient) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	if s.client != nil {
		return s.client.Close()
	}

	return nil
}

// KV returns the KV client for key-value operations.
func (s *SDKClient) KV() quicbaas.KVClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.KV()
}

// Batch returns the Batch client for atomic batch operations.
func (s *SDKClient) Batch() quicbaas.BatchClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Batch()
}

// Transaction returns the Transaction client for compare-and-swap operations.
func (s *SDKClient) Transaction() quicbaas.TransactionClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Transaction()
}

// Query returns the Query client for secondary index queries.
func (s *SDKClient) Query() quicbaas.QueryClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Query()
}

// Cluster returns the Cluster client for cluster management.
func (s *SDKClient) Cluster() quicbaas.ClusterClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Cluster()
}

// Health returns the Health client for health checks.
func (s *SDKClient) Health() quicbaas.HealthClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Health()
}

// Auth returns the Auth client for authentication.
func (s *SDKClient) Auth() quicbaas.AuthClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Security().Auth()
}

// Seal returns the Seal client for seal/unseal operations.
func (s *SDKClient) Seal() quicbaas.SealClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Security().Seal()
}

// KMS returns the KMS client for key management.
func (s *SDKClient) KMS() quicbaas.KMSClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Security().KMS()
}

// Secrets returns the Secrets client for secret storage.
func (s *SDKClient) Secrets() quicbaas.SecretsClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Security().Secrets()
}

// Crypto returns the Crypto client for encryption/decryption operations.
func (s *SDKClient) Crypto() quicbaas.CryptoClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Security().Crypto()
}

// Vector returns the Vector client for vector similarity search.
func (s *SDKClient) Vector() quicbaas.VectorClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Vector()
}

// TimeSeries returns the TimeSeries client for time-series data.
func (s *SDKClient) TimeSeries() quicbaas.TimeSeriesClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.TimeSeries()
}

// Backup returns the Backup client for backup/restore operations.
func (s *SDKClient) Backup() quicbaas.BackupClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Backup()
}

// IAM returns the IAM client for identity and access management.
func (s *SDKClient) IAM() quicbaas.IAMClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Identity().IAM()
}

// Cache returns the Cache client for cache management.
func (s *SDKClient) Cache() quicbaas.CacheClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Cache()
}

// Operations returns the Operations client for cluster operations.
func (s *SDKClient) Operations() quicbaas.OperationsClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Operations()
}

// RBAC returns the RBAC client for role-based access control.
func (s *SDKClient) RBAC() quicbaas.RBACClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Security().RBAC()
}

// DynamicSecrets returns the DynamicSecrets client for dynamic credentials.
func (s *SDKClient) DynamicSecrets() quicbaas.DynamicSecretsClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Security().DynamicSecrets()
}

// Certificate returns the Certificate client for X.509 certificate management.
func (s *SDKClient) Certificate() quicbaas.CertificateClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Security().Certificate()
}

// DEK returns the Data Encryption Key client for per-tenant DEK management.
func (s *SDKClient) DEK() quicbaas.DEKClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Security().DEK()
}

// ObjectStorage returns the ObjectStorage client for distributed object storage.
func (s *SDKClient) ObjectStorage() quicbaas.ObjectStorageClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.ObjectStorage()
}

// ObjectStorageAdmin returns the ObjectStorageAdmin client for admin operations.
func (s *SDKClient) ObjectStorageAdmin() quicbaas.ObjectStorageAdminClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.ObjectStorageAdmin()
}

// ObjectTransfer returns the ObjectTransfer client for peer-to-peer data transfer.
func (s *SDKClient) ObjectTransfer() quicbaas.ObjectTransferClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.ObjectTransfer()
}

// ParameterStore returns the ParameterStore client for hierarchical parameters.
func (s *SDKClient) ParameterStore() quicbaas.ParameterStoreClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.ParameterStore()
}

// Scheduler returns the Scheduler client for job scheduling.
func (s *SDKClient) Scheduler() quicbaas.SchedulerClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Scheduler()
}

// Embedding returns the Embedding client for embedding generation.
func (s *SDKClient) Embedding() quicbaas.EmbeddingClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Embedding()
}

// Ollama returns the Ollama client for local LLM/embedding operations.
func (s *SDKClient) Ollama() quicbaas.OllamaClient {
	client := s.Client()
	if client == nil {
		return nil
	}
	return client.Ollama()
}
