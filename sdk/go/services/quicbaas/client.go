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
	"sync/atomic"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/secret"
)

// Client wraps the go-quicbaas SDK client for platform SDK consumers.
// It provides access to all 28 QuicBaaS services through a unified interface.
type Client struct {
	sdk    quicbaas.Client
	closed atomic.Bool
}

// NewClient creates a QuicBaaS client using the go-quicbaas SDK.
// The address can be a TCP address, Unix socket path, or HTTP URL.
// Options control transport type, TLS settings, timeouts, and more.
func NewClient(address string, opts ...quicbaas.Option) (*Client, error) {
	sdk, err := quicbaas.NewClient(address, opts...)
	if err != nil {
		return nil, ErrClientCreationFailed{Address: address, Cause: err}
	}
	return &Client{sdk: sdk}, nil
}

// NewClientFromSDK creates a Client wrapper from an existing go-quicbaas SDK client.
// This is useful when the SDK client is managed externally or for testing.
func NewClientFromSDK(sdk quicbaas.Client) (*Client, error) {
	if sdk == nil {
		return nil, ErrNilSDKClient{}
	}
	return &Client{sdk: sdk}, nil
}

// SDK returns the underlying go-quicbaas SDK client for advanced operations.
// Use this when you need direct access to SDK features not exposed by the wrapper.
func (c *Client) SDK() quicbaas.Client {
	return c.sdk
}

// Close closes the client and releases all resources.
func (c *Client) Close() error {
	if c.closed.Swap(true) {
		return nil // Already closed
	}
	if c.sdk != nil {
		if err := c.sdk.Close(); err != nil {
			return ErrCloseFailed{Cause: err}
		}
	}
	return nil
}

// IsClosed returns true if the client has been closed.
func (c *Client) IsClosed() bool {
	return c.closed.Load()
}

// =============================================================================
// Core Data Services
// =============================================================================

// KV returns the key-value service client for CRUD operations and Watch.
func (c *Client) KV() quicbaas.KVClient {
	return c.sdk.KV()
}

// Batch returns the batch service client for atomic batch operations.
func (c *Client) Batch() quicbaas.BatchClient {
	return c.sdk.Batch()
}

// Transaction returns the transaction service client for compare-and-swap transactions.
func (c *Client) Transaction() quicbaas.TransactionClient {
	return c.sdk.Transaction()
}

// Query returns the query service client for secondary index queries.
func (c *Client) Query() quicbaas.QueryClient {
	return c.sdk.Query()
}

// =============================================================================
// Cluster Operations
// =============================================================================

// Cluster returns the cluster service client for cluster management.
func (c *Client) Cluster() quicbaas.ClusterClient {
	return c.sdk.Cluster()
}

// Health returns the health service client for health checks.
func (c *Client) Health() quicbaas.HealthClient {
	return c.sdk.Health()
}

// Operations returns the operations service client for migration and upgrade operations.
func (c *Client) Operations() quicbaas.OperationsClient {
	return c.sdk.Operations()
}

// Cache returns the cache service client for cache management.
func (c *Client) Cache() quicbaas.CacheClient {
	return c.sdk.Cache()
}

// =============================================================================
// Security Operations
// =============================================================================

// Auth returns the authentication service client.
func (c *Client) Auth() quicbaas.AuthClient {
	return c.sdk.Security().Auth()
}

// Seal returns the seal service client for seal/unseal operations.
func (c *Client) Seal() quicbaas.SealClient {
	return c.sdk.Security().Seal()
}

// KMS returns the key management service client.
func (c *Client) KMS() quicbaas.KMSClient {
	return c.sdk.Security().KMS()
}

// Secrets returns the secrets service client for secret storage.
func (c *Client) Secrets() quicbaas.SecretsClient {
	return c.sdk.Security().Secrets()
}

// Crypto returns the cryptographic service client for encryption and signatures.
func (c *Client) Crypto() quicbaas.CryptoClient {
	return c.sdk.Security().Crypto()
}

// RBAC returns the role-based access control service client.
func (c *Client) RBAC() quicbaas.RBACClient {
	return c.sdk.Security().RBAC()
}

// DynamicSecrets returns the dynamic secrets service client.
func (c *Client) DynamicSecrets() quicbaas.DynamicSecretsClient {
	return c.sdk.Security().DynamicSecrets()
}

// Certificate returns the certificate service client.
func (c *Client) Certificate() quicbaas.CertificateClient {
	return c.sdk.Security().Certificate()
}

// DEK returns the Data Encryption Key service client.
func (c *Client) DEK() quicbaas.DEKClient {
	return c.sdk.Security().DEK()
}

// CertificateExt returns the certificate extensions client: TCG identity
// issuance and the TrustedCA primitives.
func (c *Client) CertificateExt() quicbaas.CertificateExtensions {
	return c.sdk.Security().CertificateExt()
}

// ACME returns the ACME service: the RFC 8555 protocol client with ARI,
// cross-signing and TPM enrollment, and the server-side challenge verifiers.
func (c *Client) ACME() quicbaas.ACMEService {
	return c.sdk.Security().ACME()
}

// Trust returns the trust service: DANE TLSA publication, cross-signed
// root pools and AIA-driven root import.
func (c *Client) Trust() quicbaas.TrustService {
	return c.sdk.Security().Trust()
}

// Attestation returns the attestation service: verification of hardware
// attestation statements and certificate chains, the image endorsement
// check and container attestation.
func (c *Client) Attestation() quicbaas.AttestationService {
	return c.sdk.Security().Attestation()
}

// SSH returns the SSH key, known-hosts and authorized-keys client.
func (c *Client) SSH() quicbaas.SSHService {
	return c.sdk.Security().SSH()
}

// Barrier returns the storage barrier client: initialize, unseal, seal,
// status, rekey and Shamir share management.
func (c *Client) Barrier() (quicbaas.QRDBBarrierClient, error) {
	barrier, err := c.sdk.Security().Barrier()
	if err != nil {
		return nil, ErrServiceUnavailable{Service: "barrier", Cause: err}
	}
	return barrier, nil
}

// Ceremony returns the initialization ceremony client: Shamir M-of-N share
// enrollment, officer certificate claims, share claims and CSR signing.
func (c *Client) Ceremony() (quicbaas.QRDBCeremonyClient, error) {
	ceremony, err := c.sdk.Security().Ceremony()
	if err != nil {
		return nil, ErrServiceUnavailable{Service: "ceremony", Cause: err}
	}
	return ceremony, nil
}

// Credentials returns the named-credential client, including versioned
// rotation.
func (c *Client) Credentials() (quicbaas.QRDBCredentialClient, error) {
	credentials, err := c.sdk.Security().Credentials()
	if err != nil {
		return nil, ErrServiceUnavailable{Service: "credentials", Cause: err}
	}
	return credentials, nil
}

// SealStore returns the seal store client.
func (c *Client) SealStore() (quicbaas.QRDBSealStoreClient, error) {
	sealStore, err := c.sdk.Security().SealStore()
	if err != nil {
		return nil, ErrServiceUnavailable{Service: "seal store", Cause: err}
	}
	return sealStore, nil
}

// SecretResolver returns the secret resolver registry that dispatches
// credential://, kms:// and remote-kms:// references. It is nil when the
// SDK client was built without a secret registry, as a pure network client
// is.
func (c *Client) SecretResolver() *secret.ResolverRegistry {
	return c.sdk.Security().SecretResolver()
}

// =============================================================================
// Identity and Access Management
// =============================================================================

// IAM returns the IAM service client for identity and access management.
// The IAM client provides access to sub-clients for Tenant, User, Group,
// Role, Policy, PEP, App, GDPR, Audit, and Admin operations.
func (c *Client) IAM() quicbaas.IAMClient {
	return c.sdk.Identity().IAM()
}

// =============================================================================
// Specialized Data Operations
// =============================================================================

// Vector returns the vector service client for similarity search.
func (c *Client) Vector() quicbaas.VectorClient {
	return c.sdk.Vector()
}

// TimeSeries returns the time series service client.
func (c *Client) TimeSeries() quicbaas.TimeSeriesClient {
	return c.sdk.TimeSeries()
}

// Backup returns the backup service client for backup and restore operations.
func (c *Client) Backup() quicbaas.BackupClient {
	return c.sdk.Backup()
}

// ObjectStorage returns the object storage service client.
func (c *Client) ObjectStorage() quicbaas.ObjectStorageClient {
	return c.sdk.ObjectStorage()
}

// ObjectStorageAdmin returns the object storage admin service client.
func (c *Client) ObjectStorageAdmin() quicbaas.ObjectStorageAdminClient {
	return c.sdk.ObjectStorageAdmin()
}

// ObjectTransfer returns the object transfer service client for peer-to-peer transfers.
func (c *Client) ObjectTransfer() quicbaas.ObjectTransferClient {
	return c.sdk.ObjectTransfer()
}

// ParameterStore returns the parameter store service client.
func (c *Client) ParameterStore() quicbaas.ParameterStoreClient {
	return c.sdk.ParameterStore()
}

// =============================================================================
// Scheduler Operations
// =============================================================================

// Scheduler returns the scheduler service client for job scheduling.
func (c *Client) Scheduler() quicbaas.SchedulerClient {
	return c.sdk.Scheduler()
}

// =============================================================================
// Messaging Operations
// =============================================================================

// Messaging returns the messaging service client for notifications and channels.
func (c *Client) Messaging() quicbaas.MessagingClient {
	return c.sdk.Messaging()
}

// =============================================================================
// AI/ML Operations
// =============================================================================

// Embedding returns the embedding service client for embedding generation.
func (c *Client) Embedding() quicbaas.EmbeddingClient {
	return c.sdk.Embedding()
}

// Ollama returns the Ollama service client for local LLM/embedding operations.
func (c *Client) Ollama() quicbaas.OllamaClient {
	return c.sdk.Ollama()
}

// RAG returns the retrieval-augmented generation service client.
func (c *Client) RAG() quicbaas.RAGClient {
	return c.sdk.RAG()
}

// =============================================================================
// Agentic Operations
// =============================================================================

// Orchestrator returns the orchestrator service client for agent fleet
// management: agents, sessions, tasks, jobs and workflows.
func (c *Client) Orchestrator() quicbaas.OrchestratorClient {
	return c.sdk.Orchestrator()
}

// Project returns the project service client for agentic project management.
func (c *Client) Project() quicbaas.ProjectClient {
	return c.sdk.Project()
}

// Account returns the account service client for the per-tenant pool of
// provider accounts an agent session can be spawned against.
func (c *Client) Account() quicbaas.AccountClient {
	return c.sdk.Account()
}

// SDLC returns the SDLC module client: forge bindings, project onboarding,
// conformance checks and deliveries.
func (c *Client) SDLC() quicbaas.SDLCClient {
	return c.sdk.SDLC()
}

// =============================================================================
// Barrier Ceremony and Tenant Management
// =============================================================================

// The ceremony client of BarrierCeremonyMgmt() is the one Ceremony() returns:
// go-quicbaas routes both to the same QRDB ceremony client.

// CustodianGroup returns the client for the custodian groups used in Shamir
// secret sharing.
func (c *Client) CustodianGroup() (quicbaas.QRDBCustodianGroupClient, error) {
	custodianGroup, err := c.sdk.BarrierCeremonyMgmt().CustodianGroup()
	if err != nil {
		return nil, ErrServiceUnavailable{Service: "custodian group", Cause: err}
	}
	return custodianGroup, nil
}

// Share returns the client for submitting and tracking Shamir shares.
func (c *Client) Share() (quicbaas.QRDBShareClient, error) {
	share, err := c.sdk.BarrierCeremonyMgmt().Share()
	if err != nil {
		return nil, ErrServiceUnavailable{Service: "share", Cause: err}
	}
	return share, nil
}

// Tenant returns the tenant client: tenant lifecycle and per-tenant barriers.
func (c *Client) Tenant() (quicbaas.QRDBTenantClient, error) {
	tenant, err := c.sdk.TenantMgmtService().Tenant()
	if err != nil {
		return nil, ErrServiceUnavailable{Service: "tenant", Cause: err}
	}
	return tenant, nil
}

// =============================================================================
// Service Registry
// =============================================================================

// Registry returns the service registry client: lease-based
// service-instance endpoints (register, renew, deregister, resolve and
// watch), scoped to the caller's authenticated tenant.
func (c *Client) Registry() quicbaas.RegistryClient {
	return c.sdk.Registry()
}

// DataStore returns a QRDB key-value store suitable for constructing DAOs.
func (c *Client) DataStore() (quicbaas.QRDBKVStore, error) {
	dataStore, err := c.sdk.DataStore()
	if err != nil {
		return nil, ErrServiceUnavailable{Service: "data store", Cause: err}
	}
	return dataStore, nil
}

// =============================================================================
// Transport Access
// =============================================================================

// Transport returns the underlying transport for advanced operations.
func (c *Client) Transport() quicbaas.Transport {
	return c.sdk.Transport()
}
