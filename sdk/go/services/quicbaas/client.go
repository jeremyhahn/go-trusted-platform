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

// =============================================================================
// Transport Access
// =============================================================================

// Transport returns the underlying transport for advanced operations.
func (c *Client) Transport() quicbaas.Transport {
	return c.sdk.Transport()
}
