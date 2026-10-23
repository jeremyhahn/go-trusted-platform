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
	quicbaassecret "github.com/jeremyhahn/go-quicbaas/sdk/go/secret"
)

// MockClient is a mock implementation of the quicbaas.Client interface for testing.
//
// The mock is kept in lock-step with the canonical Client surface defined in
// go-quicbaas/sdk/go/quicbaas.go. When upstream adds, renames, or removes a
// method on quicbaas.Client, this mock must be updated to match — the
// compile-time assertion at the bottom of the file (`var _ quicbaas.Client =
// (*MockClient)(nil)`) is the source of truth for that contract.
type MockClient struct {
	mu sync.RWMutex

	// CloseError is the error to return on Close.
	CloseError error

	// closeCalled tracks if Close was called.
	closeCalled bool

	// Mock service clients
	kvClient             quicbaas.KVClient
	batchClient          quicbaas.BatchClient
	txnClient            quicbaas.TransactionClient
	queryClient          quicbaas.QueryClient
	clusterClient        quicbaas.ClusterClient
	healthClient         quicbaas.HealthClient
	operationsClient     quicbaas.OperationsClient
	cacheClient          quicbaas.CacheClient
	authClient           quicbaas.AuthClient
	sealClient           quicbaas.SealClient
	kmsClient            quicbaas.KMSClient
	secretsClient        quicbaas.SecretsClient
	cryptoClient         quicbaas.CryptoClient
	rbacClient           quicbaas.RBACClient
	dynamicSecretsClient quicbaas.DynamicSecretsClient
	certificateClient    quicbaas.CertificateClient
	dekClient            quicbaas.DEKClient
	iamClient            quicbaas.IAMClient
	vectorClient         quicbaas.VectorClient
	timeSeriesClient     quicbaas.TimeSeriesClient
	backupClient         quicbaas.BackupClient
	objectStorageClient  quicbaas.ObjectStorageClient
	objectStorageAdmin   quicbaas.ObjectStorageAdminClient
	objectTransferClient quicbaas.ObjectTransferClient
	parameterStoreClient quicbaas.ParameterStoreClient
	schedulerClient      quicbaas.SchedulerClient
	messagingClient      quicbaas.MessagingClient
	embeddingClient      quicbaas.EmbeddingClient
	ollamaClient         quicbaas.OllamaClient
	ragClient            quicbaas.RAGClient
	transport            quicbaas.Transport
}

// NewMockClient creates a new mock client.
func NewMockClient() *MockClient {
	return &MockClient{}
}

// =============================================================================
// Sub-Interface Accessors
// =============================================================================

// CoreData returns nil (stub for testing).
func (m *MockClient) CoreData() quicbaas.CoreDataService {
	return nil
}

// ClusterMgmt returns nil (stub for testing).
func (m *MockClient) ClusterMgmt() quicbaas.ClusterManagementService {
	return nil
}

// Security returns a mock SecurityService that delegates each accessor back to
// the MockClient's flat service fields. This mirrors the canonical
// securityService in go-quicbaas (sdk/go/services.go), which delegates to its
// underlying client. Delegating keeps the grouped Security() surface in
// lock-step with the flat accessors, so adapter methods that route through
// Security() (e.g. Adapter.KMS -> client.Security().KMS()) compare equal to the
// corresponding MockClient field.
func (m *MockClient) Security() quicbaas.SecurityService {
	return &mockSecurityService{m: m}
}

// mockSecurityService is a test SecurityService whose accessors resolve to the
// owning MockClient's flat service fields.
type mockSecurityService struct {
	m *MockClient
}

// Auth returns a nil AuthService. The owning MockClient's flat authClient field
// is also nil, so the adapter's Security().Auth() and the mock's flat Auth()
// compare equal (both nil) without requiring a full AuthService implementation.
func (s *mockSecurityService) Auth() quicbaas.AuthService { return nil }

func (s *mockSecurityService) Seal() quicbaas.SealClient       { return s.m.Seal() }
func (s *mockSecurityService) KMS() quicbaas.KMSClient         { return s.m.KMS() }
func (s *mockSecurityService) Secrets() quicbaas.SecretsClient { return s.m.Secrets() }
func (s *mockSecurityService) Crypto() quicbaas.CryptoClient   { return s.m.Crypto() }

func (s *mockSecurityService) Certificate() quicbaas.CertificateClient {
	return s.m.Certificate()
}

func (s *mockSecurityService) CertificateExt() quicbaas.CertificateExtensions { return nil }

func (s *mockSecurityService) DEK() quicbaas.DEKClient { return s.m.DEK() }

func (s *mockSecurityService) DynamicSecrets() quicbaas.DynamicSecretsClient {
	return s.m.DynamicSecrets()
}

func (s *mockSecurityService) RBAC() quicbaas.RBACClient { return s.m.RBAC() }

func (s *mockSecurityService) SealStore() (quicbaas.QRDBSealStoreClient, error) {
	return s.m.SealStore()
}

func (s *mockSecurityService) ACME() quicbaas.ACMEService   { return nil }
func (s *mockSecurityService) Trust() quicbaas.TrustService { return nil }

// Attestation returns a nil AttestationService. The MockClient carries no flat
// attestation field, and the adapter tests exercise Security().Attestation()
// only for identity with the client's own accessor, never for behaviour.
func (s *mockSecurityService) Attestation() quicbaas.AttestationService { return nil }

// SSH returns a nil SSHService for the same reason as Attestation.
func (s *mockSecurityService) SSH() quicbaas.SSHService { return nil }

func (s *mockSecurityService) Barrier() (quicbaas.QRDBBarrierClient, error) { return nil, nil }

func (s *mockSecurityService) Ceremony() (quicbaas.QRDBCeremonyClient, error) { return nil, nil }

func (s *mockSecurityService) Credentials() (quicbaas.QRDBCredentialClient, error) {
	return nil, nil
}

func (s *mockSecurityService) SecretResolver() *quicbaassecret.ResolverRegistry { return nil }

// Verify mockSecurityService implements quicbaas.SecurityService.
var _ quicbaas.SecurityService = (*mockSecurityService)(nil)

// mockIdentityService exposes the MockClient's own IAM client through the
// Identity() hop the SDK routes IAM through, so Adapter.IAM() and
// MockClient.IAM() resolve to the same value.
type mockIdentityService struct {
	client *MockClient
}

// IAM returns the MockClient's configured IAM client.
func (s *mockIdentityService) IAM() quicbaas.IAMClient { return s.client.IAM() }

// Verify mockIdentityService implements quicbaas.IdentityService.
var _ quicbaas.IdentityService = (*mockIdentityService)(nil)

// Identity returns a service that routes IAM back to this mock.
func (m *MockClient) Identity() quicbaas.IdentityService {
	return &mockIdentityService{client: m}
}

// Search returns nil (stub for testing).
func (m *MockClient) Search() quicbaas.SearchService {
	return nil
}

// Storage returns nil (stub for testing).
func (m *MockClient) Storage() quicbaas.StorageService {
	return nil
}

// Async returns nil (stub for testing).
func (m *MockClient) Async() quicbaas.AsyncService {
	return nil
}

// AI returns nil (stub for testing).
func (m *MockClient) AI() quicbaas.AIService {
	return nil
}

// =============================================================================
// Backward-Compatible Service Accessors
// =============================================================================

// KV returns the KV client.
func (m *MockClient) KV() quicbaas.KVClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.kvClient
}

// SetKV sets the KV client.
func (m *MockClient) SetKV(c quicbaas.KVClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kvClient = c
}

// Batch returns the Batch client.
func (m *MockClient) Batch() quicbaas.BatchClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.batchClient
}

// SetBatch sets the Batch client.
func (m *MockClient) SetBatch(c quicbaas.BatchClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.batchClient = c
}

// Transaction returns the Transaction client.
func (m *MockClient) Transaction() quicbaas.TransactionClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.txnClient
}

// SetTransaction sets the Transaction client.
func (m *MockClient) SetTransaction(c quicbaas.TransactionClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.txnClient = c
}

// Query returns the Query client.
func (m *MockClient) Query() quicbaas.QueryClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.queryClient
}

// SetQuery sets the Query client.
func (m *MockClient) SetQuery(c quicbaas.QueryClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queryClient = c
}

// Cluster returns the Cluster client.
func (m *MockClient) Cluster() quicbaas.ClusterClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clusterClient
}

// SetCluster sets the Cluster client.
func (m *MockClient) SetCluster(c quicbaas.ClusterClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clusterClient = c
}

// Health returns the Health client.
func (m *MockClient) Health() quicbaas.HealthClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthClient
}

// SetHealth sets the Health client.
func (m *MockClient) SetHealth(c quicbaas.HealthClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthClient = c
}

// Operations returns the Operations client.
func (m *MockClient) Operations() quicbaas.OperationsClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.operationsClient
}

// SetOperations sets the Operations client.
func (m *MockClient) SetOperations(c quicbaas.OperationsClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.operationsClient = c
}

// Cache returns the Cache client.
func (m *MockClient) Cache() quicbaas.CacheClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cacheClient
}

// SetCache sets the Cache client.
func (m *MockClient) SetCache(c quicbaas.CacheClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheClient = c
}

// Auth returns the Auth client.
func (m *MockClient) Auth() quicbaas.AuthClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.authClient
}

// SetAuth sets the Auth client.
func (m *MockClient) SetAuth(c quicbaas.AuthClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authClient = c
}

// Seal returns the Seal client.
func (m *MockClient) Seal() quicbaas.SealClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sealClient
}

// SetSeal sets the Seal client.
func (m *MockClient) SetSeal(c quicbaas.SealClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sealClient = c
}

// KMS returns the KMS client.
func (m *MockClient) KMS() quicbaas.KMSClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.kmsClient
}

// SetKMS sets the KMS client.
func (m *MockClient) SetKMS(c quicbaas.KMSClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kmsClient = c
}

// Secrets returns the Secrets client.
func (m *MockClient) Secrets() quicbaas.SecretsClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.secretsClient
}

// SetSecrets sets the Secrets client.
func (m *MockClient) SetSecrets(c quicbaas.SecretsClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secretsClient = c
}

// Crypto returns the Crypto client.
func (m *MockClient) Crypto() quicbaas.CryptoClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cryptoClient
}

// SetCrypto sets the Crypto client.
func (m *MockClient) SetCrypto(c quicbaas.CryptoClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cryptoClient = c
}

// RBAC returns the RBAC client.
func (m *MockClient) RBAC() quicbaas.RBACClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rbacClient
}

// SetRBAC sets the RBAC client.
func (m *MockClient) SetRBAC(c quicbaas.RBACClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rbacClient = c
}

// DynamicSecrets returns the DynamicSecrets client.
func (m *MockClient) DynamicSecrets() quicbaas.DynamicSecretsClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dynamicSecretsClient
}

// SetDynamicSecrets sets the DynamicSecrets client.
func (m *MockClient) SetDynamicSecrets(c quicbaas.DynamicSecretsClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dynamicSecretsClient = c
}

// Certificate returns the Certificate client.
func (m *MockClient) Certificate() quicbaas.CertificateClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.certificateClient
}

// SetCertificate sets the Certificate client.
func (m *MockClient) SetCertificate(c quicbaas.CertificateClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certificateClient = c
}

// DEK returns the DEK client.
func (m *MockClient) DEK() quicbaas.DEKClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dekClient
}

// Discovery returns the service-discovery registry. The mock returns nil;
// platform consumers of MockClient do not exercise discovery.
func (m *MockClient) Discovery() (*quicbaas.DiscoveryRegistry, error) {
	return nil, nil
}

// SetDEK sets the DEK client.
func (m *MockClient) SetDEK(c quicbaas.DEKClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dekClient = c
}

// IAM returns the IAM client.
func (m *MockClient) IAM() quicbaas.IAMClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.iamClient
}

// SetIAM sets the IAM client.
func (m *MockClient) SetIAM(c quicbaas.IAMClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.iamClient = c
}

// Vector returns the Vector client.
func (m *MockClient) Vector() quicbaas.VectorClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.vectorClient
}

// SetVector sets the Vector client.
func (m *MockClient) SetVector(c quicbaas.VectorClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vectorClient = c
}

// TimeSeries returns the TimeSeries client.
func (m *MockClient) TimeSeries() quicbaas.TimeSeriesClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.timeSeriesClient
}

// SetTimeSeries sets the TimeSeries client.
func (m *MockClient) SetTimeSeries(c quicbaas.TimeSeriesClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.timeSeriesClient = c
}

// Backup returns the Backup client.
func (m *MockClient) Backup() quicbaas.BackupClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.backupClient
}

// SetBackup sets the Backup client.
func (m *MockClient) SetBackup(c quicbaas.BackupClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.backupClient = c
}

// ObjectStorage returns the ObjectStorage client.
func (m *MockClient) ObjectStorage() quicbaas.ObjectStorageClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.objectStorageClient
}

// SetObjectStorage sets the ObjectStorage client.
func (m *MockClient) SetObjectStorage(c quicbaas.ObjectStorageClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objectStorageClient = c
}

// ObjectStorageAdmin returns the ObjectStorageAdmin client.
func (m *MockClient) ObjectStorageAdmin() quicbaas.ObjectStorageAdminClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.objectStorageAdmin
}

// SetObjectStorageAdmin sets the ObjectStorageAdmin client.
func (m *MockClient) SetObjectStorageAdmin(c quicbaas.ObjectStorageAdminClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objectStorageAdmin = c
}

// ObjectTransfer returns the ObjectTransfer client.
func (m *MockClient) ObjectTransfer() quicbaas.ObjectTransferClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.objectTransferClient
}

// SetObjectTransfer sets the ObjectTransfer client.
func (m *MockClient) SetObjectTransfer(c quicbaas.ObjectTransferClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objectTransferClient = c
}

// ParameterStore returns the ParameterStore client.
func (m *MockClient) ParameterStore() quicbaas.ParameterStoreClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.parameterStoreClient
}

// SetParameterStore sets the ParameterStore client.
func (m *MockClient) SetParameterStore(c quicbaas.ParameterStoreClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parameterStoreClient = c
}

// Scheduler returns the Scheduler client.
func (m *MockClient) Scheduler() quicbaas.SchedulerClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.schedulerClient
}

// SetScheduler sets the Scheduler client.
func (m *MockClient) SetScheduler(c quicbaas.SchedulerClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.schedulerClient = c
}

// Messaging returns the Messaging client.
func (m *MockClient) Messaging() quicbaas.MessagingClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.messagingClient
}

// SetMessaging sets the Messaging client.
func (m *MockClient) SetMessaging(c quicbaas.MessagingClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messagingClient = c
}

// Embedding returns the Embedding client.
func (m *MockClient) Embedding() quicbaas.EmbeddingClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.embeddingClient
}

// SetEmbedding sets the Embedding client.
func (m *MockClient) SetEmbedding(c quicbaas.EmbeddingClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.embeddingClient = c
}

// Ollama returns the Ollama client.
func (m *MockClient) Ollama() quicbaas.OllamaClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ollamaClient
}

// SetOllama sets the Ollama client.
func (m *MockClient) SetOllama(c quicbaas.OllamaClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ollamaClient = c
}

// RAG returns the RAG client.
func (m *MockClient) RAG() quicbaas.RAGClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ragClient
}

// SetRAG sets the RAG client.
func (m *MockClient) SetRAG(c quicbaas.RAGClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ragClient = c
}

// =============================================================================
// Connection Management
// =============================================================================

// Transport returns the transport.
func (m *MockClient) Transport() quicbaas.Transport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.transport
}

// SetTransport sets the transport.
func (m *MockClient) SetTransport(t quicbaas.Transport) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transport = t
}

// Close closes the mock client.
func (m *MockClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalled = true
	return m.CloseError
}

// WasCloseCalled returns true if Close was called.
func (m *MockClient) WasCloseCalled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closeCalled
}

// Reset resets the mock state.
func (m *MockClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalled = false
	m.CloseError = nil
}

// =============================================================================
// QRDB-Backed Accessors
// =============================================================================

// SealStore returns nil (stub for testing).
func (m *MockClient) SealStore() (quicbaas.QRDBSealStoreClient, error) { return nil, nil }

// TenantMgmt returns nil (stub for testing).
func (m *MockClient) TenantMgmt() (quicbaas.QRDBTenantClient, error) { return nil, nil }

// CustodianGroup returns nil (stub for testing).
func (m *MockClient) CustodianGroup() (quicbaas.QRDBCustodianGroupClient, error) { return nil, nil }

// Share returns nil (stub for testing).
func (m *MockClient) Share() (quicbaas.QRDBShareClient, error) { return nil, nil }

// DataStore returns nil (stub for testing).
func (m *MockClient) DataStore() (quicbaas.QRDBKVStore, error) { return nil, nil }

// BarrierCeremonyMgmt returns nil (stub for testing).
func (m *MockClient) BarrierCeremonyMgmt() quicbaas.BarrierCeremonyService { return nil }

// TenantMgmtService returns nil (stub for testing).
func (m *MockClient) TenantMgmtService() quicbaas.TenantService { return nil }

// =============================================================================
// Project, Account & Orchestrator Accessors
// =============================================================================

// Project returns nil (stub for testing).
func (m *MockClient) Project() quicbaas.ProjectClient { return nil }

// Account returns nil (stub for testing).
func (m *MockClient) Account() quicbaas.AccountClient { return nil }

// Orchestrator returns nil (stub for testing).
func (m *MockClient) Orchestrator() quicbaas.OrchestratorClient { return nil }

// Verify MockClient implements quicbaas.Client. This assertion is the
// source of truth for keeping the mock in lock-step with upstream.
var _ quicbaas.Client = (*MockClient)(nil)

// SDLC returns nil (stub for testing). The Client interface gained it in
// go-quicbaas v0.8.0; no test in this package exercises SDLC, and the
// surrounding mocks follow the same return-nil convention (see Identity,
// Search).
func (m *MockClient) SDLC() quicbaas.SDLCClient {
	return nil
}
