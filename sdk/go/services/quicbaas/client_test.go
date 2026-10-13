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
	"errors"
	"testing"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// mockSDKClient implements the quicbaas.Client interface for testing.
// The interface evolves with the upstream SDK; this mock is kept in
// lock-step with the canonical Client surface in
// go-quicbaas/sdk/go/quicbaas.go.
type mockSDKClient struct {
	closed      bool
	closeErr    error
	transport   quicbaas.Transport
	kvClient    quicbaas.KVClient
	batchClient quicbaas.BatchClient

	orchestratorClient quicbaas.OrchestratorClient
	projectClient      quicbaas.ProjectClient
	accountClient      quicbaas.AccountClient
}

// Distinct non-nil clients for the agentic accessors. Each embeds the
// upstream interface, so a test can tell the wrapper returned this exact
// value rather than nil or another service's client.
type stubOrchestratorClient struct{ quicbaas.OrchestratorClient }
type stubProjectClient struct{ quicbaas.ProjectClient }
type stubAccountClient struct{ quicbaas.AccountClient }

func newMockSDKClient() *mockSDKClient {
	return &mockSDKClient{}
}

// Sub-interface accessors (organized API).
func (m *mockSDKClient) CoreData() quicbaas.CoreDataService             { return nil }
func (m *mockSDKClient) ClusterMgmt() quicbaas.ClusterManagementService { return nil }
func (m *mockSDKClient) Security() quicbaas.SecurityService             { return &mockSecurityService{} }
func (m *mockSDKClient) Identity() quicbaas.IdentityService             { return &mockIdentityService{} }
func (m *mockSDKClient) Search() quicbaas.SearchService                 { return nil }
func (m *mockSDKClient) Storage() quicbaas.StorageService               { return nil }
func (m *mockSDKClient) Async() quicbaas.AsyncService                   { return nil }
func (m *mockSDKClient) AI() quicbaas.AIService                         { return nil }
func (m *mockSDKClient) BarrierCeremonyMgmt() quicbaas.BarrierCeremonyService {
	return nil
}
func (m *mockSDKClient) TenantMgmtService() quicbaas.TenantService { return nil }

// Backward-compatible service accessors.
func (m *mockSDKClient) KV() quicbaas.KVClient                                 { return m.kvClient }
func (m *mockSDKClient) Batch() quicbaas.BatchClient                           { return m.batchClient }
func (m *mockSDKClient) Transaction() quicbaas.TransactionClient               { return nil }
func (m *mockSDKClient) Query() quicbaas.QueryClient                           { return nil }
func (m *mockSDKClient) Cluster() quicbaas.ClusterClient                       { return nil }
func (m *mockSDKClient) Health() quicbaas.HealthClient                         { return nil }
func (m *mockSDKClient) Operations() quicbaas.OperationsClient                 { return nil }
func (m *mockSDKClient) Cache() quicbaas.CacheClient                           { return nil }
func (m *mockSDKClient) Discovery() (*quicbaas.DiscoveryRegistry, error)       { return nil, nil }
func (m *mockSDKClient) IAM() quicbaas.IAMClient                               { return nil }
func (m *mockSDKClient) Vector() quicbaas.VectorClient                         { return nil }
func (m *mockSDKClient) TimeSeries() quicbaas.TimeSeriesClient                 { return nil }
func (m *mockSDKClient) Backup() quicbaas.BackupClient                         { return nil }
func (m *mockSDKClient) ObjectStorage() quicbaas.ObjectStorageClient           { return nil }
func (m *mockSDKClient) ObjectStorageAdmin() quicbaas.ObjectStorageAdminClient { return nil }
func (m *mockSDKClient) ObjectTransfer() quicbaas.ObjectTransferClient         { return nil }
func (m *mockSDKClient) ParameterStore() quicbaas.ParameterStoreClient         { return nil }
func (m *mockSDKClient) Scheduler() quicbaas.SchedulerClient                   { return nil }
func (m *mockSDKClient) Messaging() quicbaas.MessagingClient                   { return nil }
func (m *mockSDKClient) Embedding() quicbaas.EmbeddingClient                   { return nil }
func (m *mockSDKClient) Ollama() quicbaas.OllamaClient                         { return nil }
func (m *mockSDKClient) RAG() quicbaas.RAGClient                               { return nil }
func (m *mockSDKClient) Project() quicbaas.ProjectClient                       { return m.projectClient }
func (m *mockSDKClient) Account() quicbaas.AccountClient                       { return m.accountClient }
func (m *mockSDKClient) Orchestrator() quicbaas.OrchestratorClient             { return m.orchestratorClient }
func (m *mockSDKClient) SDLC() quicbaas.SDLCClient                             { return nil }

// QRDB-backed accessors (returning two values, error path always nil).
func (m *mockSDKClient) SealStore() (quicbaas.QRDBSealStoreClient, error) {
	return nil, nil
}
func (m *mockSDKClient) TenantMgmt() (quicbaas.QRDBTenantClient, error) { return nil, nil }
func (m *mockSDKClient) CustodianGroup() (quicbaas.QRDBCustodianGroupClient, error) {
	return nil, nil
}
func (m *mockSDKClient) Share() (quicbaas.QRDBShareClient, error) { return nil, nil }
func (m *mockSDKClient) DataStore() (quicbaas.QRDBKVStore, error) { return nil, nil }

func (m *mockSDKClient) Transport() quicbaas.Transport { return m.transport }
func (m *mockSDKClient) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	return m.closeErr
}

// mockIdentityService is a minimal IdentityService that returns nil for every
// capability, mirroring mockSecurityService: it lets the wrapper's
// Identity().IAM() delegation execute without panicking while preserving the
// test's "expected nil" expectations.
type mockIdentityService struct {
	quicbaas.IdentityService
}

func (mockIdentityService) IAM() quicbaas.IAMClient { return nil }

// mockSecurityService is a minimal SecurityService that returns nil for every
// capability. It lets the wrapper's Security().X() delegation execute without
// panicking while preserving the test's "expected nil" expectations.
type mockSecurityService struct {
	quicbaas.SecurityService
}

func (mockSecurityService) Auth() quicbaas.AuthService                    { return nil }
func (mockSecurityService) Seal() quicbaas.SealClient                     { return nil }
func (mockSecurityService) KMS() quicbaas.KMSClient                       { return nil }
func (mockSecurityService) Secrets() quicbaas.SecretsClient               { return nil }
func (mockSecurityService) Crypto() quicbaas.CryptoClient                 { return nil }
func (mockSecurityService) RBAC() quicbaas.RBACClient                     { return nil }
func (mockSecurityService) DynamicSecrets() quicbaas.DynamicSecretsClient { return nil }
func (mockSecurityService) Certificate() quicbaas.CertificateClient       { return nil }
func (mockSecurityService) DEK() quicbaas.DEKClient                       { return nil }

// TestNewClientFromSDK_Success tests creating a client from an existing SDK client.
func TestNewClientFromSDK_Success(t *testing.T) {
	mockSDK := newMockSDKClient()

	client, err := NewClientFromSDK(mockSDK)
	if err != nil {
		t.Fatalf("NewClientFromSDK() unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("NewClientFromSDK() returned nil client")
	}
	if client.SDK() != quicbaas.Client(mockSDK) {
		t.Error("SDK() did not return the expected SDK client")
	}
}

// TestNewClientFromSDK_NilSDK tests that a nil SDK client returns an error.
func TestNewClientFromSDK_NilSDK(t *testing.T) {
	client, err := NewClientFromSDK(nil)
	if err == nil {
		t.Fatal("NewClientFromSDK(nil) expected error, got nil")
	}
	if client != nil {
		t.Error("NewClientFromSDK(nil) expected nil client")
	}

	var errNil ErrNilSDKClient
	if !errors.As(err, &errNil) {
		t.Errorf("Expected ErrNilSDKClient, got %T: %v", err, err)
	}
}

// TestClient_Close_Success tests successful client close.
func TestClient_Close_Success(t *testing.T) {
	mockSDK := newMockSDKClient()
	client, _ := NewClientFromSDK(mockSDK)

	err := client.Close()
	if err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}
	if !client.IsClosed() {
		t.Error("IsClosed() expected true after Close()")
	}
	if !mockSDK.closed {
		t.Error("SDK client was not closed")
	}
}

// TestClient_Close_AlreadyClosed tests that closing an already closed client is idempotent.
func TestClient_Close_AlreadyClosed(t *testing.T) {
	mockSDK := newMockSDKClient()
	client, _ := NewClientFromSDK(mockSDK)

	// First close
	err := client.Close()
	if err != nil {
		t.Fatalf("First Close() unexpected error: %v", err)
	}

	// Second close should be a no-op
	err = client.Close()
	if err != nil {
		t.Fatalf("Second Close() unexpected error: %v", err)
	}
}

// TestClient_Close_Error tests error handling when close fails.
func TestClient_Close_Error(t *testing.T) {
	expectedErr := errors.New("close failed")
	mockSDK := newMockSDKClient()
	mockSDK.closeErr = expectedErr

	client, _ := NewClientFromSDK(mockSDK)

	err := client.Close()
	if err == nil {
		t.Fatal("Close() expected error, got nil")
	}

	var closeErr ErrCloseFailed
	if !errors.As(err, &closeErr) {
		t.Errorf("Expected ErrCloseFailed, got %T: %v", err, err)
	}
	if !errors.Is(closeErr, expectedErr) {
		t.Errorf("Expected underlying error %v, got %v", expectedErr, closeErr.Cause)
	}
}

// TestClient_IsClosed tests the IsClosed method.
func TestClient_IsClosed(t *testing.T) {
	mockSDK := newMockSDKClient()
	client, _ := NewClientFromSDK(mockSDK)

	if client.IsClosed() {
		t.Error("IsClosed() expected false before Close()")
	}

	client.Close()

	if !client.IsClosed() {
		t.Error("IsClosed() expected true after Close()")
	}
}

// TestClient_ServiceAccessors tests all service accessor methods.
func TestClient_ServiceAccessors(t *testing.T) {
	mockSDK := newMockSDKClient()
	client, _ := NewClientFromSDK(mockSDK)

	// Test all service accessors - they should return the mock's values (nil in this case).
	// The important thing is that they don't panic and return the expected types.
	tests := []struct {
		name     string
		accessor func() interface{}
	}{
		{"KV", func() interface{} { return client.KV() }},
		{"Batch", func() interface{} { return client.Batch() }},
		{"Transaction", func() interface{} { return client.Transaction() }},
		{"Query", func() interface{} { return client.Query() }},
		{"Cluster", func() interface{} { return client.Cluster() }},
		{"Health", func() interface{} { return client.Health() }},
		{"Operations", func() interface{} { return client.Operations() }},
		{"Cache", func() interface{} { return client.Cache() }},
		{"Auth", func() interface{} { return client.Auth() }},
		{"Seal", func() interface{} { return client.Seal() }},
		{"KMS", func() interface{} { return client.KMS() }},
		{"Secrets", func() interface{} { return client.Secrets() }},
		{"Crypto", func() interface{} { return client.Crypto() }},
		{"RBAC", func() interface{} { return client.RBAC() }},
		{"DynamicSecrets", func() interface{} { return client.DynamicSecrets() }},
		{"Certificate", func() interface{} { return client.Certificate() }},
		{"DEK", func() interface{} { return client.DEK() }},
		{"IAM", func() interface{} { return client.IAM() }},
		{"Vector", func() interface{} { return client.Vector() }},
		{"TimeSeries", func() interface{} { return client.TimeSeries() }},
		{"Backup", func() interface{} { return client.Backup() }},
		{"ObjectStorage", func() interface{} { return client.ObjectStorage() }},
		{"ObjectStorageAdmin", func() interface{} { return client.ObjectStorageAdmin() }},
		{"ObjectTransfer", func() interface{} { return client.ObjectTransfer() }},
		{"ParameterStore", func() interface{} { return client.ParameterStore() }},
		{"Scheduler", func() interface{} { return client.Scheduler() }},
		{"Messaging", func() interface{} { return client.Messaging() }},
		{"Embedding", func() interface{} { return client.Embedding() }},
		{"Ollama", func() interface{} { return client.Ollama() }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic.
			result := tt.accessor()
			// Result should be nil since mock returns nil for all services.
			if result != nil {
				t.Errorf("%s() expected nil from mock, got %v", tt.name, result)
			}
		})
	}
}

// TestClient_AgenticAccessors proves each agentic accessor routes to its own
// go-quicbaas client: the value returned is the SDK's, not a sibling's.
func TestClient_AgenticAccessors(t *testing.T) {
	orchestrator := &stubOrchestratorClient{}
	project := &stubProjectClient{}
	account := &stubAccountClient{}
	mockSDK := newMockSDKClient()
	mockSDK.orchestratorClient = orchestrator
	mockSDK.projectClient = project
	mockSDK.accountClient = account

	client, err := NewClientFromSDK(mockSDK)
	if err != nil {
		t.Fatalf("NewClientFromSDK() error = %v", err)
	}

	if got := client.Orchestrator(); got != orchestrator {
		t.Errorf("Orchestrator() = %v, want the SDK's orchestrator client", got)
	}
	if got := client.Project(); got != project {
		t.Errorf("Project() = %v, want the SDK's project client", got)
	}
	if got := client.Account(); got != account {
		t.Errorf("Account() = %v, want the SDK's account client", got)
	}
}

// TestClient_AgenticAccessors_ServiceUnavailable proves an SDK that does not
// serve the agentic surface yields nil from each accessor rather than a
// panic or a client for some other service.
func TestClient_AgenticAccessors_ServiceUnavailable(t *testing.T) {
	client, err := NewClientFromSDK(newMockSDKClient())
	if err != nil {
		t.Fatalf("NewClientFromSDK() error = %v", err)
	}

	if got := client.Orchestrator(); got != nil {
		t.Errorf("Orchestrator() = %v, want nil", got)
	}
	if got := client.Project(); got != nil {
		t.Errorf("Project() = %v, want nil", got)
	}
	if got := client.Account(); got != nil {
		t.Errorf("Account() = %v, want nil", got)
	}
}

// TestClient_Transport tests the Transport accessor.
func TestClient_Transport(t *testing.T) {
	mockSDK := newMockSDKClient()
	client, _ := NewClientFromSDK(mockSDK)

	transport := client.Transport()
	// Transport should match what mock SDK returns (nil in this case).
	if transport != nil {
		t.Errorf("Transport() expected nil from mock, got %v", transport)
	}
}

// TestClient_SDK tests the SDK accessor.
func TestClient_SDK(t *testing.T) {
	mockSDK := newMockSDKClient()
	client, _ := NewClientFromSDK(mockSDK)

	sdk := client.SDK()
	if sdk != quicbaas.Client(mockSDK) {
		t.Error("SDK() did not return the expected SDK client")
	}
}

// TestErrors tests error type string representations.
func TestErrors(t *testing.T) {
	t.Run("ErrNilSDKClient", func(t *testing.T) {
		err := ErrNilSDKClient{}
		expected := "quicbaas: SDK client cannot be nil"
		if err.Error() != expected {
			t.Errorf("Error() = %q, want %q", err.Error(), expected)
		}
	})

	t.Run("ErrClientClosed", func(t *testing.T) {
		err := ErrClientClosed{}
		expected := "quicbaas: client is closed"
		if err.Error() != expected {
			t.Errorf("Error() = %q, want %q", err.Error(), expected)
		}
	})

	t.Run("ErrClientCreationFailed", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := ErrClientCreationFailed{Address: "localhost:50051", Cause: cause}
		expected := "quicbaas: failed to create client for address localhost:50051: connection refused"
		if err.Error() != expected {
			t.Errorf("Error() = %q, want %q", err.Error(), expected)
		}
		if !errors.Is(err, cause) {
			t.Error("Unwrap() did not return expected cause")
		}
	})

	t.Run("ErrInvalidTransport", func(t *testing.T) {
		err := ErrInvalidTransport{Transport: 99}
		expected := "quicbaas: invalid transport type: 99"
		if err.Error() != expected {
			t.Errorf("Error() = %q, want %q", err.Error(), expected)
		}
	})

	t.Run("ErrCloseFailed", func(t *testing.T) {
		cause := errors.New("connection already closed")
		err := ErrCloseFailed{Cause: cause}
		expected := "quicbaas: failed to close client: connection already closed"
		if err.Error() != expected {
			t.Errorf("Error() = %q, want %q", err.Error(), expected)
		}
		if !errors.Is(err, cause) {
			t.Error("Unwrap() did not return expected cause")
		}
	})
}

// TestNewClient_EmptyAddress tests that NewClient with empty address returns error.
func TestNewClient_EmptyAddress(t *testing.T) {
	client, err := NewClient("")
	if err == nil {
		t.Fatal("NewClient(\"\") expected error, got nil")
	}
	if client != nil {
		t.Error("NewClient(\"\") expected nil client")
	}

	var errCreation ErrClientCreationFailed
	if !errors.As(err, &errCreation) {
		t.Errorf("Expected ErrClientCreationFailed, got %T: %v", err, err)
	}
}

// TestNewClient_InvalidAddress tests NewClient with an invalid address.
// This tests error handling when the underlying SDK fails.
func TestNewClient_InvalidAddress(t *testing.T) {
	// Use an invalid address that will fail to connect.
	// Since there's no server running, this should fail.
	client, err := NewClient("invalid-address-format")
	// The behavior depends on SDK implementation. At minimum, we should
	// get a valid error or a working client object.
	switch {
	case err != nil:
		var errCreation ErrClientCreationFailed
		if !errors.As(err, &errCreation) {
			t.Errorf("Expected ErrClientCreationFailed, got %T: %v", err, err)
		}
	case client == nil:
		t.Error("NewClient() returned nil client with nil error")
	default:
		// Client was created, clean up.
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}
}

// Ensure mockSDKClient implements quicbaas.Client interface.
var _ quicbaas.Client = (*mockSDKClient)(nil)
