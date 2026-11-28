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

package tenant

import (
	"context"
	"errors"
	"sync"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// testBarrierClient implements TenantBarrierClient for testing with real
// in-memory state tracking. The barriers map keys tenantID to the unsealed
// flag (true = unsealed, false = sealed). Presence of an entry means the
// barrier has been initialized.
type testBarrierClient struct {
	mu       sync.Mutex
	barriers map[string]bool // tenantID -> unsealed (true = unsealed)

	// initCalls counts TenantBarrierInit calls; initPassphrases records the
	// passphrase each call carried.
	initCalls       int
	initPassphrases [][]byte

	initErr   error
	unsealErr error
	sealErr   error
	statusErr error

	// isolation answers TenantIsolationType per tenant; a tenant not listed
	// is barrier-isolated.
	isolation map[string]string
	// isolationErr, when set, fails every TenantIsolationType lookup.
	isolationErr error

	// statusCalls counts TenantBarrierStatus calls to the backend.
	statusCalls int
}

func newTestBarrierClient() *testBarrierClient {
	return &testBarrierClient{
		barriers: make(map[string]bool),
	}
}

func (c *testBarrierClient) TenantBarrierInit(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierInitRequest) error {
	c.mu.Lock()
	c.initCalls++
	c.initPassphrases = append(c.initPassphrases, append([]byte(nil), req.Passphrase...))
	c.mu.Unlock()
	// Mirrors go-qrdb v0.19.0-alpha: an init with no passphrase is refused
	// with ErrEmptyPassphrase.
	if len(req.Passphrase) == 0 {
		return errors.New("qrdb: tenant barrier passphrase is empty")
	}
	if c.initErr != nil {
		return c.initErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.barriers[req.TenantID] = false // initialized but sealed
	return nil
}

func (c *testBarrierClient) TenantBarrierUnseal(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierUnsealRequest) error {
	if c.unsealErr != nil {
		return c.unsealErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.barriers[req.TenantID] = true // unsealed
	return nil
}

func (c *testBarrierClient) TenantBarrierSeal(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierSealRequest) error {
	if c.sealErr != nil {
		return c.sealErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.barriers[req.TenantID]; !ok {
		return ErrBarrierOperationFailed{Operation: "Seal", Err: ErrInvalidRequest{Reason: "tenant barrier not initialized"}}
	}
	c.barriers[req.TenantID] = false
	return nil
}

func (c *testBarrierClient) TenantBarrierStatus(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierStatusRequest) (*quicbaassdk.QRDBTenantBarrierStatusResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.statusCalls++
	if c.statusErr != nil {
		return nil, c.statusErr
	}
	unsealed, ok := c.barriers[req.TenantID]
	return &quicbaassdk.QRDBTenantBarrierStatusResponse{
		TenantID:       req.TenantID,
		Sealed:         !unsealed, // uninitialized -> ok=false -> unsealed=false -> Sealed=true
		Initialized:    ok,
		Strategy:       "software",
		HardwareBacked: false,
	}, nil
}

func (c *testBarrierClient) TenantIsolationType(ctx context.Context, tenantID string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isolationErr != nil {
		return "", c.isolationErr
	}
	if iso, ok := c.isolation[tenantID]; ok {
		return iso, nil
	}
	return "barrier", nil
}

func (c *testBarrierClient) isInitialized(tenantID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.barriers[tenantID]
	return ok
}

// newTestManagerWithBarrier creates a manager with a barrier client configured.
func newTestManagerWithBarrier(t *testing.T) (*Manager, *mockIAMClient, *testBarrierClient) {
	t.Helper()

	iamClient := newMockIAMClient()
	barrierClient := newTestBarrierClient()
	logger := newTestLogger()

	cfg := &ManagerConfig{
		IAMTenantClient:     iamClient,
		IAMRoleClient:       iamClient,
		TenantBarrierClient: barrierClient,
		Config:              DefaultConfig(),
		Logger:              logger,
	}

	// Disable DEK isolation for barrier-focused tests
	cfg.Config.EnableDEKIsolation = false

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	return manager, iamClient, barrierClient
}

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

// TestNewManager_AcceptsNilBarrierManager verifies that the manager can be
// created without a barrier manager or barrier client (graceful degradation).
func TestNewManager_AcceptsNilBarrierManager(t *testing.T) {
	iamClient := newMockIAMClient()
	logger := newTestLogger()

	cfg := &ManagerConfig{
		IAMTenantClient:     iamClient,
		IAMRoleClient:       iamClient,
		TenantBarrierClient: nil,
		BarrierManager:      nil,
		Config:              DefaultConfig(),
		Logger:              logger,
	}
	cfg.Config.EnableDEKIsolation = false

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if m.barrierManager != nil {
		t.Error("expected nil barrier manager")
	}
	if m.tenantBarrierClient != nil {
		t.Error("expected nil tenant barrier client")
	}
}

// TestNewManager_AcceptsBarrierClient verifies that the manager stores
// the provided barrier client correctly.
func TestNewManager_AcceptsBarrierClient(t *testing.T) {
	iamClient := newMockIAMClient()
	barrierClient := newTestBarrierClient()
	logger := newTestLogger()

	cfg := &ManagerConfig{
		IAMTenantClient:     iamClient,
		IAMRoleClient:       iamClient,
		TenantBarrierClient: barrierClient,
		Config:              DefaultConfig(),
		Logger:              logger,
	}
	cfg.Config.EnableDEKIsolation = false

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if m.tenantBarrierClient == nil {
		t.Error("expected non-nil tenant barrier client")
	}
}

// ---------------------------------------------------------------------------
// BarrierManager accessor
// ---------------------------------------------------------------------------

// TestBarrierManager_ReturnsNilWhenNotConfigured verifies that BarrierManager
// returns nil when no barrier manager is set.
func TestBarrierManager_ReturnsNilWhenNotConfigured(t *testing.T) {
	m, _ := newTestManager(t)
	if m.BarrierManager() != nil {
		t.Error("expected nil barrier manager")
	}
}

// ---------------------------------------------------------------------------
// CreateTenant barrier integration
// ---------------------------------------------------------------------------

// TestCreateTenant_InitializesBarrier verifies that CreateTenant calls
// TenantBarrierInit when a barrier client is configured.
func TestCreateTenant_InitializesBarrier(t *testing.T) {
	m, _, bc := newTestManagerWithBarrier(t)
	ctx := context.Background()

	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{
		Name: "barrier-test-tenant",
	})
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	// The barrier passphrase comes from the operator in Initialize and is
	// never defaulted, so CreateTenant's non-fatal auto-init is refused and
	// the barrier stays uninitialized until the operator initializes it.
	if bc.isInitialized(entity.ID) {
		t.Error("CreateTenant must not initialize the barrier without an operator passphrase")
	}
}

// TestCreateTenant_BarrierInitFailureNonFatal verifies that CreateTenant
// succeeds even when barrier initialization fails.
func TestCreateTenant_BarrierInitFailureNonFatal(t *testing.T) {
	m, _, bc := newTestManagerWithBarrier(t)
	bc.initErr = errors.New("simulated barrier init failure")
	ctx := context.Background()

	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{
		Name: "barrier-fail-tenant",
	})
	if err != nil {
		t.Fatalf("CreateTenant should not fail when barrier init fails: %v", err)
	}

	if entity == nil {
		t.Fatal("expected non-nil entity")
	}

	// Barrier should NOT be initialized since init failed
	if bc.isInitialized(entity.ID) {
		t.Error("barrier should not be initialized when init fails")
	}
}

// TestCreateTenant_SkipsBarrierWhenClientNil verifies that CreateTenant
// does not attempt barrier initialization when no barrier client is set.
// ---------------------------------------------------------------------------
// DeleteTenant barrier integration
// ---------------------------------------------------------------------------

// TestDeleteTenant_ProceedsWithBarrierClient verifies that DeleteTenant
// succeeds even when a barrier client is configured (cleanup is deferred).
func TestDeleteTenant_ProceedsWithBarrierClient(t *testing.T) {
	m, _, bc := newTestManagerWithBarrier(t)
	ctx := context.Background()

	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{
		Name: "delete-barrier-tenant",
	})
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	if err := m.InitTenantBarrier(ctx, entity.ID, []byte("operator-pass")); err != nil {
		t.Fatalf("InitTenantBarrier: %v", err)
	}
	if !bc.isInitialized(entity.ID) {
		t.Error("barrier should be initialized after init")
	}

	err = m.DeleteTenant(ctx, entity.ID)
	if err != nil {
		t.Fatalf("DeleteTenant should succeed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// InitTenantBarrier
// ---------------------------------------------------------------------------

// TestInitTenantBarrier_Success verifies explicit barrier initialization.
func TestInitTenantBarrier_Success(t *testing.T) {
	m, _, bc := newTestManagerWithBarrier(t)
	ctx := context.Background()

	// Create tenant first (barrier init will succeed during create)
	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{
		Name: "explicit-init-tenant",
	})
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	// Reset barrier state to simulate re-initialization
	bc.mu.Lock()
	delete(bc.barriers, entity.ID)
	bc.mu.Unlock()

	err = m.InitTenantBarrier(ctx, entity.ID, []byte("operator-pass"))
	if err != nil {
		t.Fatalf("InitTenantBarrier failed: %v", err)
	}

	if !bc.isInitialized(entity.ID) {
		t.Error("barrier should be initialized")
	}
}

// TestInitTenantBarrier_EmptyTenantID verifies proper error for empty ID.
func TestInitTenantBarrier_EmptyTenantID(t *testing.T) {
	m, _, _ := newTestManagerWithBarrier(t)
	ctx := context.Background()

	err := m.InitTenantBarrier(ctx, "", []byte("operator-pass"))
	if err == nil {
		t.Fatal("expected error for empty tenant ID")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got: %T", err)
	}
}

// TestManager_InitTenantBarrierRefusesAnEmptyPassphrase verifies that an init
// with no operator passphrase is refused before the barrier client is called
// (go-qrdb v0.19.0-alpha refuses it with ErrEmptyPassphrase anyway).
func TestManager_InitTenantBarrierRefusesAnEmptyPassphrase(t *testing.T) {
	m, _, bc := newTestManagerWithBarrier(t)
	ctx := context.Background()

	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{Name: "empty-pass-tenant"})
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}
	bc.mu.Lock()
	before := bc.initCalls
	bc.mu.Unlock()

	for _, pass := range [][]byte{nil, {}} {
		err = m.InitTenantBarrier(ctx, entity.ID, pass)
		var invalidReq ErrInvalidRequest
		if !errors.As(err, &invalidReq) {
			t.Fatalf("InitTenantBarrier(%q) = %v (%T), want ErrInvalidRequest", pass, err, err)
		}
	}

	bc.mu.Lock()
	after := bc.initCalls
	bc.mu.Unlock()
	if after != before {
		t.Errorf("barrier client called %d times for an empty passphrase, want 0", after-before)
	}
	if bc.isInitialized(entity.ID) {
		t.Error("barrier must stay uninitialized after an empty-passphrase init")
	}
}

// TestManager_InitTenantBarrierForwardsTheOperatorPassphrase verifies that the
// operator's passphrase reaches the qrdb init request unchanged.
func TestManager_InitTenantBarrierForwardsTheOperatorPassphrase(t *testing.T) {
	m, _, bc := newTestManagerWithBarrier(t)
	ctx := context.Background()

	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{Name: "forward-pass-tenant"})
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	if err := m.InitTenantBarrier(ctx, entity.ID, []byte("operator-pass")); err != nil {
		t.Fatalf("InitTenantBarrier: %v", err)
	}

	bc.mu.Lock()
	defer bc.mu.Unlock()
	if n := len(bc.initPassphrases); n == 0 || string(bc.initPassphrases[n-1]) != "operator-pass" {
		t.Fatalf("init passphrases = %q, want the last to be %q", bc.initPassphrases, "operator-pass")
	}
	if unsealed, ok := bc.barriers[entity.ID]; !ok || unsealed {
		t.Errorf("barrier state = (%v, %v), want initialized and sealed", unsealed, ok)
	}
}

// TestInitTenantBarrier_NilBarrierClient verifies proper error when no
// barrier client is configured.
func TestInitTenantBarrier_NilBarrierClient(t *testing.T) {
	m, _ := newTestManager(t) // no barrier client
	ctx := context.Background()

	err := m.InitTenantBarrier(ctx, "some-tenant-id", []byte("operator-pass"))
	if err == nil {
		t.Fatal("expected error for nil barrier client")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got: %T", err)
	}
}

// TestInitTenantBarrier_TenantNotFound verifies proper error when tenant
// does not exist.
func TestInitTenantBarrier_TenantNotFound(t *testing.T) {
	m, _, _ := newTestManagerWithBarrier(t)
	ctx := context.Background()

	err := m.InitTenantBarrier(ctx, "nonexistent-tenant", []byte("operator-pass"))
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}

	var notFound ErrTenantNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrTenantNotFound, got: %T", err)
	}
}

// TestInitTenantBarrier_SDKError verifies barrier init error wrapping.
func TestInitTenantBarrier_SDKError(t *testing.T) {
	m, _, bc := newTestManagerWithBarrier(t)
	ctx := context.Background()

	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{
		Name: "sdk-error-tenant",
	})
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	// Inject error after creation
	bc.initErr = errors.New("sdk connection lost")

	err = m.InitTenantBarrier(ctx, entity.ID, []byte("operator-pass"))
	if err == nil {
		t.Fatal("expected error from SDK")
	}

	var barrierErr ErrBarrierOperationFailed
	if !errors.As(err, &barrierErr) {
		t.Errorf("expected ErrBarrierOperationFailed, got: %T", err)
	}
	if barrierErr.TenantID != entity.ID {
		t.Errorf("expected tenant ID %s, got %s", entity.ID, barrierErr.TenantID)
	}
	if barrierErr.Operation != "init" {
		t.Errorf("expected operation 'init', got '%s'", barrierErr.Operation)
	}
}

// ---------------------------------------------------------------------------
// UnsealTenantBarrier
// ---------------------------------------------------------------------------

// TestUnsealTenantBarrier_Success verifies explicit barrier unseal.
func TestUnsealTenantBarrier_Success(t *testing.T) {
	m, _, bc := newTestManagerWithBarrier(t)
	ctx := context.Background()

	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{
		Name: "unseal-test-tenant",
	})
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	err = m.UnsealTenantBarrier(ctx, entity.ID, []byte("test-key"))
	if err != nil {
		t.Fatalf("UnsealTenantBarrier failed: %v", err)
	}

	bc.mu.Lock()
	unsealed := bc.barriers[entity.ID]
	bc.mu.Unlock()

	if !unsealed {
		t.Error("barrier should be unsealed")
	}
}

// TestUnsealTenantBarrier_EmptyTenantID verifies proper error for empty ID.
func TestUnsealTenantBarrier_EmptyTenantID(t *testing.T) {
	m, _, _ := newTestManagerWithBarrier(t)
	ctx := context.Background()

	err := m.UnsealTenantBarrier(ctx, "", []byte("key"))
	if err == nil {
		t.Fatal("expected error for empty tenant ID")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got: %T", err)
	}
}

// TestUnsealTenantBarrier_EmptyKey verifies proper error for empty key.
func TestUnsealTenantBarrier_EmptyKey(t *testing.T) {
	m, _, _ := newTestManagerWithBarrier(t)
	ctx := context.Background()

	err := m.UnsealTenantBarrier(ctx, "some-tenant", nil)
	if err == nil {
		t.Fatal("expected error for empty key")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got: %T", err)
	}
}

// TestUnsealTenantBarrier_NilBarrierClient verifies proper error when no
// barrier client is configured.
func TestUnsealTenantBarrier_NilBarrierClient(t *testing.T) {
	m, _ := newTestManager(t) // no barrier client
	ctx := context.Background()

	err := m.UnsealTenantBarrier(ctx, "some-tenant", []byte("key"))
	if err == nil {
		t.Fatal("expected error for nil barrier client")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got: %T", err)
	}
}

// TestUnsealTenantBarrier_SDKError verifies unseal error wrapping.
func TestUnsealTenantBarrier_SDKError(t *testing.T) {
	m, _, bc := newTestManagerWithBarrier(t)
	ctx := context.Background()

	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{
		Name: "unseal-error-tenant",
	})
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	bc.unsealErr = errors.New("invalid unseal key")

	err = m.UnsealTenantBarrier(ctx, entity.ID, []byte("bad-key"))
	if err == nil {
		t.Fatal("expected error from SDK")
	}

	var barrierErr ErrBarrierOperationFailed
	if !errors.As(err, &barrierErr) {
		t.Errorf("expected ErrBarrierOperationFailed, got: %T", err)
	}
	if barrierErr.Operation != "unseal" {
		t.Errorf("expected operation 'unseal', got '%s'", barrierErr.Operation)
	}
}

// ---------------------------------------------------------------------------
// SealTenantBarrier
// ---------------------------------------------------------------------------

// TestSealTenantBarrier_Success verifies that seal succeeds against the SDK
// after the tenant barrier has been initialized, leaving the barrier in the
// sealed state.
func TestSealTenantBarrier_Success(t *testing.T) {
	m, _, barrierClient := newTestManagerWithBarrier(t)
	ctx := context.Background()

	if err := barrierClient.TenantBarrierInit(ctx, &quicbaassdk.QRDBTenantBarrierInitRequest{TenantID: "tenant-x", Passphrase: []byte("operator-pass")}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := barrierClient.TenantBarrierUnseal(ctx, &quicbaassdk.QRDBTenantBarrierUnsealRequest{TenantID: "tenant-x"}); err != nil {
		t.Fatalf("unseal: %v", err)
	}

	if err := m.SealTenantBarrier(ctx, "tenant-x"); err != nil {
		t.Fatalf("SealTenantBarrier: %v", err)
	}

	st, err := m.TenantBarrierStatus(ctx, "tenant-x")
	if err != nil {
		t.Fatalf("status after seal: %v", err)
	}
	if !st.Sealed {
		t.Errorf("expected sealed=true after Seal, got %+v", st)
	}
	if !st.Initialized {
		t.Errorf("expected initialized=true after Seal, got %+v", st)
	}
}

// TestSealTenantBarrier_EmptyTenantID verifies empty ID validation runs
// before the SDK call and returns ErrInvalidRequest.
func TestSealTenantBarrier_EmptyTenantID(t *testing.T) {
	m, _, _ := newTestManagerWithBarrier(t)
	ctx := context.Background()

	err := m.SealTenantBarrier(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty tenant ID")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got: %T", err)
	}
}

// TestSealTenantBarrier_NoClient verifies the not-supported guard fires when
// no barrier client has been wired into the manager.
func TestSealTenantBarrier_NoClient(t *testing.T) {
	m, _, _ := newTestManagerWithBarrier(t)
	m.tenantBarrierClient = nil

	err := m.SealTenantBarrier(context.Background(), "tenant-x")
	if err == nil {
		t.Fatal("expected not-supported error")
	}
	var notSupported ErrBarrierNotSupported
	if !errors.As(err, &notSupported) {
		t.Errorf("expected ErrBarrierNotSupported, got: %T", err)
	}
}

// TestSealTenantBarrier_SDKError wraps a transport error in ErrStorageFailed.
func TestSealTenantBarrier_SDKError(t *testing.T) {
	m, _, barrierClient := newTestManagerWithBarrier(t)
	barrierClient.sealErr = errors.New("transport down")

	err := m.SealTenantBarrier(context.Background(), "tenant-x")
	if err == nil {
		t.Fatal("expected error from SDK")
	}
	var storageErr ErrStorageFailed
	if !errors.As(err, &storageErr) {
		t.Errorf("expected ErrStorageFailed, got: %T", err)
	}
}

// ---------------------------------------------------------------------------
// TenantBarrierStatus
// ---------------------------------------------------------------------------

// TestTenantBarrierStatus_Uninitialized confirms that querying a tenant whose
// barrier was never initialized returns Sealed=true, Initialized=false rather
// than an error.
func TestTenantBarrierStatus_Uninitialized(t *testing.T) {
	m, _, _ := newTestManagerWithBarrier(t)
	ctx := context.Background()

	st, err := m.TenantBarrierStatus(ctx, "never-init")
	if err != nil {
		t.Fatalf("TenantBarrierStatus: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
	if !st.Sealed {
		t.Errorf("expected sealed=true for uninitialized barrier, got %+v", st)
	}
	if st.Initialized {
		t.Errorf("expected initialized=false for uninitialized barrier, got %+v", st)
	}
}

// TestTenantBarrierStatus_AfterUnseal verifies that an unsealed tenant
// barrier reports Sealed=false, Initialized=true with strategy metadata.
func TestTenantBarrierStatus_AfterUnseal(t *testing.T) {
	m, _, barrierClient := newTestManagerWithBarrier(t)
	ctx := context.Background()

	if err := barrierClient.TenantBarrierInit(ctx, &quicbaassdk.QRDBTenantBarrierInitRequest{TenantID: "tenant-y", Passphrase: []byte("operator-pass")}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := barrierClient.TenantBarrierUnseal(ctx, &quicbaassdk.QRDBTenantBarrierUnsealRequest{TenantID: "tenant-y"}); err != nil {
		t.Fatalf("unseal: %v", err)
	}

	st, err := m.TenantBarrierStatus(ctx, "tenant-y")
	if err != nil {
		t.Fatalf("TenantBarrierStatus: %v", err)
	}
	if st.Sealed {
		t.Errorf("expected sealed=false after unseal, got %+v", st)
	}
	if !st.Initialized {
		t.Errorf("expected initialized=true after init, got %+v", st)
	}
	if st.Strategy != "software" {
		t.Errorf("expected strategy=software, got %q", st.Strategy)
	}
}

// TestTenantBarrierStatus_EmptyTenantID verifies empty ID validation runs
// before the SDK call.
func TestTenantBarrierStatus_EmptyTenantID(t *testing.T) {
	m, _, _ := newTestManagerWithBarrier(t)
	ctx := context.Background()

	_, err := m.TenantBarrierStatus(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty tenant ID")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got: %T", err)
	}
}

// TestTenantBarrierStatus_NoClient verifies the not-supported guard fires
// when no barrier client has been wired.
func TestTenantBarrierStatus_NoClient(t *testing.T) {
	m, _, _ := newTestManagerWithBarrier(t)
	m.tenantBarrierClient = nil

	_, err := m.TenantBarrierStatus(context.Background(), "tenant-x")
	if err == nil {
		t.Fatal("expected not-supported error")
	}
	var notSupported ErrBarrierNotSupported
	if !errors.As(err, &notSupported) {
		t.Errorf("expected ErrBarrierNotSupported, got: %T", err)
	}
}

// TestTenantBarrierStatus_SDKError wraps a transport error in ErrStorageFailed.
func TestTenantBarrierStatus_SDKError(t *testing.T) {
	m, _, barrierClient := newTestManagerWithBarrier(t)
	barrierClient.statusErr = errors.New("transport down")

	_, err := m.TenantBarrierStatus(context.Background(), "tenant-x")
	if err == nil {
		t.Fatal("expected error from SDK")
	}
	var storageErr ErrStorageFailed
	if !errors.As(err, &storageErr) {
		t.Errorf("expected ErrStorageFailed, got: %T", err)
	}
}

func TestTenantBarrierStatus_PrefixTenantIsNotApplicable(t *testing.T) {
	m, _, barrierClient := newTestManagerWithBarrier(t)
	barrierClient.isolation = map[string]string{"prefix-tenant": ""}

	st, err := m.TenantBarrierStatus(context.Background(), "prefix-tenant")
	if err != nil {
		t.Fatalf("TenantBarrierStatus: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
	if st.Isolation != "prefix" {
		t.Errorf("Isolation = %q, want prefix", st.Isolation)
	}
	if st.Sealed || st.Initialized {
		t.Errorf("a prefix tenant has no barrier to be sealed or initialized, got %+v", st)
	}
	if st.TenantID != "prefix-tenant" {
		t.Errorf("TenantID = %q, want prefix-tenant", st.TenantID)
	}
	if barrierClient.statusCalls != 0 {
		t.Errorf("backend status called %d times for a tenant with no barrier", barrierClient.statusCalls)
	}
}

func TestTenantBarrierStatus_ReportsBarrierIsolation(t *testing.T) {
	m, _, barrierClient := newTestManagerWithBarrier(t)

	st, err := m.TenantBarrierStatus(context.Background(), "tenant-x")
	if err != nil {
		t.Fatalf("TenantBarrierStatus: %v", err)
	}
	if st.Isolation != "barrier" {
		t.Errorf("Isolation = %q, want barrier", st.Isolation)
	}
	if !st.Sealed {
		t.Errorf("an uninitialized barrier reports sealed, got %+v", st)
	}
	if barrierClient.statusCalls != 1 {
		t.Errorf("backend status calls = %d, want 1", barrierClient.statusCalls)
	}
}

func TestTenantBarrierStatus_IsolationLookupFailureFailsClosed(t *testing.T) {
	m, _, barrierClient := newTestManagerWithBarrier(t)
	barrierClient.isolationErr = errors.New("lookup down")

	st, err := m.TenantBarrierStatus(context.Background(), "tenant-x")
	if err == nil {
		t.Fatal("expected an error when the isolation lookup fails")
	}
	if st != nil {
		t.Errorf("expected no state on a failed lookup, got %+v", st)
	}
	var storageErr ErrStorageFailed
	if !errors.As(err, &storageErr) {
		t.Errorf("expected ErrStorageFailed, got: %T", err)
	}
	if barrierClient.statusCalls != 0 {
		t.Errorf("backend status called %d times after a failed lookup", barrierClient.statusCalls)
	}
}

// ---------------------------------------------------------------------------
// Error type tests
// ---------------------------------------------------------------------------

// TestErrBarrierOperationFailed_ErrorMessage verifies the error string format.
// TestErrBarrierNotSupported_ErrorMessage verifies the error string format.
