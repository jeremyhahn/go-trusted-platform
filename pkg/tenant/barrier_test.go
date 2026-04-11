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
// in-memory state tracking.
type testBarrierClient struct {
	mu       sync.Mutex
	barriers map[string]bool // tenantID -> unsealed

	initErr   error
	unsealErr error
}

func newTestBarrierClient() *testBarrierClient {
	return &testBarrierClient{
		barriers: make(map[string]bool),
	}
}

func (c *testBarrierClient) TenantBarrierInit(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierInitRequest) error {
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
		IAMTenantClient:           iamClient,
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
		IAMTenantClient:           iamClient,
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
		IAMTenantClient:           iamClient,
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

	if !bc.isInitialized(entity.ID) {
		t.Error("expected per-tenant barrier to be initialized")
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
func TestCreateTenant_SkipsBarrierWhenClientNil(t *testing.T) {
	m, _ := newTestManager(t) // no barrier client
	ctx := context.Background()

	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{
		Name: "no-barrier-tenant",
	})
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}
	if entity == nil {
		t.Fatal("expected non-nil entity")
	}
}

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

	if !bc.isInitialized(entity.ID) {
		t.Error("barrier should be initialized after create")
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

	err = m.InitTenantBarrier(ctx, entity.ID)
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

	err := m.InitTenantBarrier(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty tenant ID")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got: %T", err)
	}
}

// TestInitTenantBarrier_NilBarrierClient verifies proper error when no
// barrier client is configured.
func TestInitTenantBarrier_NilBarrierClient(t *testing.T) {
	m, _ := newTestManager(t) // no barrier client
	ctx := context.Background()

	err := m.InitTenantBarrier(ctx, "some-tenant-id")
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

	err := m.InitTenantBarrier(ctx, "nonexistent-tenant")
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

	err = m.InitTenantBarrier(ctx, entity.ID)
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

// TestSealTenantBarrier_NotSupported verifies that seal returns the
// not-supported error.
func TestSealTenantBarrier_NotSupported(t *testing.T) {
	m, _, _ := newTestManagerWithBarrier(t)
	ctx := context.Background()

	err := m.SealTenantBarrier(ctx, "some-tenant")
	if err == nil {
		t.Fatal("expected not-supported error")
	}

	var notSupported ErrBarrierNotSupported
	if !errors.As(err, &notSupported) {
		t.Errorf("expected ErrBarrierNotSupported, got: %T", err)
	}
}

// TestSealTenantBarrier_EmptyTenantID verifies empty ID validation runs
// before the not-supported check.
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

// ---------------------------------------------------------------------------
// TenantBarrierStatus
// ---------------------------------------------------------------------------

// TestTenantBarrierStatus_NotSupported verifies that status returns the
// not-supported error.
func TestTenantBarrierStatus_NotSupported(t *testing.T) {
	m, _, _ := newTestManagerWithBarrier(t)
	ctx := context.Background()

	_, err := m.TenantBarrierStatus(ctx, "some-tenant")
	if err == nil {
		t.Fatal("expected not-supported error")
	}

	var notSupported ErrBarrierNotSupported
	if !errors.As(err, &notSupported) {
		t.Errorf("expected ErrBarrierNotSupported, got: %T", err)
	}
}

// TestTenantBarrierStatus_EmptyTenantID verifies empty ID validation
// runs before the not-supported check.
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

// ---------------------------------------------------------------------------
// Error type tests
// ---------------------------------------------------------------------------

// TestErrBarrierOperationFailed_ErrorMessage verifies the error string format.
func TestErrBarrierOperationFailed_ErrorMessage(t *testing.T) {
	inner := errors.New("connection refused")
	err := ErrBarrierOperationFailed{
		TenantID:  "tenant-123",
		Operation: "init",
		Err:       inner,
	}

	expected := "barrier operation failed for tenant tenant-123: init: connection refused"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}

	if !errors.Is(err, inner) {
		t.Error("expected Unwrap to return inner error")
	}
}

// TestErrBarrierNotSupported_ErrorMessage verifies the error string format.
func TestErrBarrierNotSupported_ErrorMessage(t *testing.T) {
	err := ErrBarrierNotSupported{Operation: "SealTenantBarrier"}

	expected := "barrier operation not supported: SealTenantBarrier"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}
