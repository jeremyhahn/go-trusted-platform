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
	"log/slog"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
)

// mockIAMClient implements iam.TenantClient for testing.
type mockIAMClient struct {
	mu      sync.RWMutex
	tenants map[string]*iam.Tenant

	// Error injection
	createErr error
	getErr    error
	listErr   error
	updateErr error
	deleteErr error

	// Role reconcile state: the roles each tenant carries, and how many
	// Reconcile calls wrote something.
	roles          map[string][]string
	reconcileCalls int
	reconcileErr   error
}

// mockBuiltInRoles mirrors the built-in role set the IAM role reconciler
// seeds into a tenant.
var mockBuiltInRoles = []string{"so", "admin", "operator", "user", "auditor", "custodian"}

func newMockIAMClient() *mockIAMClient {
	return &mockIAMClient{
		tenants: make(map[string]*iam.Tenant),
		roles:   make(map[string][]string),
	}
}

// Reconcile implements RoleReconciler the way the IAM server does: absent
// built-in roles are created and reported, present ones are left alone.
func (m *mockIAMClient) Reconcile(_ context.Context, tenantID string) (*iam.ReconcileRolesResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.reconcileCalls++
	if m.reconcileErr != nil {
		return nil, m.reconcileErr
	}

	resp := &iam.ReconcileRolesResponse{TenantID: tenantID}
	if len(m.roles[tenantID]) == 0 {
		m.roles[tenantID] = append([]string(nil), mockBuiltInRoles...)
		for _, name := range mockBuiltInRoles {
			resp.Roles = append(resp.Roles, iam.RoleReconcileResult{RoleID: name, Name: name, Created: true})
		}
		resp.Changed = true
	}
	return resp, nil
}

func (m *mockIAMClient) tenantRoles(tenantID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.roles[tenantID]...)
}

func (m *mockIAMClient) Create(ctx context.Context, req *iam.CreateTenantRequest) (*iam.Tenant, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicate name
	for _, t := range m.tenants {
		if t.Name == req.Name {
			return nil, errors.New("tenant already exists")
		}
	}

	id := req.ID
	if id == "" {
		id = req.Name + "-id"
	}

	now := time.Now()
	tenant := &iam.Tenant{
		ID:          id,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	m.tenants[tenant.ID] = tenant

	return tenant, nil
}

func (m *mockIAMClient) Get(ctx context.Context, tenantID string) (*iam.Tenant, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	tenant, ok := m.tenants[tenantID]
	if !ok {
		return nil, errors.New("tenant not found")
	}

	return tenant, nil
}

func (m *mockIAMClient) List(ctx context.Context, req *iam.ListTenantsRequest) (*iam.ListTenantsResponse, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	tenants := make([]iam.Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		tenants = append(tenants, *t)
	}

	return &iam.ListTenantsResponse{
		Tenants: tenants,
		Pagination: iam.PaginationInfo{
			TotalCount: len(tenants),
		},
	}, nil
}

func (m *mockIAMClient) Update(ctx context.Context, tenantID string, req *iam.UpdateTenantRequest) (*iam.Tenant, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	tenant, ok := m.tenants[tenantID]
	if !ok {
		return nil, errors.New("tenant not found")
	}

	if req.DisplayName != "" {
		tenant.DisplayName = req.DisplayName
	}
	tenant.UpdatedAt = time.Now()

	return tenant, nil
}

func (m *mockIAMClient) Delete(ctx context.Context, tenantID string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.tenants[tenantID]; !ok {
		return errors.New("tenant not found")
	}

	delete(m.tenants, tenantID)

	return nil
}

// mockDEKData holds per-tenant DEK metadata for the mock.
type mockDEKData struct {
	TenantID  string
	DEKID     string
	Algorithm string
	Version   uint64
	CreatedAt time.Time
	RotatedAt time.Time
}

// mockDEKClient implements the platform TenantDEKClient boundary for
// testing. It performs no cryptography — the real DEK semantics are owned by
// the quicbaas server — and only records the tenant -> DEK bookkeeping the
// manager relies on.
type mockDEKClient struct {
	mu   sync.RWMutex
	deks map[string]*mockDEKData // keyed by tenant ID

	// Error injection
	createErr    error
	rotateErr    error
	deleteErr    error
	getStatusErr error

	// For testing re-encryption progress
	reencryptionInProgress bool
}

func newMockDEKClient() *mockDEKClient {
	return &mockDEKClient{
		deks: make(map[string]*mockDEKData),
	}
}

func (m *mockDEKClient) EnsureTenantDEK(ctx context.Context, req *EnsureTenantDEKRequest) (*EnsureTenantDEKResponse, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	dekID := "dek:tenant:" + req.TenantID
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "aes-256-gcm"
	}

	if existing, ok := m.deks[req.TenantID]; ok {
		return &EnsureTenantDEKResponse{
			DEKID:     existing.DEKID,
			Created:   false,
			Algorithm: existing.Algorithm,
			CreatedAt: existing.CreatedAt,
		}, nil
	}

	now := time.Now()
	m.deks[req.TenantID] = &mockDEKData{
		TenantID:  req.TenantID,
		DEKID:     dekID,
		Algorithm: algorithm,
		Version:   1,
		CreatedAt: now,
	}

	return &EnsureTenantDEKResponse{
		DEKID:     dekID,
		Created:   true,
		Algorithm: algorithm,
		CreatedAt: now,
	}, nil
}

func (m *mockDEKClient) DeleteTenantDEK(ctx context.Context, req *DeleteTenantDEKRequest) (*DeleteTenantDEKResponse, error) {
	if m.deleteErr != nil {
		return nil, m.deleteErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	dek, ok := m.deks[req.TenantID]
	if !ok {
		return nil, errors.New("tenant DEK not found")
	}

	delete(m.deks, req.TenantID)

	return &DeleteTenantDEKResponse{
		DEKID:     dek.DEKID,
		DeletedAt: time.Now(),
	}, nil
}

func (m *mockDEKClient) RotateTenantDEK(ctx context.Context, req *RotateTenantDEKRequest) (*RotateTenantDEKResponse, error) {
	if m.rotateErr != nil {
		return nil, m.rotateErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	dek, ok := m.deks[req.TenantID]
	if !ok {
		return nil, errors.New("no DEK to rotate")
	}

	oldVersion := dek.Version
	dek.Version++
	dek.RotatedAt = time.Now()

	return &RotateTenantDEKResponse{
		OldVersion: oldVersion,
		NewVersion: dek.Version,
		RotatedAt:  dek.RotatedAt,
	}, nil
}

func (m *mockDEKClient) TenantDEKStatus(ctx context.Context, req *TenantDEKStatusRequest) (*TenantDEKStatusResponse, error) {
	if m.getStatusErr != nil {
		return nil, m.getStatusErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	resp := &TenantDEKStatusResponse{
		CurrentVersion:         1,
		CreatedAt:              time.Now(),
		Algorithm:              "aes-256-gcm",
		ReencryptionInProgress: m.reencryptionInProgress,
	}

	if dek, ok := m.deks[req.TenantID]; ok {
		resp.CurrentVersion = dek.Version
		resp.Algorithm = dek.Algorithm
		resp.CreatedAt = dek.CreatedAt
		if !dek.RotatedAt.IsZero() {
			rotatedAt := dek.RotatedAt
			resp.RotatedAt = &rotatedAt
		}
	}

	return resp, nil
}

// mockQuotaStore implements quota.QuotaStore for testing.
type mockQuotaStore struct {
	mu     sync.RWMutex
	quotas map[string]*quota.TenantQuotas
	usage  map[string]*quota.TenantUsage

	getQuotaErr    error
	updateQuotaErr error
	getUsageErr    error
	updateUsageErr error
}

func newMockQuotaStore() *mockQuotaStore {
	return &mockQuotaStore{
		quotas: make(map[string]*quota.TenantQuotas),
		usage:  make(map[string]*quota.TenantUsage),
	}
}

func (m *mockQuotaStore) GetQuota(ctx context.Context, tenantID string) (*quota.TenantQuotas, error) {
	if m.getQuotaErr != nil {
		return nil, m.getQuotaErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	q, ok := m.quotas[tenantID]
	if !ok {
		return nil, nil
	}
	return q, nil
}

func (m *mockQuotaStore) UpdateQuota(ctx context.Context, tenantID string, quotas *quota.TenantQuotas) error {
	if m.updateQuotaErr != nil {
		return m.updateQuotaErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.quotas[tenantID] = quotas
	return nil
}

func (m *mockQuotaStore) GetUsage(ctx context.Context, tenantID string) (*quota.TenantUsage, error) {
	if m.getUsageErr != nil {
		return nil, m.getUsageErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	u, ok := m.usage[tenantID]
	if !ok {
		return &quota.TenantUsage{TenantID: tenantID}, nil
	}
	return u, nil
}

func (m *mockQuotaStore) UpdateUsage(ctx context.Context, tenantID string, usage *quota.TenantUsage) error {
	if m.updateUsageErr != nil {
		return m.updateUsageErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.usage[tenantID] = usage
	return nil
}

// setTenantQuota sets quotas for a tenant in the mock store.
func (m *mockQuotaStore) setTenantQuota(tenantID string, quotas *quota.TenantQuotas) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.quotas[tenantID] = quotas
}

// setTenantUsage sets usage for a tenant in the mock store.
func (m *mockQuotaStore) setTenantUsage(tenantID string, usage *quota.TenantUsage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.usage[tenantID] = usage
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Only show errors during tests
	}))
}

func newTestManager(t *testing.T) (*Manager, *mockIAMClient) {
	t.Helper()

	iamClient := newMockIAMClient()
	logger := newTestLogger()

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		Config:          DefaultConfig(),
		Logger:          logger,
	}

	// Disable DEK isolation for basic tests
	cfg.Config.EnableDEKIsolation = false

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	return manager, iamClient
}

// newTestManagerWithQuota creates a manager with quota enforcer and tracker.
func newTestManagerWithQuota(t *testing.T) (*Manager, *mockIAMClient, *mockQuotaStore) {
	t.Helper()

	iamClient := newMockIAMClient()
	quotaStore := newMockQuotaStore()
	logger := newTestLogger()

	enforcer, err := quota.NewEnforcer(quotaStore, logger)
	if err != nil {
		t.Fatalf("failed to create quota enforcer: %v", err)
	}

	tracker, err := quota.NewTracker(quotaStore, logger)
	if err != nil {
		t.Fatalf("failed to create quota tracker: %v", err)
	}

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		QuotaEnforcer:   enforcer,
		UsageTracker:    tracker,
		Config:          DefaultConfig(),
		Logger:          logger,
	}

	cfg.Config.EnableDEKIsolation = false

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	return manager, iamClient, quotaStore
}

func TestNewManager_Success(t *testing.T) {
	iamClient := newMockIAMClient()
	logger := newTestLogger()

	config := DefaultConfig()
	config.EnableDEKIsolation = false

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		Config:          config,
		Logger:          logger,
	}

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if manager == nil {
		t.Fatal("expected manager to be non-nil")
	}

	if manager.iamTenantClient != iamClient {
		t.Error("expected IAM client to be set")
	}
}

func TestNewManager_NilConfig(t *testing.T) {
	_, err := NewManager(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

func TestNewManager_NilIAMClient(t *testing.T) {
	cfg := &ManagerConfig{
		IAMTenantClient: nil,
		Config:          DefaultConfig(),
	}

	_, err := NewManager(cfg)
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

func TestNewManager_NilIAMRoleClient(t *testing.T) {
	cfg := &ManagerConfig{
		IAMTenantClient: newMockIAMClient(),
		Config:          DefaultConfig(),
	}

	_, err := NewManager(cfg)

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Fatalf("expected ErrInvalidRequest for nil IAM role client, got %v", err)
	}
}

func TestNewManager_DefaultConfig(t *testing.T) {
	iamClient := newMockIAMClient()

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		DEKClient:       newMockDEKClient(),
		Config:          nil, // Should use defaults
	}

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if manager.config == nil {
		t.Fatal("expected config to be set to defaults")
	}
}

func TestNewManager_DefaultLogger(t *testing.T) {
	iamClient := newMockIAMClient()

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		DEKClient:       newMockDEKClient(),
		Config:          DefaultConfig(),
		Logger:          nil, // Should use default
	}

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if manager.logger == nil {
		t.Fatal("expected logger to be set to default")
	}
}

// Tests for CreateTenant

func TestCreateTenant_Success(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	req := &CreateTenantRequest{
		Name:        "test-tenant",
		DisplayName: "Test Tenant",
		Labels: map[string]string{
			"env": "test",
		},
	}

	entity, err := manager.CreateTenant(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity == nil {
		t.Fatal("expected entity to be non-nil")
	}

	if entity.Name != req.Name {
		t.Errorf("expected name %q, got %q", req.Name, entity.Name)
	}

	if entity.DisplayName != req.DisplayName {
		t.Errorf("expected display name %q, got %q", req.DisplayName, entity.DisplayName)
	}

	if entity.State != StateActive {
		t.Errorf("expected state %q, got %q", StateActive, entity.State)
	}

	if entity.Labels["env"] != "test" {
		t.Error("expected labels to be set")
	}
}

func TestCreateTenant_NilRequest(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	_, err := manager.CreateTenant(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

func TestCreateTenant_EmptyName(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	req := &CreateTenantRequest{
		Name: "",
	}

	_, err := manager.CreateTenant(ctx, req)
	if err == nil {
		t.Fatal("expected error for empty name")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

func TestCreateTenant_DuplicateName(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	req := &CreateTenantRequest{
		Name: "test-tenant",
	}

	// Create first tenant
	_, err := manager.CreateTenant(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Try to create duplicate
	_, err = manager.CreateTenant(ctx, req)
	if err == nil {
		t.Fatal("expected error for duplicate tenant")
	}

	var tenantExists ErrTenantExists
	if !errors.As(err, &tenantExists) {
		t.Errorf("expected ErrTenantExists, got %T: %v", err, err)
	}
}

func TestCreateTenant_WithCustomQuotas(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	customCompute := &ComputeQuota{
		MaxVMs:      20,
		MaxVCPUs:    64,
		MaxMemoryMB: 131072,
	}

	req := &CreateTenantRequest{
		Name:         "test-tenant",
		ComputeQuota: customCompute,
	}

	entity, err := manager.CreateTenant(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity.ComputeQuota.MaxVMs != customCompute.MaxVMs {
		t.Errorf("expected MaxVMs %d, got %d", customCompute.MaxVMs, entity.ComputeQuota.MaxVMs)
	}

	if entity.ComputeQuota.MaxVCPUs != customCompute.MaxVCPUs {
		t.Errorf("expected MaxVCPUs %d, got %d", customCompute.MaxVCPUs, entity.ComputeQuota.MaxVCPUs)
	}
}

func TestCreateTenant_WithAllCustomQuotas(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	customCompute := &ComputeQuota{
		MaxVMs:        20,
		MaxContainers: 50,
		MaxVCPUs:      64,
		MaxMemoryMB:   131072,
	}

	customNetwork := &NetworkQuota{
		MaxBridges:       5,
		MaxPorts:         100,
		MaxBandwidthMbps: 10000,
	}

	customStorage := &StorageQuota{
		MaxVolumesGB: 1000,
		MaxSnapshots: 50,
	}

	req := &CreateTenantRequest{
		Name:         "test-tenant",
		ComputeQuota: customCompute,
		NetworkQuota: customNetwork,
		StorageQuota: customStorage,
	}

	entity, err := manager.CreateTenant(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity.ComputeQuota.MaxContainers != customCompute.MaxContainers {
		t.Errorf("expected MaxContainers %d, got %d", customCompute.MaxContainers, entity.ComputeQuota.MaxContainers)
	}

	if entity.NetworkQuota.MaxBridges != customNetwork.MaxBridges {
		t.Errorf("expected MaxBridges %d, got %d", customNetwork.MaxBridges, entity.NetworkQuota.MaxBridges)
	}

	if entity.StorageQuota.MaxVolumesGB != customStorage.MaxVolumesGB {
		t.Errorf("expected MaxVolumesGB %d, got %d", customStorage.MaxVolumesGB, entity.StorageQuota.MaxVolumesGB)
	}
}

func TestCreateTenant_IAMError(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	// Inject error
	iamClient.createErr = errors.New("IAM service unavailable")

	req := &CreateTenantRequest{
		Name: "test-tenant",
	}

	_, err := manager.CreateTenant(ctx, req)
	if err == nil {
		t.Fatal("expected error when IAM fails")
	}

	var storageFailed ErrStorageFailed
	if !errors.As(err, &storageFailed) {
		t.Errorf("expected ErrStorageFailed, got %T", err)
	}
}

func TestCreateTenant_ProvisionsDefaultRoles(t *testing.T) {
	manager, iamClient := newTestManager(t)

	entity, err := manager.CreateTenant(context.Background(), &CreateTenantRequest{Name: "roles-tenant"})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	roles := iamClient.tenantRoles(entity.ID)
	if len(roles) != len(mockBuiltInRoles) {
		t.Fatalf("new tenant carries roles %v, want %v", roles, mockBuiltInRoles)
	}
	if !slices.Contains(roles, "admin") {
		t.Errorf("new tenant lacks the admin role the owner is mirrored with: %v", roles)
	}
}

func TestCreateTenant_DefaultRolesFailureRollsBackIAMTenant(t *testing.T) {
	manager, iamClient := newTestManager(t)
	iamClient.reconcileErr = errors.New("role store unavailable")

	_, err := manager.CreateTenant(context.Background(), &CreateTenantRequest{Name: "no-roles"})

	var rolesFailed ErrDefaultRolesFailed
	if !errors.As(err, &rolesFailed) {
		t.Fatalf("expected ErrDefaultRolesFailed, got %v", err)
	}
	if !errors.Is(err, iamClient.reconcileErr) {
		t.Errorf("ErrDefaultRolesFailed does not wrap the SDK error: %v", err)
	}

	iamClient.mu.RLock()
	remaining := len(iamClient.tenants)
	iamClient.mu.RUnlock()
	if remaining != 0 {
		t.Errorf("IAM tenant left behind after role provisioning failed: %d tenants", remaining)
	}
}

func TestEnsureDefaultRoles_Idempotent(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	if err := manager.EnsureDefaultRoles(ctx, "tenant-a"); err != nil {
		t.Fatalf("first EnsureDefaultRoles: %v", err)
	}
	first := iamClient.tenantRoles("tenant-a")

	if err := manager.EnsureDefaultRoles(ctx, "tenant-a"); err != nil {
		t.Fatalf("second EnsureDefaultRoles: %v", err)
	}
	second := iamClient.tenantRoles("tenant-a")

	if !slices.Equal(first, second) {
		t.Errorf("second provisioning changed the roles: %v -> %v", first, second)
	}
	if iamClient.reconcileCalls != 2 {
		t.Errorf("Reconcile calls = %d, want 2", iamClient.reconcileCalls)
	}
}

func TestEnsureDefaultRoles_Errors(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	var invalidReq ErrInvalidRequest
	if err := manager.EnsureDefaultRoles(ctx, ""); !errors.As(err, &invalidReq) {
		t.Errorf("empty tenant ID: expected ErrInvalidRequest, got %v", err)
	}
	if iamClient.reconcileCalls != 0 {
		t.Errorf("empty tenant ID reached the SDK")
	}

	iamClient.reconcileErr = errors.New("permission denied")
	err := manager.EnsureDefaultRoles(ctx, "tenant-b")
	var rolesFailed ErrDefaultRolesFailed
	if !errors.As(err, &rolesFailed) || rolesFailed.TenantID != "tenant-b" {
		t.Fatalf("expected ErrDefaultRolesFailed for tenant-b, got %v", err)
	}
}

func TestCreateTenant_DefaultDisplayName(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	req := &CreateTenantRequest{
		Name:        "test-tenant",
		DisplayName: "", // Should default to Name
	}

	entity, err := manager.CreateTenant(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity.DisplayName != req.Name {
		t.Errorf("expected display name to default to %q, got %q", req.Name, entity.DisplayName)
	}
}

func TestCreateTenant_WithAnnotations(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	req := &CreateTenantRequest{
		Name: "test-tenant",
		Annotations: map[string]string{
			"description": "Test tenant for unit tests",
		},
	}

	entity, err := manager.CreateTenant(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity.Annotations["description"] != "Test tenant for unit tests" {
		t.Error("expected annotations to be set")
	}
}

// Tests for GetTenant

func TestGetTenant_Success(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Create tenant first
	createReq := &CreateTenantRequest{
		Name:        "test-tenant",
		DisplayName: "Test Tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Get tenant
	entity, err := manager.GetTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity.ID != created.ID {
		t.Errorf("expected ID %q, got %q", created.ID, entity.ID)
	}

	if entity.Name != created.Name {
		t.Errorf("expected name %q, got %q", created.Name, entity.Name)
	}
}

func TestGetTenant_EmptyID(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	_, err := manager.GetTenant(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty ID")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

func TestGetTenant_NotFound(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	_, err := manager.GetTenant(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}

	var notFound ErrTenantNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrTenantNotFound, got %T", err)
	}
}

func TestGetTenant_FromCache(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Create tenant
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// First get - should be from cache
	entity1, err := manager.GetTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Second get - should also be from cache
	entity2, err := manager.GetTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify both are clones (different pointers)
	if entity1 == entity2 {
		t.Error("expected entities to be clones, not same pointer")
	}

	if entity1.ID != entity2.ID {
		t.Error("expected same ID from cache")
	}
}

func TestGetTenant_FromIAMAfterCacheInvalidation(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Create tenant
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Invalidate cache
	manager.InvalidateCache(created.ID)

	// Get tenant - should fetch from IAM
	entity, err := manager.GetTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity.ID != created.ID {
		t.Errorf("expected ID %q, got %q", created.ID, entity.ID)
	}

	// Verify cache is populated again
	if manager.GetCacheSize() != 1 {
		t.Errorf("expected cache size 1, got %d", manager.GetCacheSize())
	}
}

func TestGetTenantByName_Success(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	entity, err := manager.GetTenantByName(ctx, "test-tenant")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity.ID != created.ID {
		t.Errorf("expected ID %q, got %q", created.ID, entity.ID)
	}
}

func TestGetTenantByName_EmptyName(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	_, err := manager.GetTenantByName(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty name")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

func TestGetTenantByName_NotFound(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	_, err := manager.GetTenantByName(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}

	var notFound ErrTenantNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrTenantNotFound, got %T", err)
	}
}

func TestGetTenantByName_FromCache(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Get by name - should be from cache (tenant is in cache after creation)
	entity, err := manager.GetTenantByName(ctx, "test-tenant")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity.ID != created.ID {
		t.Errorf("expected ID %q, got %q", created.ID, entity.ID)
	}
}

func TestGetTenantByName_FromIAMAfterCacheInvalidation(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Invalidate all cache
	manager.InvalidateCache("")

	// Get by name - should fetch from IAM
	entity, err := manager.GetTenantByName(ctx, "test-tenant")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity.ID != created.ID {
		t.Errorf("expected ID %q, got %q", created.ID, entity.ID)
	}

	// Verify cache is populated
	if manager.GetCacheSize() != 1 {
		t.Errorf("expected cache size 1, got %d", manager.GetCacheSize())
	}
}

func TestGetTenantByName_IAMListError(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	// Inject list error - this will cause GetTenantByName to fail when not in cache
	iamClient.listErr = errors.New("IAM list unavailable")

	_, err := manager.GetTenantByName(ctx, "test-tenant")
	if err == nil {
		t.Fatal("expected error when IAM list fails")
	}
}

// Tests for ListTenants

func TestListTenants_Empty(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	tenants, total, err := manager.ListTenants(ctx, 10, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(tenants) != 0 {
		t.Errorf("expected 0 tenants, got %d", len(tenants))
	}

	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
}

func TestListTenants_WithTenants(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Create some tenants
	for i := 0; i < 3; i++ {
		req := &CreateTenantRequest{
			Name: "test-tenant-" + string(rune('a'+i)),
		}
		_, err := manager.CreateTenant(ctx, req)
		if err != nil {
			t.Fatalf("failed to create tenant: %v", err)
		}
	}

	tenants, total, err := manager.ListTenants(ctx, 10, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(tenants) != 3 {
		t.Errorf("expected 3 tenants, got %d", len(tenants))
	}

	if total != 3 {
		t.Errorf("expected total 3, got %d", total)
	}
}

// A list must not replace the platform's cached tenant with IAM's bare
// projection: IAM carries no lifecycle state, quotas or labels, so a
// clobbered tenant reads back "created" and can no longer be suspended.
func TestListTenants_KeepsCachedTenantState(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	quota := ComputeQuota{MaxVMs: 100}
	created, err := manager.CreateTenant(ctx, &CreateTenantRequest{
		Name:         "listed-tenant",
		Labels:       map[string]string{"team": "a"},
		ComputeQuota: &quota,
	})
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	tenants, _, err := manager.ListTenants(ctx, 10, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(tenants) != 1 || tenants[0].State != StateActive {
		t.Fatalf("expected one active tenant in the list, got %+v", tenants)
	}

	got, err := manager.GetTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to get tenant: %v", err)
	}
	if got.State != StateActive {
		t.Errorf("expected state %q after list, got %q", StateActive, got.State)
	}
	if got.ComputeQuota.MaxVMs != 100 {
		t.Errorf("expected MaxVMs 100 after list, got %d", got.ComputeQuota.MaxVMs)
	}
	if got.Labels["team"] != "a" {
		t.Errorf("expected label team=a after list, got %v", got.Labels)
	}

	if err := manager.SuspendTenant(ctx, created.ID); err != nil {
		t.Errorf("expected suspend after list to succeed, got %v", err)
	}
}

func TestListTenants_DefaultLimit(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Pass invalid limit
	_, _, err := manager.ListTenants(ctx, -1, 0)
	if err != nil {
		t.Fatalf("expected no error with default limit, got %v", err)
	}
}

func TestListTenants_NegativeOffset(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Pass negative offset - should default to 0
	_, _, err := manager.ListTenants(ctx, 10, -5)
	if err != nil {
		t.Fatalf("expected no error with default offset, got %v", err)
	}
}

func TestListTenants_IAMError(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	// Inject list error
	iamClient.listErr = errors.New("IAM service unavailable")

	_, _, err := manager.ListTenants(ctx, 10, 0)
	if err == nil {
		t.Fatal("expected error when IAM fails")
	}

	var storageFailed ErrStorageFailed
	if !errors.As(err, &storageFailed) {
		t.Errorf("expected ErrStorageFailed, got %T", err)
	}
}

func TestUpdateTenant_Success(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name:        "test-tenant",
		DisplayName: "Original Name",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	newDisplayName := "Updated Name"
	updateReq := &UpdateTenantRequest{
		DisplayName: &newDisplayName,
		Labels: map[string]string{
			"updated": "true",
		},
	}

	updated, err := manager.UpdateTenant(ctx, created.ID, updateReq)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if updated.DisplayName != newDisplayName {
		t.Errorf("expected display name %q, got %q", newDisplayName, updated.DisplayName)
	}

	if updated.Labels["updated"] != "true" {
		t.Error("expected labels to be updated")
	}
}

func TestUpdateTenant_EmptyID(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	_, err := manager.UpdateTenant(ctx, "", &UpdateTenantRequest{})
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestUpdateTenant_NilRequest(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	_, err := manager.UpdateTenant(ctx, "some-id", nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestUpdateTenant_NotFound(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	_, err := manager.UpdateTenant(ctx, "nonexistent-id", &UpdateTenantRequest{})
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestUpdateTenant_WithAnnotations(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	updateReq := &UpdateTenantRequest{
		Annotations: map[string]string{
			"note": "updated annotation",
		},
	}

	updated, err := manager.UpdateTenant(ctx, created.ID, updateReq)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if updated.Annotations["note"] != "updated annotation" {
		t.Error("expected annotations to be updated")
	}
}

func TestUpdateTenant_IAMError(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Inject update error
	iamClient.updateErr = errors.New("IAM update failed")

	newDisplayName := "Updated Name"
	updateReq := &UpdateTenantRequest{
		DisplayName: &newDisplayName,
	}

	_, err = manager.UpdateTenant(ctx, created.ID, updateReq)
	if err == nil {
		t.Fatal("expected error when IAM fails")
	}

	var storageFailed ErrStorageFailed
	if !errors.As(err, &storageFailed) {
		t.Errorf("expected ErrStorageFailed, got %T", err)
	}
}

// Tests for DeleteTenant

func TestDeleteTenant_Success(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	err = manager.DeleteTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify deleted
	_, err = manager.GetTenant(ctx, created.ID)
	if err == nil {
		t.Fatal("expected error getting deleted tenant")
	}
}

func TestDeleteTenant_EmptyID(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	err := manager.DeleteTenant(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestDeleteTenant_NotFound(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	err := manager.DeleteTenant(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestDeleteTenant_IAMError(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Inject delete error
	iamClient.deleteErr = errors.New("IAM delete failed")

	err = manager.DeleteTenant(ctx, created.ID)
	if err == nil {
		t.Fatal("expected error when IAM fails")
	}

	var storageFailed ErrStorageFailed
	if !errors.As(err, &storageFailed) {
		t.Errorf("expected ErrStorageFailed, got %T", err)
	}
}

func TestDeleteTenant_WithUsageTrackerInvalidation(t *testing.T) {
	manager, _, _ := newTestManagerWithQuota(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	err = manager.DeleteTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify cache is invalidated
	if manager.GetCacheSize() != 0 {
		t.Errorf("expected cache size 0 after deletion, got %d", manager.GetCacheSize())
	}
}

// Tests for SuspendTenant

func TestSuspendTenant_Success(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	err = manager.SuspendTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify state
	entity, err := manager.GetTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to get tenant: %v", err)
	}

	if entity.State != StateSuspended {
		t.Errorf("expected state %q, got %q", StateSuspended, entity.State)
	}
}

func TestSuspendTenant_EmptyID(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	err := manager.SuspendTenant(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestSuspendTenant_NotFound(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	err := manager.SuspendTenant(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestSuspendTenant_AlreadySuspended(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Suspend first time
	err = manager.SuspendTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Suspend again - should succeed (idempotent operation)
	// The state machine allows same-state transitions for idempotency
	err = manager.SuspendTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error for idempotent suspend, got %v", err)
	}

	// Verify still suspended
	entity, err := manager.GetTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to get tenant: %v", err)
	}

	if entity.State != StateSuspended {
		t.Errorf("expected state %q, got %q", StateSuspended, entity.State)
	}
}

// Tests for ResumeTenant

func TestResumeTenant_Success(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Suspend first
	err = manager.SuspendTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to suspend tenant: %v", err)
	}

	// Resume
	err = manager.ResumeTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify state
	entity, err := manager.GetTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to get tenant: %v", err)
	}

	if entity.State != StateActive {
		t.Errorf("expected state %q, got %q", StateActive, entity.State)
	}
}

func TestResumeTenant_NotSuspended(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Try to resume without suspending
	err = manager.ResumeTenant(ctx, created.ID)
	if err == nil {
		t.Fatal("expected error resuming non-suspended tenant")
	}

	var invalidTransition ErrInvalidTransition
	if !errors.As(err, &invalidTransition) {
		t.Errorf("expected ErrInvalidTransition, got %T", err)
	}
}

func TestResumeTenant_EmptyID(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	err := manager.ResumeTenant(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestResumeTenant_NotFound(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	err := manager.ResumeTenant(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

// Tests for GetQuotas

func TestGetQuotas_Success(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	quotas, err := manager.GetQuotas(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if quotas == nil {
		t.Fatal("expected quotas to be non-nil")
	}

	// Should have default quotas
	defaults := DefaultConfig()
	if quotas.Compute.MaxVMs != defaults.DefaultComputeQuota.MaxVMs {
		t.Errorf("expected default MaxVMs %d, got %d",
			defaults.DefaultComputeQuota.MaxVMs, quotas.Compute.MaxVMs)
	}
}

func TestGetQuotas_NotFound(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	_, err := manager.GetQuotas(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

// Tests for UpdateQuotas

func TestUpdateQuotas_Success(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	newQuotas := &TenantQuotas{
		Compute: ComputeQuota{
			MaxVMs:   100,
			MaxVCPUs: 200,
		},
	}

	err = manager.UpdateQuotas(ctx, created.ID, newQuotas)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify
	quotas, err := manager.GetQuotas(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to get quotas: %v", err)
	}

	if quotas.Compute.MaxVMs != 100 {
		t.Errorf("expected MaxVMs 100, got %d", quotas.Compute.MaxVMs)
	}
}

// TestUpdateQuotas_KeepsUsageCounters proves an update takes only limits
// from the request: the stored usage counters survive, and a request
// carrying usage cannot overwrite them.
func TestUpdateQuotas_KeepsUsageCounters(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	created, err := manager.CreateTenant(ctx, &CreateTenantRequest{Name: "usage-tenant"})
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	cached, ok := manager.cache.Load(created.ID)
	if !ok {
		t.Fatalf("tenant %s not cached", created.ID)
	}
	entity := cached.(*TenantEntity).Clone()
	entity.ComputeQuota = ComputeQuota{MaxVMs: 10, MaxDiskGB: 500, UsedVMs: 3, UsedDiskGB: 120}
	entity.NetworkQuota = NetworkQuota{MaxBridges: 4, UsedBridges: 2, UsedPorts: 7}
	entity.StorageQuota = StorageQuota{MaxVolumesGB: 900, UsedVolumesGB: 250, UsedSnapshots: 5}
	manager.cache.Store(created.ID, entity)

	update := &TenantQuotas{
		Compute: ComputeQuota{MaxVMs: 20, MaxDiskGB: 600, UsedVMs: 99, UsedDiskGB: 99},
		Network: NetworkQuota{MaxBridges: 8, UsedBridges: 99},
		Storage: StorageQuota{MaxVolumesGB: 1000, UsedVolumesGB: 99},
	}
	if err := manager.UpdateQuotas(ctx, created.ID, update); err != nil {
		t.Fatalf("UpdateQuotas: %v", err)
	}

	got, err := manager.GetQuotas(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetQuotas: %v", err)
	}

	wantCompute := ComputeQuota{MaxVMs: 20, MaxDiskGB: 600, UsedVMs: 3, UsedDiskGB: 120}
	if got.Compute != wantCompute {
		t.Errorf("compute = %+v, want %+v", got.Compute, wantCompute)
	}
	wantNetwork := NetworkQuota{MaxBridges: 8, UsedBridges: 2, UsedPorts: 7}
	if got.Network != wantNetwork {
		t.Errorf("network = %+v, want %+v", got.Network, wantNetwork)
	}
	wantStorage := StorageQuota{MaxVolumesGB: 1000, UsedVolumesGB: 250, UsedSnapshots: 5}
	if got.Storage != wantStorage {
		t.Errorf("storage = %+v, want %+v", got.Storage, wantStorage)
	}
}

func TestUpdateQuotas_NilQuotas(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	err := manager.UpdateQuotas(ctx, "some-id", nil)
	if err == nil {
		t.Fatal("expected error for nil quotas")
	}
}

func TestUpdateQuotas_NotFound(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	newQuotas := &TenantQuotas{
		Compute: ComputeQuota{
			MaxVMs: 100,
		},
	}

	err := manager.UpdateQuotas(ctx, "nonexistent-id", newQuotas)
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

// Tests for GetUsage

func TestGetUsage_Success(t *testing.T) {
	manager, _, quotaStore := newTestManagerWithQuota(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Set usage in mock store
	quotaStore.setTenantUsage(created.ID, &quota.TenantUsage{
		TenantID: created.ID,
		VMs:      5,
		VCPUs:    20,
		MemoryMB: 8192,
	})

	usage, err := manager.GetUsage(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if usage == nil {
		t.Fatal("expected usage to be non-nil")
	}

	if usage.VMs != 5 {
		t.Errorf("expected VMs 5, got %d", usage.VMs)
	}
}

func TestGetUsage_NoUsageTracker(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	created, err := manager.CreateTenant(ctx, &CreateTenantRequest{Name: "test-tenant"})
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// GetUsage degrades gracefully when the optional quota subsystem is
	// not wired: it returns an empty usage snapshot (no error) so that
	// dashboards and admin tools can still render the page.
	usage, err := manager.GetUsage(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error when usage tracker not configured, got %v", err)
	}
	if usage == nil {
		t.Fatal("expected non-nil usage snapshot")
	}
	if usage.TenantID != created.ID {
		t.Errorf("expected TenantID %s, got %q", created.ID, usage.TenantID)
	}
}

func TestGetUsage_NoUsageTracker_TenantNotFound(t *testing.T) {
	manager, _ := newTestManager(t)

	_, err := manager.GetUsage(context.Background(), "missing-tenant")

	var notFound ErrTenantNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrTenantNotFound, got %v", err)
	}
}

// Tests for CheckQuota

func TestCheckQuota_Success(t *testing.T) {
	manager, _, quotaStore := newTestManagerWithQuota(t)
	ctx := context.Background()

	tenantID := "test-tenant"

	// Set quotas in mock store
	quotaStore.setTenantQuota(tenantID, &quota.TenantQuotas{
		TenantID: tenantID,
		Compute: quota.ComputeQuota{
			MaxVMs: 10,
		},
	})

	// Set usage in mock store
	quotaStore.setTenantUsage(tenantID, &quota.TenantUsage{
		TenantID: tenantID,
		VMs:      2,
	})

	err := manager.CheckQuota(ctx, tenantID, quota.ResourceVMs, 3)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCheckQuota_Exceeded(t *testing.T) {
	manager, _, quotaStore := newTestManagerWithQuota(t)
	ctx := context.Background()

	tenantID := "test-tenant"

	// Set quotas in mock store
	quotaStore.setTenantQuota(tenantID, &quota.TenantQuotas{
		TenantID: tenantID,
		Compute: quota.ComputeQuota{
			MaxVMs: 10,
		},
	})

	// Set usage in mock store
	quotaStore.setTenantUsage(tenantID, &quota.TenantUsage{
		TenantID: tenantID,
		VMs:      8,
	})

	err := manager.CheckQuota(ctx, tenantID, quota.ResourceVMs, 5)
	if err == nil {
		t.Fatal("expected error when quota exceeded")
	}
}

// newTenantWithQuotas creates a tenant on an enforcer-less manager, the
// IAM-only wiring platformd uses, so CheckQuota reads the entity quotas.
func newTenantWithQuotas(t *testing.T) (*Manager, *TenantEntity) {
	t.Helper()
	manager, _ := newTestManager(t)

	created, err := manager.CreateTenant(context.Background(), &CreateTenantRequest{
		Name: "test-tenant",
		ComputeQuota: &ComputeQuota{
			MaxVMs:  10,
			UsedVMs: 8,
		},
		NetworkQuota: &NetworkQuota{MaxBandwidthMbps: 100},
		StorageQuota: &StorageQuota{MaxSnapshots: 4},
	})
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}
	return manager, created
}

func TestCheckQuota_NoQuotaEnforcer_WithinLimits(t *testing.T) {
	manager, created := newTenantWithQuotas(t)
	ctx := context.Background()

	checks := map[quota.ResourceType]int64{
		quota.ResourceVMs:       2,
		quota.ResourceBandwidth: 100,
		quota.ResourceSnapshots: 4,
	}
	for resource, amount := range checks {
		if err := manager.CheckQuota(ctx, created.ID, resource, amount); err != nil {
			t.Errorf("CheckQuota(%s, %d): expected no error, got %v", resource, amount, err)
		}
	}
}

func TestCheckQuota_NoQuotaEnforcer_Exceeded(t *testing.T) {
	manager, created := newTenantWithQuotas(t)

	err := manager.CheckQuota(context.Background(), created.ID, quota.ResourceVMs, 3)

	var exceeded ErrQuotaExceeded
	if !errors.As(err, &exceeded) {
		t.Fatalf("expected ErrQuotaExceeded, got %v", err)
	}
	if exceeded.Requested != 3 || exceeded.Available != 2 {
		t.Errorf("expected requested 3 available 2, got requested %d available %d",
			exceeded.Requested, exceeded.Available)
	}
}

func TestCheckQuota_NoQuotaEnforcer_UnsetLimitExceeded(t *testing.T) {
	manager, created := newTenantWithQuotas(t)

	// No container limit was set, so none are available.
	err := manager.CheckQuota(context.Background(), created.ID, quota.ResourceContainers, 1)

	var exceeded ErrQuotaExceeded
	if !errors.As(err, &exceeded) {
		t.Fatalf("expected ErrQuotaExceeded, got %v", err)
	}
}

func TestCheckQuota_NoQuotaEnforcer_TenantNotFound(t *testing.T) {
	manager, _ := newTestManager(t)

	err := manager.CheckQuota(context.Background(), "missing-tenant", quota.ResourceVMs, 1)

	var notFound ErrTenantNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrTenantNotFound, got %v", err)
	}
}

func TestCheckQuota_NoQuotaEnforcer_UntrackedResource(t *testing.T) {
	manager, created := newTenantWithQuotas(t)

	// The entity tracks volume capacity in GB, not a volume count.
	err := manager.CheckQuota(context.Background(), created.ID, quota.ResourceVolumes, 1)

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

// Tests for ReserveQuota

func TestReserveQuota_Success(t *testing.T) {
	manager, _, quotaStore := newTestManagerWithQuota(t)
	ctx := context.Background()

	tenantID := "test-tenant"

	// Set quotas in mock store
	quotaStore.setTenantQuota(tenantID, &quota.TenantQuotas{
		TenantID: tenantID,
		Compute: quota.ComputeQuota{
			MaxVMs: 10,
		},
	})

	// Set usage in mock store
	quotaStore.setTenantUsage(tenantID, &quota.TenantUsage{
		TenantID: tenantID,
		VMs:      2,
	})

	reservation, err := manager.ReserveQuota(ctx, tenantID, quota.ResourceVMs, 3)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if reservation == nil {
		t.Fatal("expected reservation to be non-nil")
	}

	if reservation.TenantID != tenantID {
		t.Errorf("expected tenant ID %q, got %q", tenantID, reservation.TenantID)
	}

	if reservation.Amount != 3 {
		t.Errorf("expected amount 3, got %d", reservation.Amount)
	}
}

func TestReserveQuota_NoQuotaEnforcer(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	_, err := manager.ReserveQuota(ctx, "test-tenant", quota.ResourceVMs, 1)
	if err == nil {
		t.Fatal("expected error when quota enforcer not configured")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

// Tests for CommitQuota

func TestCommitQuota_Success(t *testing.T) {
	manager, _, quotaStore := newTestManagerWithQuota(t)
	ctx := context.Background()

	tenantID := "test-tenant"

	// Set quotas in mock store
	quotaStore.setTenantQuota(tenantID, &quota.TenantQuotas{
		TenantID: tenantID,
		Compute: quota.ComputeQuota{
			MaxVMs: 10,
		},
	})

	// Set usage in mock store
	quotaStore.setTenantUsage(tenantID, &quota.TenantUsage{
		TenantID: tenantID,
		VMs:      2,
	})

	// Create reservation first
	reservation, err := manager.ReserveQuota(ctx, tenantID, quota.ResourceVMs, 3)
	if err != nil {
		t.Fatalf("failed to reserve quota: %v", err)
	}

	// Commit reservation
	err = manager.CommitQuota(ctx, reservation.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCommitQuota_NoQuotaEnforcer(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	err := manager.CommitQuota(ctx, "some-reservation-id")
	if err == nil {
		t.Fatal("expected error when quota enforcer not configured")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

// Tests for ReleaseQuota

func TestReleaseQuota_Success(t *testing.T) {
	manager, _, quotaStore := newTestManagerWithQuota(t)
	ctx := context.Background()

	tenantID := "test-tenant"

	// Set quotas in mock store
	quotaStore.setTenantQuota(tenantID, &quota.TenantQuotas{
		TenantID: tenantID,
		Compute: quota.ComputeQuota{
			MaxVMs: 10,
		},
	})

	// Set usage in mock store
	quotaStore.setTenantUsage(tenantID, &quota.TenantUsage{
		TenantID: tenantID,
		VMs:      2,
	})

	// Create reservation first
	reservation, err := manager.ReserveQuota(ctx, tenantID, quota.ResourceVMs, 3)
	if err != nil {
		t.Fatalf("failed to reserve quota: %v", err)
	}

	// Release reservation
	err = manager.ReleaseQuota(ctx, reservation.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSync_Success(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Sync should not fail even with no components
	err := manager.Sync(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSync_WithQuotaComponents(t *testing.T) {
	manager, _, _ := newTestManagerWithQuota(t)
	ctx := context.Background()

	// Sync should work with quota components
	err := manager.Sync(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// Tests for cache operations

func TestInvalidateCache_SpecificTenant(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Verify in cache
	if manager.GetCacheSize() != 1 {
		t.Errorf("expected cache size 1, got %d", manager.GetCacheSize())
	}

	// Invalidate
	manager.InvalidateCache(created.ID)

	// Cache should be empty
	if manager.GetCacheSize() != 0 {
		t.Errorf("expected cache size 0 after invalidation, got %d", manager.GetCacheSize())
	}
}

func TestInvalidateCache_All(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Create multiple tenants
	for i := 0; i < 3; i++ {
		createReq := &CreateTenantRequest{
			Name: "test-tenant-" + string(rune('a'+i)),
		}
		_, err := manager.CreateTenant(ctx, createReq)
		if err != nil {
			t.Fatalf("failed to create tenant: %v", err)
		}
	}

	if manager.GetCacheSize() != 3 {
		t.Errorf("expected cache size 3, got %d", manager.GetCacheSize())
	}

	// Invalidate all
	manager.InvalidateCache("")

	if manager.GetCacheSize() != 0 {
		t.Errorf("expected cache size 0 after full invalidation, got %d", manager.GetCacheSize())
	}
}

// Tests for DEK operations

func newTestManagerWithDEK(t *testing.T) (*Manager, *mockIAMClient, *mockDEKClient) {
	t.Helper()

	iamClient := newMockIAMClient()
	dekClient := newMockDEKClient()
	logger := newTestLogger()

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		DEKClient:       dekClient,
		Config:          DefaultConfig(),
		Logger:          logger,
	}

	// Enable DEK isolation
	cfg.Config.EnableDEKIsolation = true

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	return manager, iamClient, dekClient
}

func TestCreateTenant_WithDEKIsolation(t *testing.T) {
	manager, _, dekClient := newTestManagerWithDEK(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	entity, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity == nil {
		t.Fatal("expected entity to be non-nil")
	}

	// DEK path should be set
	if entity.DEKPath == "" {
		t.Error("expected DEKPath to be set")
	}

	expectedDEKID := "dek:tenant:" + entity.ID
	if entity.DEKPath != expectedDEKID {
		t.Errorf("DEKPath = %q, want %q", entity.DEKPath, expectedDEKID)
	}

	// Verify DEK was created in the mock client
	dekClient.mu.RLock()
	_, exists := dekClient.deks[entity.ID]
	dekClient.mu.RUnlock()

	if !exists {
		t.Error("expected DEK to be created in mock client")
	}
}

func TestDeleteTenant_WithDEKIsolation(t *testing.T) {
	manager, _, dekClient := newTestManagerWithDEK(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Verify DEK exists before deletion
	dekClient.mu.RLock()
	_, exists := dekClient.deks[created.ID]
	dekClient.mu.RUnlock()
	if !exists {
		t.Fatal("expected DEK to exist before deletion")
	}

	err = manager.DeleteTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify DEK was deleted
	dekClient.mu.RLock()
	_, exists = dekClient.deks[created.ID]
	dekClient.mu.RUnlock()
	if exists {
		t.Error("expected DEK to be deleted from mock client")
	}
}

func TestRotateTenantDEK(t *testing.T) {
	manager, _, dekClient := newTestManagerWithDEK(t)
	ctx := context.Background()

	// Create tenant first
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Check initial version
	dekClient.mu.RLock()
	dek := dekClient.deks[created.ID]
	initialVersion := dek.Version
	dekClient.mu.RUnlock()

	// Rotate DEK
	err = manager.RotateTenantDEK(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to rotate DEK: %v", err)
	}

	// Verify version was incremented
	dekClient.mu.RLock()
	dek = dekClient.deks[created.ID]
	newVersion := dek.Version
	dekClient.mu.RUnlock()

	if newVersion != initialVersion+1 {
		t.Errorf("DEK version = %d, want %d", newVersion, initialVersion+1)
	}
}

func TestGetTenantDEKStatus(t *testing.T) {
	manager, _, _ := newTestManagerWithDEK(t)
	ctx := context.Background()

	// Create tenant first
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Get DEK status
	status, err := manager.GetTenantDEKStatus(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to get DEK status: %v", err)
	}

	if status == nil {
		t.Fatal("expected status to be non-nil")
	}

	if status.Path != created.DEKPath {
		t.Errorf("status.Path = %q, want %q", status.Path, created.DEKPath)
	}

	if status.Version != 1 {
		t.Errorf("status.Version = %d, want 1", status.Version)
	}
}

func TestRotateTenantDEK_WithoutDEKIsolation(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Create tenant first (without DEK isolation)
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Try to rotate DEK - should fail since DEK isolation is disabled
	err = manager.RotateTenantDEK(ctx, created.ID)
	if err == nil {
		t.Error("expected error when rotating DEK without DEK isolation enabled")
	}
}

func TestGetTenantDEKStatus_WithoutDEKIsolation(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Create tenant first (without DEK isolation)
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Try to get DEK status - should fail since DEK isolation is disabled
	_, err = manager.GetTenantDEKStatus(ctx, created.ID)
	if err == nil {
		t.Error("expected error when getting DEK status without DEK isolation enabled")
	}
}

func TestNewManager_DEKClientRequired(t *testing.T) {
	iamClient := newMockIAMClient()
	logger := newTestLogger()

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		Config:          DefaultConfig(),
		Logger:          logger,
	}

	// Enable DEK isolation but don't provide DEK client
	cfg.Config.EnableDEKIsolation = true

	_, err := NewManager(cfg)
	if err == nil {
		t.Error("expected error when DEK isolation enabled without DEK client")
	}
}

// Tests for concurrent access

func TestConcurrentCreateTenant(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	const numGoroutines = 10
	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			req := &CreateTenantRequest{
				Name: "concurrent-tenant-" + string(rune('a'+idx)),
			}

			_, err := manager.CreateTenant(ctx, req)
			if err != nil {
				errChan <- err
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrent create error: %v", err)
	}

	// Verify all tenants created
	tenants, _, err := manager.ListTenants(ctx, 100, 0)
	if err != nil {
		t.Fatalf("failed to list tenants: %v", err)
	}

	if len(tenants) != numGoroutines {
		t.Errorf("expected %d tenants, got %d", numGoroutines, len(tenants))
	}
}

func TestConcurrentGetTenant(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Create a tenant
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Concurrent reads
	const numGoroutines = 100
	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			entity, err := manager.GetTenant(ctx, created.ID)
			if err != nil {
				errChan <- err
				return
			}

			if entity.ID != created.ID {
				errChan <- errors.New("ID mismatch")
			}
		}()
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrent get error: %v", err)
	}
}

func BenchmarkCreateTenant(b *testing.B) {
	iamClient := newMockIAMClient()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		Config:          DefaultConfig(),
		Logger:          logger,
	}
	cfg.Config.EnableDEKIsolation = false

	manager, _ := NewManager(cfg)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := &CreateTenantRequest{
			Name: "bench-tenant-" + time.Now().String(),
		}
		if _, err := manager.CreateTenant(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetTenant(b *testing.B) {
	iamClient := newMockIAMClient()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		Config:          DefaultConfig(),
		Logger:          logger,
	}
	cfg.Config.EnableDEKIsolation = false

	manager, _ := NewManager(cfg)
	ctx := context.Background()

	// Create a tenant
	createReq := &CreateTenantRequest{
		Name: "bench-tenant",
	}
	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := manager.GetTenant(ctx, created.ID); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConcurrentGetTenant(b *testing.B) {
	iamClient := newMockIAMClient()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		Config:          DefaultConfig(),
		Logger:          logger,
	}
	cfg.Config.EnableDEKIsolation = false

	manager, _ := NewManager(cfg)
	ctx := context.Background()

	// Create a tenant
	createReq := &CreateTenantRequest{
		Name: "bench-tenant",
	}
	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := manager.GetTenant(ctx, created.ID); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkListTenants(b *testing.B) {
	iamClient := newMockIAMClient()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		Config:          DefaultConfig(),
		Logger:          logger,
	}
	cfg.Config.EnableDEKIsolation = false

	manager, _ := NewManager(cfg)
	ctx := context.Background()

	// Create some tenants
	for i := 0; i < 100; i++ {
		req := &CreateTenantRequest{
			Name: "bench-tenant-" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
		}
		if _, err := manager.CreateTenant(ctx, req); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := manager.ListTenants(ctx, 50, 0); err != nil {
			b.Fatal(err)
		}
	}
}

// Additional tests for improving coverage

func TestRotateTenantDEKWithOptions_EmptyTenantID(t *testing.T) {
	manager, _, _ := newTestManagerWithDEK(t)
	ctx := context.Background()

	_, err := manager.RotateTenantDEKWithOptions(ctx, "", false)
	if err == nil {
		t.Fatal("expected error for empty tenant ID")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

func TestRotateTenantDEKWithOptions_NoDEKClient(t *testing.T) {
	iamClient := newMockIAMClient()
	logger := newTestLogger()

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		DEKClient:       nil, // No DEK client
		Config:          DefaultConfig(),
		Logger:          logger,
	}
	cfg.Config.EnableDEKIsolation = true

	// This should fail during manager creation
	_, err := NewManager(cfg)
	if err == nil {
		t.Fatal("expected error when DEK client not provided with DEK isolation enabled")
	}
}

func TestRotateTenantDEKWithOptions_Background(t *testing.T) {
	manager, _, _ := newTestManagerWithDEK(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Rotate with background option
	result, err := manager.RotateTenantDEKWithOptions(ctx, created.ID, true)
	if err != nil {
		t.Fatalf("failed to rotate DEK: %v", err)
	}

	if result == nil {
		t.Fatal("expected result to be non-nil")
	}

	if result.TenantID != created.ID {
		t.Errorf("expected tenant ID %q, got %q", created.ID, result.TenantID)
	}

	if result.NewVersion != 2 {
		t.Errorf("expected new version 2, got %d", result.NewVersion)
	}
}

func TestRotateTenantDEKWithOptions_NoDEKConfigured(t *testing.T) {
	manager, _, _ := newTestManagerWithDEK(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Manually clear DEK path to simulate tenant without DEK
	entity, _ := manager.GetTenant(ctx, created.ID)
	entity.DEKPath = ""
	manager.cache.Store(created.ID, entity)

	_, err = manager.RotateTenantDEKWithOptions(ctx, created.ID, false)
	if err == nil {
		t.Fatal("expected error when tenant has no DEK configured")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

func TestRotateTenantDEKWithOptions_RotateError(t *testing.T) {
	manager, _, dekClient := newTestManagerWithDEK(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Inject rotate error
	dekClient.rotateErr = errors.New("rotate failed")

	_, err = manager.RotateTenantDEKWithOptions(ctx, created.ID, false)
	if err == nil {
		t.Fatal("expected error when DEK rotation fails")
	}

	var dekErr ErrDEKOperationFailed
	if !errors.As(err, &dekErr) {
		t.Errorf("expected ErrDEKOperationFailed, got %T", err)
	}
}

func TestGetTenantDEKStatus_EmptyTenantID(t *testing.T) {
	manager, _, _ := newTestManagerWithDEK(t)
	ctx := context.Background()

	_, err := manager.GetTenantDEKStatus(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty tenant ID")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

func TestGetTenantDEKStatus_NoDEKConfigured(t *testing.T) {
	manager, _, _ := newTestManagerWithDEK(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Manually clear DEK path to simulate tenant without DEK
	entity, _ := manager.GetTenant(ctx, created.ID)
	entity.DEKPath = ""
	manager.cache.Store(created.ID, entity)

	_, err = manager.GetTenantDEKStatus(ctx, created.ID)
	if err == nil {
		t.Fatal("expected error when tenant has no DEK configured")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

func TestGetTenantDEKStatus_GetStatusError(t *testing.T) {
	manager, _, dekClient := newTestManagerWithDEK(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Inject get status error
	dekClient.getStatusErr = errors.New("status retrieval failed")

	_, err = manager.GetTenantDEKStatus(ctx, created.ID)
	if err == nil {
		t.Fatal("expected error when DEK status retrieval fails")
	}

	var dekErr ErrDEKOperationFailed
	if !errors.As(err, &dekErr) {
		t.Errorf("expected ErrDEKOperationFailed, got %T", err)
	}
}

func TestGetTenantDEKStatus_WithReencryptionProgress(t *testing.T) {
	manager, _, dekClient := newTestManagerWithDEK(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Set re-encryption in progress
	dekClient.mu.Lock()
	dekClient.reencryptionInProgress = true
	dekClient.mu.Unlock()

	status, err := manager.GetTenantDEKStatus(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to get DEK status: %v", err)
	}

	if status.ReencryptProgress == nil {
		t.Fatal("expected re-encryption progress to be set")
	}

	if !status.ReencryptProgress.InProgress {
		t.Error("expected InProgress to be true")
	}

}

func TestCreateTenant_DEKCreateError(t *testing.T) {
	iamClient := newMockIAMClient()
	dekClient := newMockDEKClient()
	logger := newTestLogger()

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		DEKClient:       dekClient,
		Config:          DefaultConfig(),
		Logger:          logger,
	}
	cfg.Config.EnableDEKIsolation = true

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Inject DEK creation error
	dekClient.createErr = errors.New("DEK creation failed")

	ctx := context.Background()
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	_, err = manager.CreateTenant(ctx, createReq)
	if err == nil {
		t.Fatal("expected error when DEK creation fails")
	}

	var dekErr ErrDEKOperationFailed
	if !errors.As(err, &dekErr) {
		t.Errorf("expected ErrDEKOperationFailed, got %T", err)
	}
}
func TestNewManager_InvalidConfig(t *testing.T) {
	iamClient := newMockIAMClient()

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		Config: &Config{
			EnableDEKIsolation: true,
			DEKAlgorithm:       "rot13",
		},
	}

	_, err := NewManager(cfg)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestReleaseQuota_NoQuotaEnforcer(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	err := manager.ReleaseQuota(ctx, "some-reservation-id")
	if err == nil {
		t.Fatal("expected error when quota enforcer not configured")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

func TestConcurrentSuspendResume(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Create multiple tenants
	tenantIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		createReq := &CreateTenantRequest{
			Name: "concurrent-tenant-" + string(rune('a'+i)),
		}
		created, err := manager.CreateTenant(ctx, createReq)
		if err != nil {
			t.Fatalf("failed to create tenant: %v", err)
		}
		tenantIDs[i] = created.ID
	}

	// Concurrent suspend operations
	var wg sync.WaitGroup
	errChan := make(chan error, len(tenantIDs))

	for _, id := range tenantIDs {
		wg.Add(1)
		go func(tenantID string) {
			defer wg.Done()

			err := manager.SuspendTenant(ctx, tenantID)
			if err != nil {
				errChan <- err
			}
		}(id)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrent suspend error: %v", err)
	}

	// Verify all tenants suspended
	for _, id := range tenantIDs {
		entity, err := manager.GetTenant(ctx, id)
		if err != nil {
			t.Fatalf("failed to get tenant: %v", err)
		}
		if entity.State != StateSuspended {
			t.Errorf("expected tenant %s to be suspended, got %s", id, entity.State)
		}
	}
}

// Tests for lifecycle hooks with bridge manager
// Note: TestCreateTenant_WithBridgeManager is removed because LifecycleHooks
// requires a properly initialized bridge.Manager with OVS client, which cannot
// be easily mocked in unit tests. This functionality is tested in integration tests.

// Benchmark tests
