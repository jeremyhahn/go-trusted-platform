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
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/clusterdek"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/vlan"
)

// mockIAMClient implements iam.TenantClient for testing.
type mockIAMClient struct {
	mu      sync.RWMutex
	tenants map[string]*iam.Tenant
	nextID  int

	// Error injection
	createErr error
	getErr    error
	listErr   error
	updateErr error
	deleteErr error
}

func newMockIAMClient() *mockIAMClient {
	return &mockIAMClient{
		tenants: make(map[string]*iam.Tenant),
		nextID:  1,
	}
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
	m.nextID++

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

// mockDEKClient implements clusterdek.Client for testing.
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

func (m *mockDEKClient) InitializeClusterDEK(ctx context.Context, req *clusterdek.InitClusterDEKRequest) (*clusterdek.InitClusterDEKResponse, error) {
	return &clusterdek.InitClusterDEKResponse{
		Version:   1,
		CreatedAt: time.Now(),
		Algorithm: req.Algorithm,
		KeySize:   req.KeySize,
	}, nil
}

func (m *mockDEKClient) GetClusterDEKStatus(ctx context.Context) (*clusterdek.ClusterDEKStatusResponse, error) {
	if m.getStatusErr != nil {
		return nil, m.getStatusErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a status based on the first DEK found (for testing)
	resp := &clusterdek.ClusterDEKStatusResponse{
		Initialized:            true,
		CurrentVersion:         1,
		CreatedAt:              time.Now(),
		Algorithm:              "aes-256-gcm",
		ReencryptionInProgress: m.reencryptionInProgress,
	}

	// If we have DEKs, use the first one's version
	for _, dek := range m.deks {
		resp.CurrentVersion = dek.Version
		resp.Algorithm = dek.Algorithm
		resp.CreatedAt = dek.CreatedAt
		if !dek.RotatedAt.IsZero() {
			rotatedAt := dek.RotatedAt
			resp.RotatedAt = &rotatedAt
		}
		break
	}

	return resp, nil
}

func (m *mockDEKClient) RotateClusterDEK(ctx context.Context, req *clusterdek.RotateClusterDEKRequest) (*clusterdek.RotateClusterDEKResponse, error) {
	if m.rotateErr != nil {
		return nil, m.rotateErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Find any DEK and rotate it
	for _, dek := range m.deks {
		oldVersion := dek.Version
		dek.Version++
		dek.RotatedAt = time.Now()

		return &clusterdek.RotateClusterDEKResponse{
			OldVersion: oldVersion,
			NewVersion: dek.Version,
			RotatedAt:  dek.RotatedAt,
		}, nil
	}

	return nil, errors.New("no DEK to rotate")
}

func (m *mockDEKClient) SyncNodeDEK(ctx context.Context, req *clusterdek.SyncNodeDEKRequest) (*clusterdek.SyncNodeDEKResponse, error) {
	return &clusterdek.SyncNodeDEKResponse{
		NodeID:         req.NodeID,
		CurrentVersion: 1,
		SyncedAt:       time.Now(),
	}, nil
}

func (m *mockDEKClient) GetNodeDEKStatus(ctx context.Context, req *clusterdek.GetNodeDEKStatusRequest) (*clusterdek.GetNodeDEKStatusResponse, error) {
	return &clusterdek.GetNodeDEKStatusResponse{
		NodeID:         req.NodeID,
		CurrentVersion: 1,
		LastSyncedAt:   time.Now(),
		Status:         clusterdek.NodeDEKSynced,
	}, nil
}

func (m *mockDEKClient) StartReencryption(ctx context.Context, req *clusterdek.StartReencryptionRequest) (*clusterdek.StartReencryptionResponse, error) {
	return &clusterdek.StartReencryptionResponse{
		Started:   true,
		StartedAt: time.Now(),
	}, nil
}

func (m *mockDEKClient) GetReencryptionStatus(ctx context.Context) (*clusterdek.ReencryptionStatusResponse, error) {
	return &clusterdek.ReencryptionStatusResponse{
		State: clusterdek.ReencryptionCompleted,
	}, nil
}

func (m *mockDEKClient) CancelReencryption(ctx context.Context) error {
	return nil
}

func (m *mockDEKClient) RecoverDEK(ctx context.Context, req *clusterdek.RecoverDEKRequest) (*clusterdek.RecoverDEKResponse, error) {
	return &clusterdek.RecoverDEKResponse{
		Success:          true,
		RecoveredVersion: 1,
		RecoveredAt:      time.Now(),
	}, nil
}

func (m *mockDEKClient) EnsureTenantDEK(ctx context.Context, req *clusterdek.EnsureTenantDEKRequest) (*clusterdek.EnsureTenantDEKResponse, error) {
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

	// Check if already exists
	if existing, ok := m.deks[req.TenantID]; ok {
		return &clusterdek.EnsureTenantDEKResponse{
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

	return &clusterdek.EnsureTenantDEKResponse{
		DEKID:     dekID,
		Created:   true,
		Algorithm: algorithm,
		CreatedAt: now,
	}, nil
}

func (m *mockDEKClient) DeleteTenantDEK(ctx context.Context, req *clusterdek.DeleteTenantDEKRequest) (*clusterdek.DeleteTenantDEKResponse, error) {
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

	return &clusterdek.DeleteTenantDEKResponse{
		DEKID:     dek.DEKID,
		DeletedAt: time.Now(),
	}, nil
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

// mockVLANStore implements vlan.AllocationStore for testing.
type mockVLANStore struct {
	mu          sync.RWMutex
	allocations map[string]*vlan.Allocation

	getErr    error
	saveErr   error
	deleteErr error
	listErr   error
}

func newMockVLANStore() *mockVLANStore {
	return &mockVLANStore{
		allocations: make(map[string]*vlan.Allocation),
	}
}

func (m *mockVLANStore) GetAllocation(ctx context.Context, tenantID string) (*vlan.Allocation, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	alloc, ok := m.allocations[tenantID]
	if !ok {
		return nil, nil
	}
	return alloc, nil
}

func (m *mockVLANStore) SaveAllocation(ctx context.Context, alloc *vlan.Allocation) error {
	if m.saveErr != nil {
		return m.saveErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.allocations[alloc.TenantID] = alloc
	return nil
}

func (m *mockVLANStore) DeleteAllocation(ctx context.Context, tenantID string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.allocations, tenantID)
	return nil
}

func (m *mockVLANStore) ListAllocations(ctx context.Context) ([]*vlan.Allocation, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*vlan.Allocation, 0, len(m.allocations))
	for _, alloc := range m.allocations {
		result = append(result, alloc)
	}
	return result, nil
}

// Test helper functions

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
		Config:    DefaultConfig(),
		Logger:    logger,
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
		IAMTenantClient:     iamClient,
		QuotaEnforcer: enforcer,
		UsageTracker:  tracker,
		Config:        DefaultConfig(),
		Logger:        logger,
	}

	cfg.Config.EnableDEKIsolation = false

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	return manager, iamClient, quotaStore
}

// newTestManagerWithVLAN creates a manager with VLAN allocator and validator.
func newTestManagerWithVLAN(t *testing.T) (*Manager, *mockIAMClient, *mockVLANStore) {
	t.Helper()

	iamClient := newMockIAMClient()
	vlanStore := newMockVLANStore()
	logger := newTestLogger()

	vlanCfg := vlan.DefaultConfig()
	allocator, err := vlan.NewAllocator(vlanStore, vlanCfg, logger)
	if err != nil {
		t.Fatalf("failed to create VLAN allocator: %v", err)
	}

	validator := vlan.NewValidator(allocator, logger)

	cfg := &ManagerConfig{
		IAMTenantClient:     iamClient,
		VLANAllocator: allocator,
		VLANValidator: validator,
		Config:        DefaultConfig(),
		Logger:        logger,
	}

	cfg.Config.EnableDEKIsolation = false

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	return manager, iamClient, vlanStore
}

// Tests for NewManager

func TestNewManager_Success(t *testing.T) {
	iamClient := newMockIAMClient()
	logger := newTestLogger()

	config := DefaultConfig()
	config.EnableDEKIsolation = false

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		Config:    config,
		Logger:    logger,
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
		Config:    DefaultConfig(),
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

func TestNewManager_InvalidConfig(t *testing.T) {
	iamClient := newMockIAMClient()

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		Config: &Config{
			DefaultVLANRangeStart: 0, // Invalid
		},
	}

	_, err := NewManager(cfg)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestNewManager_DefaultConfig(t *testing.T) {
	iamClient := newMockIAMClient()

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		DEKClient: newMockDEKClient(),
		Config:    nil, // Should use defaults
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
		DEKClient: newMockDEKClient(),
		Config:    DefaultConfig(),
		Logger:    nil, // Should use default
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

func TestCreateTenant_WithVLANAutoAllocate(t *testing.T) {
	manager, _, _ := newTestManagerWithVLAN(t)
	ctx := context.Background()

	req := &CreateTenantRequest{
		Name: "test-tenant",
	}

	entity, err := manager.CreateTenant(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity.VLANRange.Start == 0 || entity.VLANRange.End == 0 {
		t.Error("expected VLAN range to be auto-allocated")
	}

	if entity.VLANRange.End-entity.VLANRange.Start+1 != 100 {
		t.Errorf("expected VLAN range size 100, got %d", entity.VLANRange.End-entity.VLANRange.Start+1)
	}
}

func TestCreateTenant_WithSpecificVLANRange(t *testing.T) {
	manager, _, _ := newTestManagerWithVLAN(t)
	ctx := context.Background()

	req := &CreateTenantRequest{
		Name: "test-tenant",
		VLANRange: &VLANRange{
			Start: 500,
			End:   599,
		},
	}

	entity, err := manager.CreateTenant(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity.VLANRange.Start != 500 {
		t.Errorf("expected VLAN start 500, got %d", entity.VLANRange.Start)
	}

	if entity.VLANRange.End != 599 {
		t.Errorf("expected VLAN end 599, got %d", entity.VLANRange.End)
	}
}

func TestCreateTenant_VLANAllocationConflict(t *testing.T) {
	manager, _, _ := newTestManagerWithVLAN(t)
	ctx := context.Background()

	// Create first tenant with specific VLAN range
	req1 := &CreateTenantRequest{
		Name: "test-tenant-1",
		VLANRange: &VLANRange{
			Start: 500,
			End:   599,
		},
	}

	_, err := manager.CreateTenant(ctx, req1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Try to create second tenant with overlapping VLAN range
	req2 := &CreateTenantRequest{
		Name: "test-tenant-2",
		VLANRange: &VLANRange{
			Start: 550,
			End:   649,
		},
	}

	_, err = manager.CreateTenant(ctx, req2)
	if err == nil {
		t.Fatal("expected error for overlapping VLAN range")
	}

	var vlanErr ErrVLANAllocationFailed
	if !errors.As(err, &vlanErr) {
		t.Errorf("expected ErrVLANAllocationFailed, got %T: %v", err, err)
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

func TestGetTenant_WithVLANAllocation(t *testing.T) {
	manager, _, _ := newTestManagerWithVLAN(t)
	ctx := context.Background()

	// Create tenant with VLAN
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Invalidate cache to force IAM fetch
	manager.InvalidateCache(created.ID)

	// Get tenant - should enrich with VLAN data
	entity, err := manager.GetTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entity.VLANRange.Start == 0 && entity.VLANRange.End == 0 {
		t.Error("expected VLAN range to be enriched")
	}
}

// Tests for GetTenantByName

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

func TestListTenants_WithVLANEnrichment(t *testing.T) {
	manager, _, _ := newTestManagerWithVLAN(t)
	ctx := context.Background()

	// Create tenant with VLAN
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	_, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// List tenants - should enrich with VLAN data
	tenants, _, err := manager.ListTenants(ctx, 10, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(tenants) != 1 {
		t.Fatalf("expected 1 tenant, got %d", len(tenants))
	}

	if tenants[0].VLANRange.Start == 0 && tenants[0].VLANRange.End == 0 {
		t.Error("expected VLAN range to be enriched")
	}
}

// Tests for UpdateTenant

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

func TestDeleteTenant_WithVLANRelease(t *testing.T) {
	manager, _, vlanStore := newTestManagerWithVLAN(t)
	ctx := context.Background()

	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Verify VLAN allocation exists
	alloc, err := vlanStore.GetAllocation(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to get VLAN allocation: %v", err)
	}
	if alloc == nil {
		t.Fatal("expected VLAN allocation to exist")
	}

	err = manager.DeleteTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify VLAN allocation released
	alloc, err = vlanStore.GetAllocation(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to get VLAN allocation: %v", err)
	}
	if alloc != nil {
		t.Error("expected VLAN allocation to be released")
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

	_, err := manager.GetUsage(ctx, "test-tenant")
	if err == nil {
		t.Fatal("expected error when usage tracker not configured")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
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

func TestCheckQuota_NoQuotaEnforcer(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	err := manager.CheckQuota(ctx, "test-tenant", quota.ResourceVMs, 1)
	if err == nil {
		t.Fatal("expected error when quota enforcer not configured")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
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

// Tests for ValidateVLAN

func TestValidateVLAN_Success(t *testing.T) {
	manager, _, _ := newTestManagerWithVLAN(t)
	ctx := context.Background()

	// Create tenant with VLAN allocation
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
		VLANRange: &VLANRange{
			Start: 500,
			End:   599,
		},
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Validate VLAN in range
	err = manager.ValidateVLAN(ctx, created.ID, 550)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateVLAN_OutOfRange(t *testing.T) {
	manager, _, _ := newTestManagerWithVLAN(t)
	ctx := context.Background()

	// Create tenant with VLAN allocation
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
		VLANRange: &VLANRange{
			Start: 500,
			End:   599,
		},
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Validate VLAN outside range
	err = manager.ValidateVLAN(ctx, created.ID, 700)
	if err == nil {
		t.Fatal("expected error for VLAN outside range")
	}
}

func TestValidateVLAN_NoValidator(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	err := manager.ValidateVLAN(ctx, "test-tenant", 100)
	if err == nil {
		t.Fatal("expected error when VLAN validator not configured")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

// Tests for GetBridgeName

func TestGetBridgeName_Success(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Create tenant with explicit bridge name
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Without bridge manager, OVSBridge will be empty
	// So we need to set it manually for testing
	entity, err := manager.GetTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to get tenant: %v", err)
	}
	entity.OVSBridge = "br-test-tenant"
	manager.cache.Store(created.ID, entity)

	bridgeName, err := manager.GetBridgeName(ctx, created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if bridgeName != "br-test-tenant" {
		t.Errorf("expected bridge name %q, got %q", "br-test-tenant", bridgeName)
	}
}

func TestGetBridgeName_NotFound(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	_, err := manager.GetBridgeName(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestGetBridgeName_NoBridge(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Create tenant without bridge
	createReq := &CreateTenantRequest{
		Name: "test-tenant",
	}

	created, err := manager.CreateTenant(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	_, err = manager.GetBridgeName(ctx, created.ID)
	if err == nil {
		t.Fatal("expected error when tenant has no bridge")
	}

	var invalidReq ErrInvalidRequest
	if !errors.As(err, &invalidReq) {
		t.Errorf("expected ErrInvalidRequest, got %T", err)
	}
}

// Tests for Sync

func TestSync_Success(t *testing.T) {
	manager, _ := newTestManager(t)
	ctx := context.Background()

	// Sync should not fail even with no components
	err := manager.Sync(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSync_WithVLANAllocator(t *testing.T) {
	manager, _, _ := newTestManagerWithVLAN(t)
	ctx := context.Background()

	// Sync should work with VLAN allocator
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
		DEKClient: dekClient,
		Config:    DefaultConfig(),
		Logger:    logger,
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
		Config:    DefaultConfig(),
		Logger:    logger,
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

func BenchmarkCreateTenant(b *testing.B) {
	iamClient := newMockIAMClient()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		Config:    DefaultConfig(),
		Logger:    logger,
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
		Config:    DefaultConfig(),
		Logger:    logger,
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
		Config:    DefaultConfig(),
		Logger:    logger,
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
		Config:    DefaultConfig(),
		Logger:    logger,
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
		DEKClient: nil, // No DEK client
		Config:    DefaultConfig(),
		Logger:    logger,
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
		DEKClient: dekClient,
		Config:    DefaultConfig(),
		Logger:    logger,
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
