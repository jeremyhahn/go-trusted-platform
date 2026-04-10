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

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
)

// =============================================================================
// Mock Tenant Manager
// =============================================================================

// mockTenantManager implements TenantManagerInterface for testing.
type mockTenantManager struct {
	tenants           map[string]*tenant.TenantEntity
	quotas            map[string]*tenant.TenantQuotas
	usage             map[string]*quota.TenantUsage
	createErr         error
	getErr            error
	getByNameErr      error
	listErr           error
	updateErr         error
	deleteErr         error
	suspendErr        error
	resumeErr         error
	getQuotasErr      error
	updateQuotasErr   error
	usageErr          error
	checkQuotaErr     error
	validateVLANErr   error
	bridgeErr         error
	syncErr           error
	rotateDEKErr      error
	getDEKStatusErr   error
	createdTenant     *tenant.TenantEntity
	updatedTenant     *tenant.TenantEntity
	lastCreateReq     *tenant.CreateTenantRequest
	lastUpdateReq     *tenant.UpdateTenantRequest
	lastQuotasUpdated *tenant.TenantQuotas
	dekRotationResult *tenant.DEKRotationResult
	dekStatus         *tenant.DEKStatus
	lastRotateBack    bool
}

func newMockTenantManager() *mockTenantManager {
	return &mockTenantManager{
		tenants: make(map[string]*tenant.TenantEntity),
		quotas:  make(map[string]*tenant.TenantQuotas),
		usage:   make(map[string]*quota.TenantUsage),
	}
}

func (m *mockTenantManager) addTenant(e *tenant.TenantEntity) {
	m.tenants[e.ID] = e
	m.quotas[e.ID] = &tenant.TenantQuotas{
		Compute: e.ComputeQuota,
		Network: e.NetworkQuota,
		Storage: e.StorageQuota,
	}
	m.usage[e.ID] = &quota.TenantUsage{
		TenantID:      e.ID,
		VMs:           5,
		Containers:    10,
		VCPUs:         16,
		MemoryMB:      32768,
		DiskGB:        512,
		Bridges:       2,
		Ports:         20,
		BandwidthMbps: 1000,
		Volumes:       5,
		Snapshots:     10,
		Timestamp:     time.Now(),
	}
}

func (m *mockTenantManager) CreateTenant(ctx context.Context, req *tenant.CreateTenantRequest) (*tenant.TenantEntity, error) {
	m.lastCreateReq = req
	if m.createErr != nil {
		return nil, m.createErr
	}
	if m.createdTenant != nil {
		return m.createdTenant, nil
	}
	entity := &tenant.TenantEntity{
		ID:          "tenant-" + req.Name,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		State:       tenant.StateActive,
		OVSBridge:   "br-" + req.Name,
		Labels:      req.Labels,
		Annotations: req.Annotations,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if req.VLANRange != nil {
		entity.VLANRange = *req.VLANRange
	}
	m.tenants[entity.ID] = entity
	return entity, nil
}

func (m *mockTenantManager) GetTenant(ctx context.Context, id string) (*tenant.TenantEntity, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	entity, ok := m.tenants[id]
	if !ok {
		return nil, tenant.ErrTenantNotFound{ID: id}
	}
	return entity, nil
}

func (m *mockTenantManager) GetTenantByName(ctx context.Context, name string) (*tenant.TenantEntity, error) {
	if m.getByNameErr != nil {
		return nil, m.getByNameErr
	}
	for _, e := range m.tenants {
		if e.Name == name {
			return e, nil
		}
	}
	return nil, tenant.ErrTenantNotFound{Name: name}
}

func (m *mockTenantManager) ListTenants(ctx context.Context, limit, offset int) ([]*tenant.TenantEntity, int, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	tenants := make([]*tenant.TenantEntity, 0, len(m.tenants))
	for _, t := range m.tenants {
		tenants = append(tenants, t)
	}

	total := len(tenants)
	if offset >= len(tenants) {
		return []*tenant.TenantEntity{}, total, nil
	}
	end := offset + limit
	if end > len(tenants) {
		end = len(tenants)
	}
	return tenants[offset:end], total, nil
}

func (m *mockTenantManager) UpdateTenant(ctx context.Context, id string, req *tenant.UpdateTenantRequest) (*tenant.TenantEntity, error) {
	m.lastUpdateReq = req
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	if m.updatedTenant != nil {
		return m.updatedTenant, nil
	}
	entity, ok := m.tenants[id]
	if !ok {
		return nil, tenant.ErrTenantNotFound{ID: id}
	}
	if req.DisplayName != nil {
		entity.DisplayName = *req.DisplayName
	}
	if req.Labels != nil {
		entity.Labels = req.Labels
	}
	if req.Annotations != nil {
		entity.Annotations = req.Annotations
	}
	entity.UpdatedAt = time.Now()
	return entity, nil
}

func (m *mockTenantManager) DeleteTenant(ctx context.Context, id string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.tenants[id]; !ok {
		return tenant.ErrTenantNotFound{ID: id}
	}
	delete(m.tenants, id)
	delete(m.quotas, id)
	delete(m.usage, id)
	return nil
}

func (m *mockTenantManager) SuspendTenant(ctx context.Context, id string) error {
	if m.suspendErr != nil {
		return m.suspendErr
	}
	entity, ok := m.tenants[id]
	if !ok {
		return tenant.ErrTenantNotFound{ID: id}
	}
	entity.State = tenant.StateSuspended
	return nil
}

func (m *mockTenantManager) ResumeTenant(ctx context.Context, id string) error {
	if m.resumeErr != nil {
		return m.resumeErr
	}
	entity, ok := m.tenants[id]
	if !ok {
		return tenant.ErrTenantNotFound{ID: id}
	}
	entity.State = tenant.StateActive
	return nil
}

func (m *mockTenantManager) GetQuotas(ctx context.Context, tenantID string) (*tenant.TenantQuotas, error) {
	if m.getQuotasErr != nil {
		return nil, m.getQuotasErr
	}
	q, ok := m.quotas[tenantID]
	if !ok {
		return nil, tenant.ErrTenantNotFound{ID: tenantID}
	}
	return q, nil
}

func (m *mockTenantManager) UpdateQuotas(ctx context.Context, tenantID string, quotas *tenant.TenantQuotas) error {
	m.lastQuotasUpdated = quotas
	if m.updateQuotasErr != nil {
		return m.updateQuotasErr
	}
	if _, ok := m.quotas[tenantID]; !ok {
		return tenant.ErrTenantNotFound{ID: tenantID}
	}
	m.quotas[tenantID] = quotas
	return nil
}

func (m *mockTenantManager) GetUsage(ctx context.Context, tenantID string) (*quota.TenantUsage, error) {
	if m.usageErr != nil {
		return nil, m.usageErr
	}
	u, ok := m.usage[tenantID]
	if !ok {
		return nil, tenant.ErrTenantNotFound{ID: tenantID}
	}
	return u, nil
}

func (m *mockTenantManager) CheckQuota(ctx context.Context, tenantID string, resource quota.ResourceType, amount int64) error {
	if m.checkQuotaErr != nil {
		return m.checkQuotaErr
	}
	return nil
}

func (m *mockTenantManager) ValidateVLAN(ctx context.Context, tenantID string, vlanID uint16) error {
	if m.validateVLANErr != nil {
		return m.validateVLANErr
	}
	return nil
}

func (m *mockTenantManager) GetBridgeName(ctx context.Context, tenantID string) (string, error) {
	if m.bridgeErr != nil {
		return "", m.bridgeErr
	}
	entity, ok := m.tenants[tenantID]
	if !ok {
		return "", tenant.ErrTenantNotFound{ID: tenantID}
	}
	return entity.OVSBridge, nil
}

func (m *mockTenantManager) Sync(ctx context.Context) error {
	if m.syncErr != nil {
		return m.syncErr
	}
	return nil
}

func (m *mockTenantManager) RotateTenantDEK(ctx context.Context, tenantID string, background bool) (*tenant.DEKRotationResult, error) {
	m.lastRotateBack = background
	if m.rotateDEKErr != nil {
		return nil, m.rotateDEKErr
	}
	if _, ok := m.tenants[tenantID]; !ok {
		return nil, tenant.ErrTenantNotFound{ID: tenantID}
	}
	if m.dekRotationResult != nil {
		return m.dekRotationResult, nil
	}
	return &tenant.DEKRotationResult{
		OldVersion: 1,
		NewVersion: 2,
	}, nil
}

func (m *mockTenantManager) GetTenantDEKStatus(ctx context.Context, tenantID string) (*tenant.DEKStatus, error) {
	if m.getDEKStatusErr != nil {
		return nil, m.getDEKStatusErr
	}
	if _, ok := m.tenants[tenantID]; !ok {
		return nil, tenant.ErrTenantNotFound{ID: tenantID}
	}
	if m.dekStatus != nil {
		return m.dekStatus, nil
	}
	return &tenant.DEKStatus{
		Path:           "/keys/" + tenantID + "/dek",
		Algorithm:      "AES-256-GCM",
		Version:        1,
		Status:         "active",
		IsDefault:      true,
		CreatedAt:      time.Now().Add(-24 * time.Hour),
		RotatedAt:      time.Now().Add(-1 * time.Hour),
		UsageCount:     1000,
		BytesUsed:      1024 * 1024,
		MaxUsageCount:  100000,
		MaxBytesUsed:   1024 * 1024 * 1024,
		WarningPercent: 80,
		UsagePercent:   1.0,
		NeedsRotation:  false,
	}, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestTenantHandlersWithMock(mgr *mockTenantManager) *TenantHandlers {
	return NewTenantHandlers(
		WithTenantManager(mgr),
		WithTenantLogger(slog.Default()),
	)
}

func createTestTenantEntity(id, name string) *tenant.TenantEntity {
	return &tenant.TenantEntity{
		ID:          id,
		Name:        name,
		DisplayName: name,
		State:       tenant.StateActive,
		OVSBridge:   "br-tenant-" + name,
		VLANRange: tenant.VLANRange{
			Start: 100,
			End:   199,
		},
		ComputeQuota: tenant.ComputeQuota{
			MaxVMs:        10,
			MaxContainers: 50,
			MaxVCPUs:      32,
			MaxMemoryMB:   65536,
			MaxDiskGB:     1024,
		},
		NetworkQuota: tenant.NetworkQuota{
			MaxBridges:       5,
			MaxPorts:         100,
			MaxBandwidthMbps: 10000,
		},
		StorageQuota: tenant.StorageQuota{
			MaxVolumesGB: 2048,
			MaxSnapshots: 100,
		},
		Labels:      map[string]string{"env": "test"},
		Annotations: map[string]string{"note": "test tenant"},
		CreatedAt:   time.Now().Add(-time.Hour),
		UpdatedAt:   time.Now(),
	}
}

func executeTenantRequest(router *mux.Router, method, path string, body interface{}) *httptest.ResponseRecorder {
	var reqBody *bytes.Buffer
	if body != nil {
		data, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(data)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req, _ := http.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrTenantManagerNotAvailable(t *testing.T) {
	err := ErrTenantManagerNotAvailable{}
	expected := "tenant manager not available"
	if err.Error() != expected {
		t.Errorf("Expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidTenantID(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		expected string
	}{
		{
			name:     "empty ID",
			id:       "",
			expected: "tenant ID is required",
		},
		{
			name:     "invalid ID",
			id:       "bad-id",
			expected: "invalid tenant ID: bad-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidTenantID{ID: tt.id}
			if err.Error() != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, err.Error())
			}
		})
	}
}

func TestErrInvalidTenantName(t *testing.T) {
	tests := []struct {
		name       string
		tenantName string
		expected   string
	}{
		{
			name:       "empty name",
			tenantName: "",
			expected:   "tenant name is required",
		},
		{
			name:       "invalid name",
			tenantName: "bad-name",
			expected:   "invalid tenant name: bad-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidTenantName{Name: tt.tenantName}
			if err.Error() != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, err.Error())
			}
		})
	}
}

func TestErrTenantOperationFailed(t *testing.T) {
	cause := tenant.ErrTenantNotFound{ID: "test-id"}
	err := ErrTenantOperationFailed{
		Operation: "get_tenant",
		Cause:     cause,
	}

	expectedMsg := "tenant operation get_tenant failed: tenant not found: id=test-id"
	if err.Error() != expectedMsg {
		t.Errorf("Expected %q, got %q", expectedMsg, err.Error())
	}

	if err.Unwrap() != cause {
		t.Errorf("Expected Unwrap to return cause error")
	}
}

func TestErrInvalidResourceType(t *testing.T) {
	err := ErrInvalidResourceType{Resource: "invalid"}
	expected := "invalid resource type: invalid"
	if err.Error() != expected {
		t.Errorf("Expected %q, got %q", expected, err.Error())
	}
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewTenantHandlers(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		h := NewTenantHandlers()
		if h == nil {
			t.Fatal("Expected non-nil handler")
		}
		if h.manager != nil {
			t.Error("Expected nil manager")
		}
		if h.logger == nil {
			t.Error("Expected non-nil logger")
		}
	})

	t.Run("with logger", func(t *testing.T) {
		logger := slog.Default()
		h := NewTenantHandlers(WithTenantLogger(logger))
		if h.logger != logger {
			t.Error("Expected custom logger")
		}
	})

	t.Run("with manager", func(t *testing.T) {
		mgr := newMockTenantManager()
		h := NewTenantHandlers(WithTenantManager(mgr))
		if h.manager != mgr {
			t.Error("Expected custom manager")
		}
	})
}

// =============================================================================
// Handler Tests - Service Unavailable
// =============================================================================

func TestHandlersWithNilManager(t *testing.T) {
	h := NewTenantHandlers()
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	tests := []struct {
		name   string
		method string
		path   string
		body   interface{}
	}{
		{"list", http.MethodGet, "/api/v1/tenants", nil},
		{"create", http.MethodPost, "/api/v1/tenants", CreateTenantRequest{Name: "test"}},
		{"get", http.MethodGet, "/api/v1/tenants/test-id", nil},
		{"getByName", http.MethodGet, "/api/v1/tenants/name/test-name", nil},
		{"update", http.MethodPut, "/api/v1/tenants/test-id", UpdateTenantRequest{}},
		{"delete", http.MethodDelete, "/api/v1/tenants/test-id", nil},
		{"suspend", http.MethodPost, "/api/v1/tenants/test-id/suspend", nil},
		{"resume", http.MethodPost, "/api/v1/tenants/test-id/resume", nil},
		{"getQuotas", http.MethodGet, "/api/v1/tenants/test-id/quotas", nil},
		{"updateQuotas", http.MethodPut, "/api/v1/tenants/test-id/quotas", UpdateQuotasRequest{}},
		{"getUsage", http.MethodGet, "/api/v1/tenants/test-id/usage", nil},
		{"checkQuota", http.MethodPost, "/api/v1/tenants/test-id/check-quota", CheckQuotaRequest{Resource: "vms", Amount: 1}},
		{"validateVLAN", http.MethodPost, "/api/v1/tenants/test-id/validate-vlan", ValidateVLANRequest{VLANID: 100}},
		{"getBridge", http.MethodGet, "/api/v1/tenants/test-id/bridge", nil},
		{"sync", http.MethodPost, "/api/v1/tenants/sync", nil},
		{"rotateDEK", http.MethodPost, "/api/v1/tenants/test-id/dek/rotate", RotateDEKRequest{Background: false}},
		{"getDEKStatus", http.MethodGet, "/api/v1/tenants/test-id/dek/status", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := executeTenantRequest(router, tt.method, tt.path, tt.body)
			if rr.Code != http.StatusServiceUnavailable {
				t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, rr.Code)
			}
		})
	}
}

// =============================================================================
// List Tenants Handler Tests
// =============================================================================

func TestHandleListTenants_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-1", "test-tenant-1"))
	mgr.addTenant(createTestTenantEntity("tenant-2", "test-tenant-2"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp TenantListResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(resp.Tenants) != 2 {
		t.Errorf("Expected 2 tenants, got %d", len(resp.Tenants))
	}

	if resp.Total != 2 {
		t.Errorf("Expected total 2, got %d", resp.Total)
	}
}

func TestHandleListTenants_WithPagination(t *testing.T) {
	mgr := newMockTenantManager()
	for i := 0; i < 5; i++ {
		mgr.addTenant(createTestTenantEntity("tenant-"+string(rune('a'+i)), "test-tenant"))
	}

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants?limit=2&offset=0", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp TenantListResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(resp.Tenants) > 2 {
		t.Errorf("Expected at most 2 tenants, got %d", len(resp.Tenants))
	}
}

func TestHandleListTenants_Error(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.listErr = errors.New("database error")

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants", nil)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

// =============================================================================
// Create Tenant Handler Tests
// =============================================================================

func TestHandleCreateTenant_Success(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := CreateTenantRequest{
		Name:        "new-tenant",
		DisplayName: "New Tenant",
		Labels:      map[string]string{"env": "prod"},
		VLANRange: &VLANRangeRequest{
			Start: 100,
			End:   199,
		},
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants", req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, rr.Code)
	}

	var resp TenantResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Name != "new-tenant" {
		t.Errorf("Expected name %q, got %q", "new-tenant", resp.Name)
	}
}

func TestHandleCreateTenant_MissingName(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := CreateTenantRequest{
		DisplayName: "New Tenant",
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants", req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleCreateTenant_InvalidBody(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/tenants", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleCreateTenant_ManagerError(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.createErr = tenant.ErrTenantExists{Name: "existing"}

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := CreateTenantRequest{
		Name: "existing",
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants", req)

	if rr.Code != http.StatusConflict {
		t.Errorf("Expected status %d, got %d", http.StatusConflict, rr.Code)
	}
}

// =============================================================================
// Get Tenant Handler Tests
// =============================================================================

func TestHandleGetTenant_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/tenant-123", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp TenantResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.ID != "tenant-123" {
		t.Errorf("Expected ID %q, got %q", "tenant-123", resp.ID)
	}
}

func TestHandleGetTenant_NotFound(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/nonexistent", nil)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// =============================================================================
// Get Tenant By Name Handler Tests
// =============================================================================

func TestHandleGetTenantByName_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "my-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/name/my-tenant", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp TenantResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Name != "my-tenant" {
		t.Errorf("Expected name %q, got %q", "my-tenant", resp.Name)
	}
}

func TestHandleGetTenantByName_NotFound(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/name/nonexistent", nil)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// =============================================================================
// Update Tenant Handler Tests
// =============================================================================

func TestHandleUpdateTenant_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	displayName := "Updated Name"
	req := UpdateTenantRequest{
		DisplayName: &displayName,
		Labels:      map[string]string{"updated": "true"},
	}

	rr := executeTenantRequest(router, http.MethodPut, "/api/v1/tenants/tenant-123", req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestHandleUpdateTenant_NotFound(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := UpdateTenantRequest{}

	rr := executeTenantRequest(router, http.MethodPut, "/api/v1/tenants/nonexistent", req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestHandleUpdateTenant_InvalidBody(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req, _ := http.NewRequest(http.MethodPut, "/api/v1/tenants/tenant-123", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// =============================================================================
// Delete Tenant Handler Tests
// =============================================================================

func TestHandleDeleteTenant_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodDelete, "/api/v1/tenants/tenant-123", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp TenantActionResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("Expected success true")
	}

	if resp.Action != "delete" {
		t.Errorf("Expected action 'delete', got %q", resp.Action)
	}
}

func TestHandleDeleteTenant_NotFound(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodDelete, "/api/v1/tenants/nonexistent", nil)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// =============================================================================
// Suspend Tenant Handler Tests
// =============================================================================

func TestHandleSuspendTenant_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/suspend", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp TenantActionResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Action != "suspend" {
		t.Errorf("Expected action 'suspend', got %q", resp.Action)
	}
}

func TestHandleSuspendTenant_NotFound(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/nonexistent/suspend", nil)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestHandleSuspendTenant_Error(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
	mgr.suspendErr = tenant.ErrInvalidTransition{From: "suspended", To: "suspended"}

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/suspend", nil)

	if rr.Code != http.StatusConflict {
		t.Errorf("Expected status %d, got %d", http.StatusConflict, rr.Code)
	}
}

// =============================================================================
// Resume Tenant Handler Tests
// =============================================================================

func TestHandleResumeTenant_Success(t *testing.T) {
	mgr := newMockTenantManager()
	entity := createTestTenantEntity("tenant-123", "test-tenant")
	entity.State = tenant.StateSuspended
	mgr.addTenant(entity)

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/resume", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp TenantActionResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Action != "resume" {
		t.Errorf("Expected action 'resume', got %q", resp.Action)
	}
}

func TestHandleResumeTenant_NotFound(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/nonexistent/resume", nil)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// =============================================================================
// Get Quotas Handler Tests
// =============================================================================

func TestHandleGetQuotas_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/tenant-123/quotas", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp TenantQuotasResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Compute == nil {
		t.Fatal("Expected compute quotas")
	}

	if resp.Compute.MaxVMs != 10 {
		t.Errorf("Expected MaxVMs 10, got %d", resp.Compute.MaxVMs)
	}
}

func TestHandleGetQuotas_NotFound(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/nonexistent/quotas", nil)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// =============================================================================
// Update Quotas Handler Tests
// =============================================================================

func TestHandleUpdateQuotas_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := UpdateQuotasRequest{
		Compute: &ComputeQuotaRequest{
			MaxVMs:        20,
			MaxContainers: 100,
		},
		Network: &NetworkQuotaRequest{
			MaxBridges: 10,
		},
		Storage: &StorageQuotaRequest{
			MaxVolumesGB: 4096,
		},
	}

	rr := executeTenantRequest(router, http.MethodPut, "/api/v1/tenants/tenant-123/quotas", req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp TenantQuotasResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Compute.MaxVMs != 20 {
		t.Errorf("Expected MaxVMs 20, got %d", resp.Compute.MaxVMs)
	}
}

func TestHandleUpdateQuotas_NotFound(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := UpdateQuotasRequest{}

	rr := executeTenantRequest(router, http.MethodPut, "/api/v1/tenants/nonexistent/quotas", req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestHandleUpdateQuotas_InvalidBody(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req, _ := http.NewRequest(http.MethodPut, "/api/v1/tenants/tenant-123/quotas", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleUpdateQuotas_UpdateError(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
	mgr.updateQuotasErr = errors.New("quota update failed")

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := UpdateQuotasRequest{
		Compute: &ComputeQuotaRequest{
			MaxVMs: 20,
		},
	}

	rr := executeTenantRequest(router, http.MethodPut, "/api/v1/tenants/tenant-123/quotas", req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

// =============================================================================
// Get Usage Handler Tests
// =============================================================================

func TestHandleGetUsage_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/tenant-123/usage", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp TenantUsageResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.TenantID != "tenant-123" {
		t.Errorf("Expected tenant ID 'tenant-123', got %q", resp.TenantID)
	}

	if resp.VMs != 5 {
		t.Errorf("Expected VMs 5, got %d", resp.VMs)
	}
}

func TestHandleGetUsage_NotFound(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/nonexistent/usage", nil)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// =============================================================================
// Check Quota Handler Tests
// =============================================================================

func TestHandleCheckQuota_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := CheckQuotaRequest{
		Resource: "vms",
		Amount:   5,
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/check-quota", req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp CheckQuotaResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Allowed {
		t.Error("Expected Allowed true")
	}
}

func TestHandleCheckQuota_Exceeded(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
	mgr.checkQuotaErr = tenant.ErrQuotaExceeded{Resource: "vms"}

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := CheckQuotaRequest{
		Resource: "vms",
		Amount:   100,
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/check-quota", req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp CheckQuotaResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Allowed {
		t.Error("Expected Allowed false")
	}
}

func TestHandleCheckQuota_MissingResource(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := CheckQuotaRequest{
		Amount: 5,
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/check-quota", req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleCheckQuota_InvalidResource(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := CheckQuotaRequest{
		Resource: "invalid-resource",
		Amount:   5,
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/check-quota", req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleCheckQuota_InvalidBody(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/tenants/tenant-123/check-quota", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// =============================================================================
// Validate VLAN Handler Tests
// =============================================================================

func TestHandleValidateVLAN_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := ValidateVLANRequest{
		VLANID: 150,
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/validate-vlan", req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp ValidateVLANResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Valid {
		t.Error("Expected Valid true")
	}
}

func TestHandleValidateVLAN_Invalid(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
	mgr.validateVLANErr = errors.New("VLAN out of range")

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := ValidateVLANRequest{
		VLANID: 500,
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/validate-vlan", req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp ValidateVLANResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Valid {
		t.Error("Expected Valid false")
	}
}

func TestHandleValidateVLAN_MissingVLANID(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := ValidateVLANRequest{}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/validate-vlan", req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleValidateVLAN_InvalidBody(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/tenants/tenant-123/validate-vlan", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// =============================================================================
// Get Bridge Name Handler Tests
// =============================================================================

func TestHandleGetBridgeName_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/tenant-123/bridge", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp BridgeNameResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.BridgeName == "" {
		t.Error("Expected non-empty bridge name")
	}
}

func TestHandleGetBridgeName_NotFound(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/nonexistent/bridge", nil)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

// =============================================================================
// Sync Handler Tests
// =============================================================================

func TestHandleSync_Success(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/sync", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp TenantActionResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Action != "sync" {
		t.Errorf("Expected action 'sync', got %q", resp.Action)
	}

	if !resp.Success {
		t.Error("Expected success true")
	}
}

func TestHandleSync_Error(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.syncErr = errors.New("sync failed")

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/sync", nil)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

// =============================================================================
// Rotate Tenant DEK Handler Tests
// =============================================================================

func TestHandleRotateTenantDEK_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
	mgr.dekRotationResult = &tenant.DEKRotationResult{
		OldVersion: 1,
		NewVersion: 2,
	}

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := RotateDEKRequest{
		Background: false,
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/dek/rotate", req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp RotateDEKResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.TenantID != "tenant-123" {
		t.Errorf("Expected tenant ID 'tenant-123', got %q", resp.TenantID)
	}

	if resp.OldVersion != 1 {
		t.Errorf("Expected OldVersion 1, got %d", resp.OldVersion)
	}

	if resp.NewVersion != 2 {
		t.Errorf("Expected NewVersion 2, got %d", resp.NewVersion)
	}

	if mgr.lastRotateBack != false {
		t.Error("Expected background=false to be passed to manager")
	}
}

func TestHandleRotateTenantDEK_Background(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := RotateDEKRequest{
		Background: true,
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/dek/rotate", req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	if mgr.lastRotateBack != true {
		t.Error("Expected background=true to be passed to manager")
	}
}

func TestHandleRotateTenantDEK_NotFound(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := RotateDEKRequest{
		Background: false,
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/nonexistent/dek/rotate", req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestHandleRotateTenantDEK_Error(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
	mgr.rotateDEKErr = tenant.ErrDEKOperationFailed{Operation: "rotate", Err: errors.New("rotation failed")}

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req := RotateDEKRequest{
		Background: false,
	}

	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/tenant-123/dek/rotate", req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestHandleRotateTenantDEK_InvalidBody(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/tenants/tenant-123/dek/rotate", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// =============================================================================
// Get Tenant DEK Status Handler Tests
// =============================================================================

func TestHandleGetTenantDEKStatus_Success(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
	mgr.dekStatus = &tenant.DEKStatus{
		Path:           "/keys/tenant-123/dek",
		Algorithm:      "AES-256-GCM",
		Version:        3,
		Status:         "active",
		IsDefault:      true,
		CreatedAt:      time.Now().Add(-48 * time.Hour),
		RotatedAt:      time.Now().Add(-1 * time.Hour),
		UsageCount:     5000,
		BytesUsed:      1024 * 1024 * 10,
		MaxUsageCount:  100000,
		MaxBytesUsed:   1024 * 1024 * 1024,
		WarningPercent: 80,
		UsagePercent:   5.0,
		NeedsRotation:  false,
	}

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/tenant-123/dek/status", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp DEKStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.TenantID != "tenant-123" {
		t.Errorf("Expected tenant ID 'tenant-123', got %q", resp.TenantID)
	}

	if resp.Path != "/keys/tenant-123/dek" {
		t.Errorf("Expected path '/keys/tenant-123/dek', got %q", resp.Path)
	}

	if resp.Algorithm != "AES-256-GCM" {
		t.Errorf("Expected algorithm 'AES-256-GCM', got %q", resp.Algorithm)
	}

	if resp.Version != 3 {
		t.Errorf("Expected version 3, got %d", resp.Version)
	}

	if resp.Status != "active" {
		t.Errorf("Expected status 'active', got %q", resp.Status)
	}

	if !resp.IsDefault {
		t.Error("Expected IsDefault true")
	}

	if resp.UsageCount != 5000 {
		t.Errorf("Expected UsageCount 5000, got %d", resp.UsageCount)
	}

	if resp.NeedsRotation {
		t.Error("Expected NeedsRotation false")
	}
}

func TestHandleGetTenantDEKStatus_WithReencryptionProgress(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
	startedAt := time.Now().Add(-5 * time.Minute)
	estimatedCompletion := time.Now().Add(10 * time.Minute)
	mgr.dekStatus = &tenant.DEKStatus{
		Path:           "/keys/tenant-123/dek",
		Algorithm:      "AES-256-GCM",
		Version:        3,
		Status:         "rotating",
		IsDefault:      true,
		CreatedAt:      time.Now().Add(-48 * time.Hour),
		RotatedAt:      time.Now().Add(-1 * time.Hour),
		UsageCount:     5000,
		BytesUsed:      1024 * 1024 * 10,
		MaxUsageCount:  100000,
		MaxBytesUsed:   1024 * 1024 * 1024,
		WarningPercent: 80,
		UsagePercent:   5.0,
		NeedsRotation:  false,
		ReencryptProgress: &tenant.ReencryptionProgress{
			InProgress:          true,
			TotalKeys:           1000,
			ProcessedKeys:       500,
			FailedKeys:          2,
			StartedAt:           startedAt,
			EstimatedCompletion: estimatedCompletion,
		},
	}

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/tenant-123/dek/status", nil)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var resp DEKStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.ReencryptionProgress == nil {
		t.Fatal("Expected ReencryptionProgress to be present")
	}

	if !resp.ReencryptionProgress.InProgress {
		t.Error("Expected InProgress true")
	}

	if resp.ReencryptionProgress.TotalKeys != 1000 {
		t.Errorf("Expected TotalKeys 1000, got %d", resp.ReencryptionProgress.TotalKeys)
	}

	if resp.ReencryptionProgress.ProcessedKeys != 500 {
		t.Errorf("Expected ProcessedKeys 500, got %d", resp.ReencryptionProgress.ProcessedKeys)
	}

	if resp.ReencryptionProgress.FailedKeys != 2 {
		t.Errorf("Expected FailedKeys 2, got %d", resp.ReencryptionProgress.FailedKeys)
	}
}

func TestHandleGetTenantDEKStatus_NotFound(t *testing.T) {
	mgr := newMockTenantManager()

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/nonexistent/dek/status", nil)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestHandleGetTenantDEKStatus_Error(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
	mgr.getDEKStatusErr = tenant.ErrDEKOperationFailed{Operation: "get_status", Err: errors.New("status retrieval failed")}

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/tenant-123/dek/status", nil)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

// =============================================================================
// TenantToResponse Tests
// =============================================================================

func TestTenantToResponse(t *testing.T) {
	mgr := newMockTenantManager()
	h := newTestTenantHandlersWithMock(mgr)

	entity := createTestTenantEntity("tenant-123", "test-tenant")
	resp := h.tenantToResponse(entity)

	if resp.ID != entity.ID {
		t.Errorf("Expected ID %q, got %q", entity.ID, resp.ID)
	}

	if resp.Name != entity.Name {
		t.Errorf("Expected name %q, got %q", entity.Name, resp.Name)
	}

	if resp.State != string(entity.State) {
		t.Errorf("Expected state %q, got %q", entity.State, resp.State)
	}

	if resp.VLANRange == nil {
		t.Fatal("Expected VLAN range")
	}

	if resp.VLANRange.Start != entity.VLANRange.Start {
		t.Errorf("Expected VLAN start %d, got %d", entity.VLANRange.Start, resp.VLANRange.Start)
	}

	if resp.ComputeQuota == nil {
		t.Fatal("Expected compute quota")
	}

	if resp.ComputeQuota.MaxVMs != entity.ComputeQuota.MaxVMs {
		t.Errorf("Expected MaxVMs %d, got %d", entity.ComputeQuota.MaxVMs, resp.ComputeQuota.MaxVMs)
	}
}

func TestTenantToResponse_EmptyVLANRange(t *testing.T) {
	mgr := newMockTenantManager()
	h := newTestTenantHandlersWithMock(mgr)

	entity := createTestTenantEntity("tenant-123", "test-tenant")
	entity.VLANRange = tenant.VLANRange{} // Empty

	resp := h.tenantToResponse(entity)

	if resp.VLANRange != nil {
		t.Error("Expected nil VLAN range for empty range")
	}
}

// =============================================================================
// WriteTenantError Tests
// =============================================================================

func TestWriteTenantError_ErrorMapping(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"TenantNotFound", tenant.ErrTenantNotFound{ID: "test"}, http.StatusNotFound},
		{"TenantExists", tenant.ErrTenantExists{Name: "test"}, http.StatusConflict},
		{"InvalidRequest", tenant.ErrInvalidRequest{Reason: "test"}, http.StatusBadRequest},
		{"InvalidState", tenant.ErrInvalidState{Current: tenant.StateActive}, http.StatusBadRequest},
		{"InvalidTransition", tenant.ErrInvalidTransition{From: "a", To: "b"}, http.StatusConflict},
		{"QuotaExceeded", tenant.ErrQuotaExceeded{Resource: "vms"}, http.StatusForbidden},
		{"ResourceLimitReached", tenant.ErrResourceLimitReached{Resource: "vms"}, http.StatusForbidden},
		{"InvalidVLANRange", tenant.ErrInvalidVLANRange{Start: 100, End: 50}, http.StatusBadRequest},
		{"VLANAllocationFailed", tenant.ErrVLANAllocationFailed{TenantID: "test"}, http.StatusInternalServerError},
		{"BridgeOperationFailed", tenant.ErrBridgeOperationFailed{Operation: "test"}, http.StatusInternalServerError},
		{"DEKOperationFailed", tenant.ErrDEKOperationFailed{Operation: "test"}, http.StatusInternalServerError},
		{"StorageFailed", tenant.ErrStorageFailed{Operation: "test"}, http.StatusInternalServerError},
		{"Unknown", errors.New("unknown error"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newMockTenantManager()
			mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

			switch tt.name {
			case "TenantNotFound":
				mgr.getErr = tt.err
			case "TenantExists":
				mgr.createErr = tt.err
			default:
				mgr.listErr = tt.err
			}

			h := newTestTenantHandlersWithMock(mgr)
			router := mux.NewRouter()
			h.RegisterRoutes(router)

			var rr *httptest.ResponseRecorder
			switch tt.name {
			case "TenantNotFound":
				rr = executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/tenant-123", nil)
			case "TenantExists":
				rr = executeTenantRequest(router, http.MethodPost, "/api/v1/tenants", CreateTenantRequest{Name: "test"})
			default:
				rr = executeTenantRequest(router, http.MethodGet, "/api/v1/tenants", nil)
			}

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

// =============================================================================
// Route Registration Tests
// =============================================================================

func TestTenantHandlers_RegisterRoutes(t *testing.T) {
	h := NewTenantHandlers()
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/tenants"},
		{http.MethodPost, "/api/v1/tenants"},
		{http.MethodPost, "/api/v1/tenants/sync"},
		{http.MethodGet, "/api/v1/tenants/name/{name}"},
		{http.MethodGet, "/api/v1/tenants/{id}"},
		{http.MethodPut, "/api/v1/tenants/{id}"},
		{http.MethodDelete, "/api/v1/tenants/{id}"},
		{http.MethodPost, "/api/v1/tenants/{id}/suspend"},
		{http.MethodPost, "/api/v1/tenants/{id}/resume"},
		{http.MethodGet, "/api/v1/tenants/{id}/quotas"},
		{http.MethodPut, "/api/v1/tenants/{id}/quotas"},
		{http.MethodGet, "/api/v1/tenants/{id}/usage"},
		{http.MethodPost, "/api/v1/tenants/{id}/check-quota"},
		{http.MethodPost, "/api/v1/tenants/{id}/validate-vlan"},
		{http.MethodGet, "/api/v1/tenants/{id}/bridge"},
		{http.MethodPost, "/api/v1/tenants/{id}/dek/rotate"},
		{http.MethodGet, "/api/v1/tenants/{id}/dek/status"},
	}

	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			match := &mux.RouteMatch{}
			req, _ := http.NewRequest(rt.method, rt.path, nil)
			if !router.Match(req, match) {
				t.Errorf("Route %s %s not registered", rt.method, rt.path)
			}
		})
	}
}

// =============================================================================
// Content-Type Header Tests
// =============================================================================

func TestContentTypeHeaders(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants", nil)

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got %q", contentType)
	}
}

// =============================================================================
// Request/Response Type Tests
// =============================================================================

func TestCreateTenantRequestSerialization(t *testing.T) {
	req := CreateTenantRequest{
		Name:        "test-tenant",
		DisplayName: "Test Tenant",
		Labels:      map[string]string{"env": "prod"},
		Annotations: map[string]string{"note": "test"},
		VLANRange: &VLANRangeRequest{
			Start: 100,
			End:   199,
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded CreateTenantRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Name != req.Name {
		t.Errorf("Expected name %q, got %q", req.Name, decoded.Name)
	}

	if decoded.VLANRange == nil {
		t.Fatal("Expected VLAN range")
	}

	if decoded.VLANRange.Start != 100 || decoded.VLANRange.End != 199 {
		t.Errorf("Expected VLAN range 100-199, got %d-%d",
			decoded.VLANRange.Start, decoded.VLANRange.End)
	}
}

func TestTenantResponseSerialization(t *testing.T) {
	now := time.Now().UTC()
	resp := TenantResponse{
		ID:          "tenant-123",
		Name:        "test-tenant",
		DisplayName: "Test Tenant",
		State:       "active",
		OVSBridge:   "br-tenant-test",
		VLANRange: &VLANRangeResponse{
			Start: 100,
			End:   199,
		},
		ComputeQuota: &ComputeQuotaResp{
			MaxVMs: 10,
		},
		NetworkQuota: &NetworkQuotaResp{
			MaxBridges: 5,
		},
		StorageQuota: &StorageQuotaResp{
			MaxVolumesGB: 2048,
		},
		Labels:    map[string]string{"env": "test"},
		CreatedAt: now,
		UpdatedAt: now,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded TenantResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.ID != resp.ID {
		t.Errorf("Expected ID %q, got %q", resp.ID, decoded.ID)
	}

	if decoded.State != "active" {
		t.Errorf("Expected state 'active', got %q", decoded.State)
	}
}

func TestRotateDEKRequestSerialization(t *testing.T) {
	req := RotateDEKRequest{
		Background: true,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded RotateDEKRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Background != true {
		t.Errorf("Expected Background true, got %v", decoded.Background)
	}
}

func TestRotateDEKResponseSerialization(t *testing.T) {
	now := time.Now().UTC()
	resp := RotateDEKResponse{
		TenantID:   "tenant-123",
		OldVersion: 1,
		NewVersion: 2,
		Timestamp:  now,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded RotateDEKResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.TenantID != "tenant-123" {
		t.Errorf("Expected TenantID 'tenant-123', got %q", decoded.TenantID)
	}

	if decoded.OldVersion != 1 {
		t.Errorf("Expected OldVersion 1, got %d", decoded.OldVersion)
	}

	if decoded.NewVersion != 2 {
		t.Errorf("Expected NewVersion 2, got %d", decoded.NewVersion)
	}
}

func TestDEKStatusResponseSerialization(t *testing.T) {
	now := time.Now().UTC()
	resp := DEKStatusResponse{
		TenantID:       "tenant-123",
		Path:           "/keys/tenant-123/dek",
		Algorithm:      "AES-256-GCM",
		Version:        3,
		Status:         "active",
		IsDefault:      true,
		CreatedAt:      now.Add(-48 * time.Hour),
		RotatedAt:      now.Add(-1 * time.Hour),
		UsageCount:     5000,
		BytesUsed:      1024 * 1024 * 10,
		MaxUsageCount:  100000,
		MaxBytesUsed:   1024 * 1024 * 1024,
		WarningPercent: 80,
		UsagePercent:   5.0,
		NeedsRotation:  false,
		Timestamp:      now,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded DEKStatusResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.TenantID != "tenant-123" {
		t.Errorf("Expected TenantID 'tenant-123', got %q", decoded.TenantID)
	}

	if decoded.Algorithm != "AES-256-GCM" {
		t.Errorf("Expected Algorithm 'AES-256-GCM', got %q", decoded.Algorithm)
	}

	if decoded.Version != 3 {
		t.Errorf("Expected Version 3, got %d", decoded.Version)
	}
}

// =============================================================================
// Functional Options Tests
// =============================================================================

func TestWithTenantManagerOption(t *testing.T) {
	mgr := newMockTenantManager()
	opt := WithTenantManager(mgr)

	h := &TenantHandlers{}
	opt(h)

	if h.manager != mgr {
		t.Error("Expected WithTenantManager to set the manager")
	}
}

func TestWithTenantLoggerOption(t *testing.T) {
	logger := slog.Default()
	opt := WithTenantLogger(logger)

	h := &TenantHandlers{}
	opt(h)

	if h.logger != logger {
		t.Error("Expected WithTenantLogger to set the logger")
	}
}

// =============================================================================
// Context Handling Tests
// =============================================================================

func TestContextPropagation(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))

	h := newTestTenantHandlersWithMock(mgr)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}
