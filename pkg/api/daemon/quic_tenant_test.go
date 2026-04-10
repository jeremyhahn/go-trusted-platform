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

//go:build codec_msgpack

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
)

func init() {
	// Initialize the QUIC codec for tests
	_ = quic.SetDefaultCodecType(codec.MsgPack)
}

// mockTenantManager is a mock implementation of TenantManagerInterface for testing
type mockTenantManager struct {
	// Configurable responses
	tenants           []*tenant.TenantEntity
	tenant            *tenant.TenantEntity
	quotas            *tenant.TenantQuotas
	usage             *quota.TenantUsage
	bridgeName        string
	dekRotationResult *tenant.DEKRotationResult
	dekStatus         *tenant.DEKStatus
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
	getUsageErr       error
	checkQuotaErr     error
	validateVLANErr   error
	getBridgeErr      error
	syncErr           error
	rotateDEKErr      error
	getDEKStatusErr   error

	// Counters for verification
	createCalled       int
	getCalled          int
	getByNameCalled    int
	listCalled         int
	updateCalled       int
	deleteCalled       int
	suspendCalled      int
	resumeCalled       int
	getQuotasCalled    int
	updateQuotasCalled int
	getUsageCalled     int
	checkQuotaCalled   int
	validateVLANCalled int
	getBridgeCalled    int
	syncCalled         int
	rotateDEKCalled    int
	getDEKStatusCalled int
}

func newMockTenantManager() *mockTenantManager {
	return &mockTenantManager{
		tenant: &tenant.TenantEntity{
			ID:          "tenant-123",
			Name:        "test-tenant",
			DisplayName: "Test Tenant",
			State:       tenant.StateActive,
			OVSBridge:   "br-tenant-123",
			VLANRange:   tenant.VLANRange{Start: 100, End: 199},
			Labels:      map[string]string{"env": "test"},
			Annotations: map[string]string{"description": "test tenant"},
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
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		quotas: &tenant.TenantQuotas{
			Compute: tenant.ComputeQuota{
				MaxVMs:        10,
				MaxContainers: 50,
				MaxVCPUs:      32,
				MaxMemoryMB:   65536,
				MaxDiskGB:     1024,
			},
			Network: tenant.NetworkQuota{
				MaxBridges:       5,
				MaxPorts:         100,
				MaxBandwidthMbps: 10000,
			},
			Storage: tenant.StorageQuota{
				MaxVolumesGB: 2048,
				MaxSnapshots: 100,
			},
		},
		usage: &quota.TenantUsage{
			TenantID:   "tenant-123",
			VMs:        2,
			Containers: 10,
			VCPUs:      8,
			MemoryMB:   16384,
			DiskGB:     256,
			Bridges:    1,
			Ports:      20,
			Volumes:    5,
			Snapshots:  10,
			Timestamp:  time.Now(),
		},
		bridgeName: "br-tenant-123",
		dekRotationResult: &tenant.DEKRotationResult{
			TenantID:   "tenant-123",
			OldVersion: 1,
			NewVersion: 2,
			Timestamp:  time.Now(),
		},
		dekStatus: &tenant.DEKStatus{
			Path:           "/tenant/tenant-123/default",
			Algorithm:      "AES-256-GCM",
			Version:        2,
			Status:         "active",
			IsDefault:      true,
			CreatedAt:      time.Now().Add(-24 * time.Hour),
			RotatedAt:      time.Now().Add(-1 * time.Hour),
			UsageCount:     1000,
			BytesUsed:      1024000,
			MaxUsageCount:  1000000,
			MaxBytesUsed:   10737418240,
			WarningPercent: 80,
			UsagePercent:   10.5,
			NeedsRotation:  false,
		},
	}
}

func (m *mockTenantManager) CreateTenant(ctx context.Context, req *tenant.CreateTenantRequest) (*tenant.TenantEntity, error) {
	m.createCalled++
	if m.createErr != nil {
		return nil, m.createErr
	}
	result := *m.tenant
	result.Name = req.Name
	if req.DisplayName != "" {
		result.DisplayName = req.DisplayName
	}
	return &result, nil
}

func (m *mockTenantManager) GetTenant(ctx context.Context, id string) (*tenant.TenantEntity, error) {
	m.getCalled++
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.tenant, nil
}

func (m *mockTenantManager) GetTenantByName(ctx context.Context, name string) (*tenant.TenantEntity, error) {
	m.getByNameCalled++
	if m.getByNameErr != nil {
		return nil, m.getByNameErr
	}
	return m.tenant, nil
}

func (m *mockTenantManager) ListTenants(ctx context.Context, limit, offset int) ([]*tenant.TenantEntity, int, error) {
	m.listCalled++
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	if m.tenants == nil {
		return []*tenant.TenantEntity{m.tenant}, 1, nil
	}
	return m.tenants, len(m.tenants), nil
}

func (m *mockTenantManager) UpdateTenant(ctx context.Context, id string, req *tenant.UpdateTenantRequest) (*tenant.TenantEntity, error) {
	m.updateCalled++
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	return m.tenant, nil
}

func (m *mockTenantManager) DeleteTenant(ctx context.Context, id string) error {
	m.deleteCalled++
	return m.deleteErr
}

func (m *mockTenantManager) SuspendTenant(ctx context.Context, id string) error {
	m.suspendCalled++
	return m.suspendErr
}

func (m *mockTenantManager) ResumeTenant(ctx context.Context, id string) error {
	m.resumeCalled++
	return m.resumeErr
}

func (m *mockTenantManager) GetQuotas(ctx context.Context, tenantID string) (*tenant.TenantQuotas, error) {
	m.getQuotasCalled++
	if m.getQuotasErr != nil {
		return nil, m.getQuotasErr
	}
	return m.quotas, nil
}

func (m *mockTenantManager) UpdateQuotas(ctx context.Context, tenantID string, quotas *tenant.TenantQuotas) error {
	m.updateQuotasCalled++
	return m.updateQuotasErr
}

func (m *mockTenantManager) GetUsage(ctx context.Context, tenantID string) (*quota.TenantUsage, error) {
	m.getUsageCalled++
	if m.getUsageErr != nil {
		return nil, m.getUsageErr
	}
	return m.usage, nil
}

func (m *mockTenantManager) CheckQuota(ctx context.Context, tenantID string, resource quota.ResourceType, amount int64) error {
	m.checkQuotaCalled++
	return m.checkQuotaErr
}

func (m *mockTenantManager) ValidateVLAN(ctx context.Context, tenantID string, vlanID uint16) error {
	m.validateVLANCalled++
	return m.validateVLANErr
}

func (m *mockTenantManager) GetBridgeName(ctx context.Context, tenantID string) (string, error) {
	m.getBridgeCalled++
	if m.getBridgeErr != nil {
		return "", m.getBridgeErr
	}
	return m.bridgeName, nil
}

func (m *mockTenantManager) Sync(ctx context.Context) error {
	m.syncCalled++
	return m.syncErr
}

func (m *mockTenantManager) RotateDEK(ctx context.Context, tenantID string, background bool) (*tenant.DEKRotationResult, error) {
	m.rotateDEKCalled++
	if m.rotateDEKErr != nil {
		return nil, m.rotateDEKErr
	}
	return m.dekRotationResult, nil
}

func (m *mockTenantManager) GetDEKStatus(ctx context.Context, tenantID string) (*tenant.DEKStatus, error) {
	m.getDEKStatusCalled++
	if m.getDEKStatusErr != nil {
		return nil, m.getDEKStatusErr
	}
	return m.dekStatus, nil
}

// Test helper to create handler with tenant manager
func newTestTenantHandler(t *testing.T, mgr TenantManagerInterface) *QUICServiceHandler {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger, WithQUICTenantManager(mgr))
	return handler
}

// TestHandleTenantRotateDEK tests the rotate DEK operation
func TestHandleTenantRotateDEK(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mgr := newMockTenantManager()
		handler := newTestTenantHandler(t, mgr)
		ctx := context.Background()

		rotateReq := &TenantRotateDEKRequest{
			TenantID:   "tenant-123",
			Background: false,
		}
		payload, _ := quic.EncodePayload(rotateReq)

		req := &quic.Request{
			Opcode:  OpTenantRotateDEK,
			Payload: payload,
		}

		resp := handler.handleTenantOperation(ctx, req)
		if resp.Status != quic.StatusOK {
			t.Errorf("expected StatusOK, got %d", resp.Status)
		}
		if mgr.rotateDEKCalled != 1 {
			t.Errorf("expected rotateDEKCalled=1, got %d", mgr.rotateDEKCalled)
		}

		// Decode and verify response
		var rotateResp TenantRotateDEKResponse
		if err := quic.DecodePayload(resp.Payload, &rotateResp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if rotateResp.TenantID != "tenant-123" {
			t.Errorf("expected TenantID=tenant-123, got %s", rotateResp.TenantID)
		}
		if rotateResp.OldVersion != 1 {
			t.Errorf("expected OldVersion=1, got %d", rotateResp.OldVersion)
		}
		if rotateResp.NewVersion != 2 {
			t.Errorf("expected NewVersion=2, got %d", rotateResp.NewVersion)
		}
	})

	t.Run("success with background", func(t *testing.T) {
		mgr := newMockTenantManager()
		handler := newTestTenantHandler(t, mgr)
		ctx := context.Background()

		rotateReq := &TenantRotateDEKRequest{
			TenantID:   "tenant-123",
			Background: true,
		}
		payload, _ := quic.EncodePayload(rotateReq)

		req := &quic.Request{
			Opcode:  OpTenantRotateDEK,
			Payload: payload,
		}

		resp := handler.handleTenantOperation(ctx, req)
		if resp.Status != quic.StatusOK {
			t.Errorf("expected StatusOK, got %d", resp.Status)
		}
	})

	t.Run("missing tenant ID", func(t *testing.T) {
		mgr := newMockTenantManager()
		handler := newTestTenantHandler(t, mgr)
		ctx := context.Background()

		rotateReq := &TenantRotateDEKRequest{TenantID: ""}
		payload, _ := quic.EncodePayload(rotateReq)

		req := &quic.Request{
			Opcode:  OpTenantRotateDEK,
			Payload: payload,
		}

		resp := handler.handleTenantOperation(ctx, req)
		if resp.Status != quic.StatusInvalidArgument {
			t.Errorf("expected StatusInvalidArgument, got %d", resp.Status)
		}
	})

	t.Run("rotation failed", func(t *testing.T) {
		mgr := newMockTenantManager()
		mgr.rotateDEKErr = errors.New("DEK rotation failed: KMS unavailable")
		handler := newTestTenantHandler(t, mgr)
		ctx := context.Background()

		rotateReq := &TenantRotateDEKRequest{TenantID: "tenant-123"}
		payload, _ := quic.EncodePayload(rotateReq)

		req := &quic.Request{
			Opcode:  OpTenantRotateDEK,
			Payload: payload,
		}

		resp := handler.handleTenantOperation(ctx, req)
		if resp.Status != quic.StatusInternalError {
			t.Errorf("expected StatusInternalError, got %d", resp.Status)
		}
	})
}

// TestHandleTenantGetDEKStatus tests the get DEK status operation
func TestHandleTenantGetDEKStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mgr := newMockTenantManager()
		handler := newTestTenantHandler(t, mgr)
		ctx := context.Background()

		statusReq := &TenantGetDEKStatusRequest{TenantID: "tenant-123"}
		payload, _ := quic.EncodePayload(statusReq)

		req := &quic.Request{
			Opcode:  OpTenantGetDEKStatus,
			Payload: payload,
		}

		resp := handler.handleTenantOperation(ctx, req)
		if resp.Status != quic.StatusOK {
			t.Errorf("expected StatusOK, got %d", resp.Status)
		}
		if mgr.getDEKStatusCalled != 1 {
			t.Errorf("expected getDEKStatusCalled=1, got %d", mgr.getDEKStatusCalled)
		}

		// Decode and verify response
		var statusResp QUICTenantDEKStatusResponse
		if err := quic.DecodePayload(resp.Payload, &statusResp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if statusResp.TenantID != "tenant-123" {
			t.Errorf("expected TenantID=tenant-123, got %s", statusResp.TenantID)
		}
		if statusResp.Path != "/tenant/tenant-123/default" {
			t.Errorf("expected Path=/tenant/tenant-123/default, got %s", statusResp.Path)
		}
		if statusResp.Algorithm != "AES-256-GCM" {
			t.Errorf("expected Algorithm=AES-256-GCM, got %s", statusResp.Algorithm)
		}
		if statusResp.Version != 2 {
			t.Errorf("expected Version=2, got %d", statusResp.Version)
		}
		if statusResp.Status != "active" {
			t.Errorf("expected Status=active, got %s", statusResp.Status)
		}
		if !statusResp.IsDefault {
			t.Error("expected IsDefault=true")
		}
		if statusResp.NeedsRotation {
			t.Error("expected NeedsRotation=false")
		}
		if statusResp.RotatedAt == 0 {
			t.Error("expected RotatedAt to be set")
		}
	})

	t.Run("success without rotation timestamp", func(t *testing.T) {
		mgr := newMockTenantManager()
		// Set RotatedAt to zero time
		mgr.dekStatus.RotatedAt = time.Time{}
		handler := newTestTenantHandler(t, mgr)
		ctx := context.Background()

		statusReq := &TenantGetDEKStatusRequest{TenantID: "tenant-123"}
		payload, _ := quic.EncodePayload(statusReq)

		req := &quic.Request{
			Opcode:  OpTenantGetDEKStatus,
			Payload: payload,
		}

		resp := handler.handleTenantOperation(ctx, req)
		if resp.Status != quic.StatusOK {
			t.Errorf("expected StatusOK, got %d", resp.Status)
		}

		// Decode and verify RotatedAt is 0
		var statusResp QUICTenantDEKStatusResponse
		if err := quic.DecodePayload(resp.Payload, &statusResp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if statusResp.RotatedAt != 0 {
			t.Errorf("expected RotatedAt=0, got %d", statusResp.RotatedAt)
		}
	})

	t.Run("missing tenant ID", func(t *testing.T) {
		mgr := newMockTenantManager()
		handler := newTestTenantHandler(t, mgr)
		ctx := context.Background()

		statusReq := &TenantGetDEKStatusRequest{TenantID: ""}
		payload, _ := quic.EncodePayload(statusReq)

		req := &quic.Request{
			Opcode:  OpTenantGetDEKStatus,
			Payload: payload,
		}

		resp := handler.handleTenantOperation(ctx, req)
		if resp.Status != quic.StatusInvalidArgument {
			t.Errorf("expected StatusInvalidArgument, got %d", resp.Status)
		}
	})

	t.Run("DEK not found", func(t *testing.T) {
		mgr := newMockTenantManager()
		mgr.getDEKStatusErr = errors.New("DEK not found")
		handler := newTestTenantHandler(t, mgr)
		ctx := context.Background()

		statusReq := &TenantGetDEKStatusRequest{TenantID: "nonexistent"}
		payload, _ := quic.EncodePayload(statusReq)

		req := &quic.Request{
			Opcode:  OpTenantGetDEKStatus,
			Payload: payload,
		}

		resp := handler.handleTenantOperation(ctx, req)
		if resp.Status != quic.StatusNotFound {
			t.Errorf("expected StatusNotFound, got %d", resp.Status)
		}
	})
}

// TestHandleTenantOperationNoManager tests tenant operations without manager
func TestHandleTenantOperationNoManager(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  OpTenantRotateDEK,
		Payload: nil,
	}

	resp := handler.handleTenantOperation(ctx, req)
	if resp.Status != quic.StatusUnavailable {
		t.Errorf("expected StatusUnavailable, got %d", resp.Status)
	}
}

// TestTenantDEKErrorTypes tests custom error type formatting for DEK operations
func TestTenantDEKErrorTypes(t *testing.T) {
	t.Run("ErrTenantDEKRotationFailed", func(t *testing.T) {
		err := ErrTenantDEKRotationFailed{TenantID: "test-123", Cause: errors.New("rotation error")}
		expected := "tenant DEK rotation failed for test-123: rotation error"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %v, want %v", got, expected)
		}
	})

	t.Run("ErrTenantDEKNotFound", func(t *testing.T) {
		err := ErrTenantDEKNotFound{TenantID: "test-123"}
		expected := "tenant DEK not found for: test-123"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %v, want %v", got, expected)
		}
	})
}

// TestTenantDEKErrorUnwrap tests error unwrapping for DEK rotation error
func TestTenantDEKErrorUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	var err error = ErrTenantDEKRotationFailed{TenantID: "test", Cause: cause}

	unwrapper, ok := err.(interface{ Unwrap() error })
	if !ok {
		t.Fatal("error does not implement Unwrap")
	}
	if got := unwrapper.Unwrap(); got != cause {
		t.Errorf("Unwrap() = %v, want %v", got, cause)
	}
}
