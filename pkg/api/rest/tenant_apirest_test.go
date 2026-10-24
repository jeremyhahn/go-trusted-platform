package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

func tenantErrorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var errResp ErrorResponse
	decodeResponse(t, rec.Body, &errResp)
	return errResp.Error
}

// The router never yields an empty {id}, so the ID-scoped handlers are
// driven directly to prove they refuse before reaching the manager.
func TestTenantAPIRest_EmptyID(t *testing.T) {
	h := newTestTenantHandlersWithMock(newMockTenantManager())
	handlers := map[string]http.HandlerFunc{
		"get":           h.handleGetTenant,
		"update":        h.handleUpdateTenant,
		"delete":        h.handleDeleteTenant,
		"suspend":       h.handleSuspendTenant,
		"resume":        h.handleResumeTenant,
		"get quotas":    h.handleGetQuotas,
		"update quotas": h.handleUpdateQuotas,
		"usage":         h.handleGetUsage,
		"check quota":   h.handleCheckQuota,
		"rotate dek":    h.handleRotateTenantDEK,
		"dek status":    h.handleGetTenantDEKStatus,
	}
	for name, handle := range handlers {
		t.Run(name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), map[string]string{"id": ""})
			rec := httptest.NewRecorder()
			handle(rec, req)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, ErrInvalidTenantID{}.Error(), tenantErrorMessage(t, rec))
		})
	}
}

func TestTenantAPIRest_GetByEmptyName(t *testing.T) {
	h := newTestTenantHandlersWithMock(newMockTenantManager())
	req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	h.handleGetTenantByName(rec, req, nil)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, ErrInvalidTenantName{}.Error(), tenantErrorMessage(t, rec))
}

// Every positive field in the request replaces the stored limit; the
// response and the persisted quotas carry the merged result.
func TestTenantAPIRest_UpdateQuotasEveryField(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
	mgr.quotas["tenant-123"] = &tenant.TenantQuotas{
		Compute: tenant.ComputeQuota{MaxVMs: 1, MaxContainers: 1, MaxVCPUs: 1, MaxMemoryMB: 1, MaxDiskGB: 1},
		Network: tenant.NetworkQuota{MaxBridges: 1, MaxPorts: 1, MaxBandwidthMbps: 1},
		Storage: tenant.StorageQuota{MaxVolumesGB: 1, MaxSnapshots: 1},
	}
	router := newBarrierTestRouter(mgr)

	body := map[string]interface{}{
		"compute": map[string]int64{"max_vms": 2, "max_containers": 3, "max_vcpus": 4, "max_memory_mb": 5, "max_disk_gb": 6},
		"network": map[string]int64{"max_bridges": 7, "max_ports": 8, "max_bandwidth_mbps": 9},
		"storage": map[string]int64{"max_volumes_gb": 10, "max_snapshots": 11},
	}
	rec := executeTenantRequest(router, http.MethodPut, "/api/v1/tenants/tenant-123/quotas", body)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp TenantQuotasResponse
	decodeResponse(t, rec.Body, &resp)
	assert.Equal(t, "tenant-123", resp.TenantID)
	assert.Equal(t, &ComputeQuotaResp{MaxVMs: 2, MaxContainers: 3, MaxVCPUs: 4, MaxMemoryMB: 5, MaxDiskGB: 6}, resp.Compute)
	assert.Equal(t, &NetworkQuotaResp{MaxBridges: 7, MaxPorts: 8, MaxBandwidthMbps: 9}, resp.Network)
	assert.Equal(t, &StorageQuotaResp{MaxVolumesGB: 10, MaxSnapshots: 11}, resp.Storage)
	assert.False(t, resp.Timestamp.IsZero())

	stored := mgr.quotas["tenant-123"]
	assert.Equal(t, tenant.ComputeQuota{MaxVMs: 2, MaxContainers: 3, MaxVCPUs: 4, MaxMemoryMB: 5, MaxDiskGB: 6}, stored.Compute)
	assert.Equal(t, tenant.NetworkQuota{MaxBridges: 7, MaxPorts: 8, MaxBandwidthMbps: 9}, stored.Network)
	assert.Equal(t, tenant.StorageQuota{MaxVolumesGB: 10, MaxSnapshots: 11}, stored.Storage)
}

func TestTenantAPIRest_WriteJSONEncodeFailure(t *testing.T) {
	h := newTestTenantHandlersWithMock(newMockTenantManager())
	rec := httptest.NewRecorder()

	h.writeJSON(rec, http.StatusOK, map[string]interface{}{"ch": make(chan int)})

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.String())
}
