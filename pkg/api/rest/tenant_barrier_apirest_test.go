package rest

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

func newBarrierTestRouter(mgr *mockTenantManager) *mux.Router {
	router := mux.NewRouter()
	newTestTenantHandlersWithMock(mgr).RegisterRoutes(router)
	return router
}

func barrierStatus(t *testing.T, router *mux.Router, id string) TenantBarrierStatusResponse {
	t.Helper()
	rr := executeTenantRequest(router, http.MethodGet, "/api/v1/tenants/"+id+"/barrier/status", nil)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var st TenantBarrierStatusResponse
	decodeResponse(t, rr.Body, &st)
	return st
}

func barrierAction(t *testing.T, router *mux.Router, id, action string, body interface{}) TenantBarrierActionResponse {
	t.Helper()
	rr := executeTenantRequest(router, http.MethodPost, "/api/v1/tenants/"+id+"/barrier/"+action, body)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp TenantBarrierActionResponse
	decodeResponse(t, rr.Body, &resp)
	return resp
}

func TestTenantBarrierAPIRest_Lifecycle(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
	router := newBarrierTestRouter(mgr)

	st := barrierStatus(t, router, "tenant-123")
	assert.Equal(t, "tenant-123", st.TenantID)
	assert.True(t, st.Sealed, "an uninitialized barrier reports sealed")
	assert.False(t, st.Initialized)

	resp := barrierAction(t, router, "tenant-123", "init", InitTenantBarrierRequest{Threshold: 2, Shares: 3})
	assert.Equal(t, TenantBarrierActionResponse{
		TenantID: "tenant-123", Success: true, Message: "tenant barrier initialized", Timestamp: resp.Timestamp,
	}, resp)
	assert.False(t, resp.Timestamp.IsZero())

	st = barrierStatus(t, router, "tenant-123")
	assert.True(t, st.Initialized)
	assert.False(t, st.Sealed)
	assert.Equal(t, "software", st.Strategy)
	assert.False(t, st.HardwareBacked)

	resp = barrierAction(t, router, "tenant-123", "seal", nil)
	assert.Equal(t, "tenant barrier sealed", resp.Message)
	assert.True(t, barrierStatus(t, router, "tenant-123").Sealed)

	resp = barrierAction(t, router, "tenant-123", "unseal", nil)
	assert.Equal(t, "tenant barrier unsealed", resp.Message)
	assert.Empty(t, mgr.lastUnsealKey, "an empty body unseals with the deterministic key")
	assert.False(t, barrierStatus(t, router, "tenant-123").Sealed)
}

func TestTenantBarrierAPIRest_InitWithoutBody(t *testing.T) {
	mgr := newMockTenantManager()
	mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
	router := newBarrierTestRouter(mgr)

	resp := barrierAction(t, router, "tenant-123", "init", nil)
	assert.True(t, resp.Success)
	assert.True(t, mgr.barrierStates["tenant-123"].Initialized)
}

func TestTenantBarrierAPIRest_ManagerErrors(t *testing.T) {
	operations := []struct {
		name      string
		method    string
		operation string
		setErr    func(m *mockTenantManager, err error)
	}{
		{"init", http.MethodPost, "init_tenant_barrier", func(m *mockTenantManager, err error) { m.initBarrierErr = err }},
		{"unseal", http.MethodPost, "unseal_tenant_barrier", func(m *mockTenantManager, err error) { m.unsealBarrierErr = err }},
		{"seal", http.MethodPost, "seal_tenant_barrier", func(m *mockTenantManager, err error) { m.sealBarrierErr = err }},
		{"status", http.MethodGet, "tenant_barrier_status", func(m *mockTenantManager, err error) { m.barrierStatusErr = err }},
	}
	errorCases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"not found", tenant.ErrTenantNotFound{ID: "tenant-123"}, http.StatusNotFound},
		{"not supported", tenant.ErrBarrierNotSupported{Operation: "op"}, http.StatusNotImplemented},
		{"operation failed", tenant.ErrBarrierOperationFailed{TenantID: "tenant-123", Operation: "op", Err: errors.New("io")}, http.StatusInternalServerError},
		{"untyped", errors.New("unexpected"), http.StatusInternalServerError},
	}

	for _, op := range operations {
		for _, ec := range errorCases {
			t.Run(op.name+"/"+ec.name, func(t *testing.T) {
				mgr := newMockTenantManager()
				mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
				op.setErr(mgr, ec.err)
				router := newBarrierTestRouter(mgr)

				rr := executeTenantRequest(router, op.method, "/api/v1/tenants/tenant-123/barrier/"+op.name, nil)

				require.Equal(t, ec.wantStatus, rr.Code, rr.Body.String())
				var errResp ErrorResponse
				decodeResponse(t, rr.Body, &errResp)
				assert.Equal(t, ErrTenantOperationFailed{Operation: op.operation, Cause: ec.err}.Error(), errResp.Error)
			})
		}
	}
}

func TestTenantBarrierAPIRest_InvalidBody(t *testing.T) {
	for _, action := range []string{"init", "unseal"} {
		t.Run(action, func(t *testing.T) {
			mgr := newMockTenantManager()
			mgr.addTenant(createTestTenantEntity("tenant-123", "test-tenant"))
			router := newBarrierTestRouter(mgr)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/tenant-123/barrier/"+action, strings.NewReader(`{"key":`))
			req.Header.Set("Authorization", "Bearer "+tenantSystemToken)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			var errResp ErrorResponse
			decodeResponse(t, rr.Body, &errResp)
			assert.Contains(t, errResp.Error, "invalid request body")
			assert.Nil(t, mgr.barrierStates["tenant-123"], "a rejected request must not reach the manager")
		})
	}
}

// The barrier handlers refuse to run without a manager or a tenant ID; the
// router never produces an empty {id}, so they are driven directly.
func TestTenantBarrierAPIRest_Preconditions(t *testing.T) {
	withManager := newTestTenantHandlersWithMock(newMockTenantManager())
	withoutManager := NewTenantHandlers()

	handlers := func(h *TenantHandlers) map[string]http.HandlerFunc {
		return map[string]http.HandlerFunc{
			"init":   h.handleInitTenantBarrier,
			"unseal": h.handleUnsealTenantBarrier,
			"seal":   h.handleSealTenantBarrier,
			"status": h.handleTenantBarrierStatus,
		}
	}

	for name, handle := range handlers(withoutManager) {
		t.Run(name+"/no manager", func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "tenant-123"})
			rr := httptest.NewRecorder()
			handle(rr, req)
			require.Equal(t, http.StatusServiceUnavailable, rr.Code)
			var errResp ErrorResponse
			decodeResponse(t, rr.Body, &errResp)
			assert.Equal(t, ErrTenantManagerNotAvailable{}.Error(), errResp.Error)
		})
	}
	for name, handle := range handlers(withManager) {
		t.Run(name+"/empty id", func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": ""})
			rr := httptest.NewRecorder()
			handle(rr, req)
			require.Equal(t, http.StatusBadRequest, rr.Code)
			var errResp ErrorResponse
			decodeResponse(t, rr.Body, &errResp)
			assert.Equal(t, ErrInvalidTenantID{}.Error(), errResp.Error)
		})
	}
}
