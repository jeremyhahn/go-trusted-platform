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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Overlay Error Type Tests
// =============================================================================

func TestOverlayErrors(t *testing.T) {
	t.Parallel()

	t.Run("ErrOverlayServiceNotAvailable", func(t *testing.T) {
		t.Parallel()
		err := ErrOverlayServiceNotAvailable{}
		assert.Equal(t, "overlay service not available", err.Error())
	})

	t.Run("ErrInvalidNodeID_empty", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidNodeID{ID: ""}
		assert.Equal(t, "node ID is required", err.Error())
	})

	t.Run("ErrInvalidNodeID_with_value", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidNodeID{ID: "bad-node-id"}
		assert.Equal(t, "invalid node ID: bad-node-id", err.Error())
	})

	t.Run("ErrInvalidVNI", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidVNI{VNI: 16777216}
		assert.Equal(t, "invalid VNI: 16777216", err.Error())
	})

	t.Run("ErrInvalidMAC_empty", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidMAC{MAC: ""}
		assert.Equal(t, "MAC address is required", err.Error())
	})

	t.Run("ErrInvalidMAC_with_value", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidMAC{MAC: "invalid-mac"}
		assert.Equal(t, "invalid MAC address: invalid-mac", err.Error())
	})

	t.Run("ErrVTEPNotFound", func(t *testing.T) {
		t.Parallel()
		err := ErrVTEPNotFound{NodeID: "node-123"}
		assert.Equal(t, "VTEP not found for node: node-123", err.Error())
	})

	t.Run("ErrVNINotFound", func(t *testing.T) {
		t.Parallel()
		err := ErrVNINotFound{VNI: 100}
		assert.Equal(t, "VNI not found: 100", err.Error())
	})

	t.Run("ErrVNIAlreadyExists", func(t *testing.T) {
		t.Parallel()
		err := ErrVNIAlreadyExists{VNI: 100}
		assert.Equal(t, "VNI already exists: 100", err.Error())
	})

	t.Run("ErrMACNotFound", func(t *testing.T) {
		t.Parallel()
		err := ErrMACNotFound{MAC: "aa:bb:cc:dd:ee:ff"}
		assert.Equal(t, "MAC not found: aa:bb:cc:dd:ee:ff", err.Error())
	})

	t.Run("ErrOverlayOperationFailed", func(t *testing.T) {
		t.Parallel()
		cause := errors.New("underlying error")
		err := ErrOverlayOperationFailed{Operation: "create", Cause: cause}
		assert.Equal(t, "overlay operation create failed: underlying error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrOverlayOperationFailed_unwrap_nil", func(t *testing.T) {
		t.Parallel()
		err := ErrOverlayOperationFailed{Operation: "delete", Cause: nil}
		assert.Equal(t, "overlay operation delete failed: <nil>", err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

// =============================================================================
// Overlay Error Interface Compliance Tests
// =============================================================================

func TestOverlayErrorsImplementError(t *testing.T) {
	t.Parallel()

	// Verify all overlay error types implement the error interface
	tests := []struct {
		name string
		err  error
	}{
		{"ErrOverlayServiceNotAvailable", ErrOverlayServiceNotAvailable{}},
		{"ErrInvalidNodeID", ErrInvalidNodeID{ID: "test"}},
		{"ErrInvalidVNI", ErrInvalidVNI{VNI: 100}},
		{"ErrInvalidMAC", ErrInvalidMAC{MAC: "test"}},
		{"ErrVTEPNotFound", ErrVTEPNotFound{NodeID: "test"}},
		{"ErrVNINotFound", ErrVNINotFound{VNI: 100}},
		{"ErrVNIAlreadyExists", ErrVNIAlreadyExists{VNI: 100}},
		{"ErrMACNotFound", ErrMACNotFound{MAC: "test"}},
		{"ErrOverlayOperationFailed", ErrOverlayOperationFailed{Operation: "test", Cause: nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Type assertion to verify error interface implementation
			var _ = tt.err
			assert.NotEmpty(t, tt.err.Error())
		})
	}
}

// =============================================================================
// Mock Overlay Service
// =============================================================================

type mockOverlayService struct {
	getStatusResp      *OverlayStatusResponse
	getStatusErr       error
	listVTEPsResp      []VTEPInfoResponse
	listVTEPsErr       error
	getVTEPResp        *VTEPInfoResponse
	getVTEPErr         error
	createVNIResp      *VNIResponse
	createVNIErr       error
	deleteVNIErr       error
	listVNIsResp       []VNIResponse
	listVNIsErr        error
	listTunnelsResp    []TunnelInfoResponse
	listTunnelsErr     error
	listRemoteMACsResp []RemoteMACResponse
	listRemoteMACsErr  error
	forgetMACErr       error
}

func newMockOverlayService() *mockOverlayService {
	return &mockOverlayService{}
}

func (m *mockOverlayService) GetOverlayStatus(ctx context.Context) (*OverlayStatusResponse, error) {
	if m.getStatusErr != nil {
		return nil, m.getStatusErr
	}
	if m.getStatusResp != nil {
		return m.getStatusResp, nil
	}
	return &OverlayStatusResponse{
		NodeID:         "node-1",
		VTEPIP:         "10.0.0.1",
		VTEPCount:      5,
		VNICount:       10,
		TunnelCount:    8,
		RemoteMACCount: 100,
		Healthy:        true,
	}, nil
}

func (m *mockOverlayService) ListVTEPs(ctx context.Context) ([]VTEPInfoResponse, error) {
	if m.listVTEPsErr != nil {
		return nil, m.listVTEPsErr
	}
	if m.listVTEPsResp != nil {
		return m.listVTEPsResp, nil
	}
	return []VTEPInfoResponse{
		{
			NodeID:   "node-1",
			IP:       "10.0.0.1",
			Healthy:  true,
			LastSeen: time.Now(),
		},
		{
			NodeID:   "node-2",
			IP:       "10.0.0.2",
			Healthy:  true,
			LastSeen: time.Now(),
		},
	}, nil
}

func (m *mockOverlayService) GetVTEP(ctx context.Context, nodeID string) (*VTEPInfoResponse, error) {
	if m.getVTEPErr != nil {
		return nil, m.getVTEPErr
	}
	if m.getVTEPResp != nil {
		return m.getVTEPResp, nil
	}
	return &VTEPInfoResponse{
		NodeID:   nodeID,
		IP:       "10.0.0.1",
		Healthy:  true,
		LastSeen: time.Now(),
	}, nil
}

func (m *mockOverlayService) CreateVNI(ctx context.Context, config *VNIConfigRequest) (*VNIResponse, error) {
	if m.createVNIErr != nil {
		return nil, m.createVNIErr
	}
	if m.createVNIResp != nil {
		return m.createVNIResp, nil
	}
	return &VNIResponse{
		ID:        "vni-100",
		Config:    *config,
		CreatedAt: time.Now(),
		MACCount:  0,
	}, nil
}

func (m *mockOverlayService) DeleteVNI(ctx context.Context, vni uint32) error {
	return m.deleteVNIErr
}

func (m *mockOverlayService) ListVNIs(ctx context.Context) ([]VNIResponse, error) {
	if m.listVNIsErr != nil {
		return nil, m.listVNIsErr
	}
	if m.listVNIsResp != nil {
		return m.listVNIsResp, nil
	}
	return []VNIResponse{
		{
			ID: "vni-100",
			Config: VNIConfigRequest{
				VNI:  100,
				VLAN: 10,
				Name: "test-vni",
			},
			CreatedAt: time.Now(),
			MACCount:  5,
		},
	}, nil
}

func (m *mockOverlayService) ListTunnels(ctx context.Context, vni uint32) ([]TunnelInfoResponse, error) {
	if m.listTunnelsErr != nil {
		return nil, m.listTunnelsErr
	}
	if m.listTunnelsResp != nil {
		return m.listTunnelsResp, nil
	}
	return []TunnelInfoResponse{
		{
			LocalVTEP:  "10.0.0.1",
			RemoteVTEP: "10.0.0.2",
			VNI:        100,
			State:      "active",
			BytesTx:    1024,
			BytesRx:    2048,
		},
	}, nil
}

func (m *mockOverlayService) ListRemoteMACs(ctx context.Context, vni uint32) ([]RemoteMACResponse, error) {
	if m.listRemoteMACsErr != nil {
		return nil, m.listRemoteMACsErr
	}
	if m.listRemoteMACsResp != nil {
		return m.listRemoteMACsResp, nil
	}
	return []RemoteMACResponse{
		{
			MAC:        "aa:bb:cc:dd:ee:ff",
			VNI:        100,
			RemoteVTEP: "10.0.0.2",
			LearnedAt:  time.Now(),
		},
	}, nil
}

func (m *mockOverlayService) ForgetMAC(ctx context.Context, mac string, vni uint32) error {
	return m.forgetMACErr
}

// =============================================================================
// Test Helpers
// =============================================================================

func setupOverlayTestHandler(svc *mockOverlayService) (*OverlayHandlers, *mux.Router) {
	logger := slog.Default()
	handlers := NewOverlayHandlers(svc, logger)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return handlers, router
}

func decodeOverlayResponse(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	err := json.NewDecoder(resp.Body).Decode(v)
	require.NoError(t, err)
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewOverlayHandlers(t *testing.T) {
	t.Parallel()

	t.Run("creates handlers with service and logger", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		logger := slog.Default()
		handlers := NewOverlayHandlers(svc, logger)
		require.NotNil(t, handlers)
		assert.Equal(t, svc, handlers.overlayService)
		assert.Equal(t, logger, handlers.logger)
	})

	t.Run("creates handlers with nil logger uses default", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		handlers := NewOverlayHandlers(svc, nil)
		require.NotNil(t, handlers)
		assert.NotNil(t, handlers.logger)
	})

	t.Run("creates handlers with nil service", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		require.NotNil(t, handlers)
		assert.Nil(t, handlers.overlayService)
	})
}

func TestSetOverlayService(t *testing.T) {
	t.Parallel()

	t.Run("sets overlay service", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		require.Nil(t, handlers.overlayService)

		svc := newMockOverlayService()
		handlers.SetOverlayService(svc)
		assert.Equal(t, svc, handlers.overlayService)
	})
}

func TestOverlayRegisterRoutes(t *testing.T) {
	t.Parallel()

	t.Run("registers all overlay routes", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		routes := []struct {
			method string
			path   string
		}{
			{http.MethodGet, "/api/v1/sdn/overlay/status"},
			{http.MethodGet, "/api/v1/sdn/overlay/vteps"},
			{http.MethodGet, "/api/v1/sdn/overlay/vteps/node-1"},
			{http.MethodGet, "/api/v1/sdn/overlay/vnis"},
			{http.MethodPost, "/api/v1/sdn/overlay/vnis"},
			{http.MethodDelete, "/api/v1/sdn/overlay/vnis/100"},
			{http.MethodGet, "/api/v1/sdn/overlay/tunnels"},
			{http.MethodGet, "/api/v1/sdn/overlay/macs"},
			{http.MethodDelete, "/api/v1/sdn/overlay/macs/aa:bb:cc:dd:ee:ff"},
		}

		for _, route := range routes {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			matched := router.Match(req, match)
			assert.True(t, matched, "Route %s %s should be registered", route.method, route.path)
		}
	})
}

// =============================================================================
// Overlay Status Handler Tests
// =============================================================================

func TestHandleGetOverlayStatus(t *testing.T) {
	t.Parallel()

	t.Run("returns overlay status successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var status OverlayStatusResponse
		decodeOverlayResponse(t, resp, &status)
		assert.Equal(t, "node-1", status.NodeID)
		assert.True(t, status.Healthy)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

		var errResp OverlayErrorResponse
		decodeOverlayResponse(t, resp, &errResp)
		assert.Contains(t, errResp.Error, "overlay service not available")
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		svc.getStatusErr = errors.New("service error")
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// VTEP Handler Tests
// =============================================================================

func TestHandleListVTEPs(t *testing.T) {
	t.Parallel()

	t.Run("returns VTEPs successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/vteps", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var vtepsResp VTEPListResponse
		decodeOverlayResponse(t, resp, &vtepsResp)
		assert.Equal(t, 2, vtepsResp.Count)
		assert.Equal(t, "node-1", vtepsResp.VTEPs[0].NodeID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/vteps", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		svc.listVTEPsErr = errors.New("service error")
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/vteps", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

func TestHandleGetVTEP(t *testing.T) {
	t.Parallel()

	t.Run("returns VTEP successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/vteps/node-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var vtep VTEPInfoResponse
		decodeOverlayResponse(t, resp, &vtep)
		assert.Equal(t, "node-1", vtep.NodeID)
		assert.True(t, vtep.Healthy)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/vteps/node-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when VTEP not found", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		svc.getVTEPErr = ErrVTEPNotFound{NodeID: "node-1"}
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/vteps/node-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// =============================================================================
// VNI Handler Tests
// =============================================================================

func TestHandleListVNIs(t *testing.T) {
	t.Parallel()

	t.Run("returns VNIs successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/vnis", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var vnisResp VNIListResponse
		decodeOverlayResponse(t, resp, &vnisResp)
		assert.Equal(t, 1, vnisResp.Count)
		assert.Equal(t, uint32(100), vnisResp.VNIs[0].Config.VNI)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/vnis", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		svc.listVNIsErr = errors.New("service error")
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/vnis", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

func TestHandleCreateVNI(t *testing.T) {
	t.Parallel()

	t.Run("creates VNI successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		reqBody := VNIConfigRequest{
			VNI:  100,
			VLAN: 10,
			Name: "test-vni",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/overlay/vnis", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var vniResp VNIResponse
		decodeOverlayResponse(t, resp, &vniResp)
		assert.Equal(t, uint32(100), vniResp.Config.VNI)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := VNIConfigRequest{VNI: 100}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/overlay/vnis", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON body", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/overlay/vnis", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for missing VNI", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		reqBody := VNIConfigRequest{Name: "test-vni"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/overlay/vnis", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid VNI value", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		reqBody := VNIConfigRequest{VNI: 16777216} // Greater than max VXLAN VNI
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/overlay/vnis", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	// 65636 would wrap to VLAN 100 in the uint16 VNIConfig.
	for _, vlan := range []uint32{4095, 65636} {
		t.Run(fmt.Sprintf("refuses VLAN %d with 400", vlan), func(t *testing.T) {
			t.Parallel()
			svc := newMockOverlayService()
			_, router := setupOverlayTestHandler(svc)

			body, err := json.Marshal(VNIConfigRequest{VNI: 100, VLAN: vlan})
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/overlay/vnis", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			respBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(respBody), ErrInvalidVLAN{VLAN: vlan}.Error())
		})
	}

	t.Run("returns error when VNI already exists", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		svc.createVNIErr = ErrVNIAlreadyExists{VNI: 100}
		_, router := setupOverlayTestHandler(svc)

		reqBody := VNIConfigRequest{VNI: 100}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/overlay/vnis", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})
}

func TestHandleDeleteVNI(t *testing.T) {
	t.Parallel()

	t.Run("deletes VNI successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/overlay/vnis/100", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp OverlayActionResponse
		decodeOverlayResponse(t, resp, &actionResp)
		assert.True(t, actionResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/overlay/vnis/100", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid VNI format", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/overlay/vnis/invalid", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when VNI not found", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		svc.deleteVNIErr = ErrVNINotFound{VNI: 100}
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/overlay/vnis/100", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// =============================================================================
// Tunnel Handler Tests
// =============================================================================

func TestHandleListTunnels(t *testing.T) {
	t.Parallel()

	t.Run("returns tunnels successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/tunnels", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var tunnelsResp TunnelListResponse
		decodeOverlayResponse(t, resp, &tunnelsResp)
		assert.Equal(t, 1, tunnelsResp.Count)
		assert.Equal(t, "10.0.0.1", tunnelsResp.Tunnels[0].LocalVTEP)
	})

	t.Run("returns tunnels with VNI filter", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/tunnels?vni=100", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/tunnels", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid VNI filter", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/tunnels?vni=invalid", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		svc.listTunnelsErr = errors.New("service error")
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/tunnels", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// MAC Handler Tests
// =============================================================================

func TestHandleListRemoteMACs(t *testing.T) {
	t.Parallel()

	t.Run("returns remote MACs successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/macs", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var macsResp RemoteMACListResponse
		decodeOverlayResponse(t, resp, &macsResp)
		assert.Equal(t, 1, macsResp.Count)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", macsResp.MACs[0].MAC)
	})

	t.Run("returns remote MACs with VNI filter", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/macs?vni=100", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/macs", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid VNI filter", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/macs?vni=invalid", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		svc.listRemoteMACsErr = errors.New("service error")
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/overlay/macs", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

func TestHandleForgetMAC(t *testing.T) {
	t.Parallel()

	t.Run("forgets MAC successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/overlay/macs/aa:bb:cc:dd:ee:ff", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp OverlayActionResponse
		decodeOverlayResponse(t, resp, &actionResp)
		assert.True(t, actionResp.Success)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", actionResp.ResourceID)
	})

	t.Run("forgets MAC with VNI filter", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/overlay/macs/aa:bb:cc:dd:ee:ff?vni=100", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/overlay/macs/aa:bb:cc:dd:ee:ff", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid VNI filter", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/overlay/macs/aa:bb:cc:dd:ee:ff?vni=invalid", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when MAC not found", func(t *testing.T) {
		t.Parallel()
		svc := newMockOverlayService()
		svc.forgetMACErr = ErrMACNotFound{MAC: "aa:bb:cc:dd:ee:ff"}
		_, router := setupOverlayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/overlay/macs/aa:bb:cc:dd:ee:ff", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// =============================================================================
// Helper Method Tests
// =============================================================================

func TestOverlayWriteOverlayError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"ErrVTEPNotFound", ErrVTEPNotFound{NodeID: "test"}, http.StatusNotFound},
		{"ErrVNINotFound", ErrVNINotFound{VNI: 100}, http.StatusNotFound},
		{"ErrVNIAlreadyExists", ErrVNIAlreadyExists{VNI: 100}, http.StatusConflict},
		{"ErrMACNotFound", ErrMACNotFound{MAC: "test"}, http.StatusNotFound},
		{"ErrInvalidVNI", ErrInvalidVNI{VNI: 100}, http.StatusBadRequest},
		{"ErrInvalidNodeID", ErrInvalidNodeID{ID: "test"}, http.StatusBadRequest},
		{"ErrInvalidMAC", ErrInvalidMAC{MAC: "test"}, http.StatusBadRequest},
		{"ErrOverlayServiceNotAvailable", ErrOverlayServiceNotAvailable{}, http.StatusServiceUnavailable},
		{"UnknownError", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handlers := NewOverlayHandlers(nil, nil)
			w := httptest.NewRecorder()
			handlers.writeOverlayError(w, "test_op", tt.err)
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestOverlayWriteJSON(t *testing.T) {
	t.Parallel()

	t.Run("writes JSON response successfully", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		w := httptest.NewRecorder()

		data := map[string]string{"key": "value"}
		handlers.writeJSON(w, http.StatusOK, data)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var result map[string]string
		err := json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		assert.Equal(t, "value", result["key"])
	})
}

func TestOverlayWriteError(t *testing.T) {
	t.Parallel()

	t.Run("writes error response", func(t *testing.T) {
		t.Parallel()
		handlers := NewOverlayHandlers(nil, nil)
		w := httptest.NewRecorder()

		handlers.writeError(w, http.StatusBadRequest, errors.New("test error"))

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var errResp OverlayErrorResponse
		err := json.NewDecoder(w.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "test error", errResp.Error)
		assert.Equal(t, http.StatusBadRequest, errResp.Code)
	})
}
