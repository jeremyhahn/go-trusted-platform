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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Gateway Error Type Tests
// =============================================================================

func TestGatewayErrors(t *testing.T) {
	t.Parallel()

	t.Run("ErrGatewayServiceNotAvailable", func(t *testing.T) {
		t.Parallel()
		err := ErrGatewayServiceNotAvailable{}
		assert.Equal(t, "gateway service not available", err.Error())
	})

	t.Run("ErrInvalidGatewayMode", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidGatewayMode{Mode: 999}
		assert.Equal(t, "invalid gateway mode: 999", err.Error())
	})

	t.Run("ErrInvalidPrefix_empty", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidPrefix{Prefix: ""}
		assert.Equal(t, "prefix is required", err.Error())
	})

	t.Run("ErrInvalidPrefix_with_value", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidPrefix{Prefix: "invalid-prefix"}
		assert.Equal(t, "invalid prefix: invalid-prefix", err.Error())
	})

	t.Run("ErrInvalidIPAddress_empty", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidIPAddress{IP: ""}
		assert.Equal(t, "IP address is required", err.Error())
	})

	t.Run("ErrInvalidIPAddress_with_value", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidIPAddress{IP: "256.256.256.256"}
		assert.Equal(t, "invalid IP address: 256.256.256.256", err.Error())
	})

	t.Run("ErrInvalidPoolID_empty", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidPoolID{ID: ""}
		assert.Equal(t, "pool ID is required", err.Error())
	})

	t.Run("ErrInvalidPoolID_with_value", func(t *testing.T) {
		t.Parallel()
		err := ErrInvalidPoolID{ID: "bad-pool-id"}
		assert.Equal(t, "invalid pool ID: bad-pool-id", err.Error())
	})

	t.Run("ErrBGPNotEnabled", func(t *testing.T) {
		t.Parallel()
		err := ErrBGPNotEnabled{}
		assert.Equal(t, "BGP is not enabled", err.Error())
	})

	t.Run("ErrBGPPeerNotFound", func(t *testing.T) {
		t.Parallel()
		err := ErrBGPPeerNotFound{Address: "192.168.1.1"}
		assert.Equal(t, "BGP peer not found: 192.168.1.1", err.Error())
	})

	t.Run("ErrPrefixNotFound", func(t *testing.T) {
		t.Parallel()
		err := ErrPrefixNotFound{Prefix: "10.0.0.0/8"}
		assert.Equal(t, "prefix not found: 10.0.0.0/8", err.Error())
	})

	t.Run("ErrPrefixAlreadyAnnounced", func(t *testing.T) {
		t.Parallel()
		err := ErrPrefixAlreadyAnnounced{Prefix: "10.0.0.0/8"}
		assert.Equal(t, "prefix already announced: 10.0.0.0/8", err.Error())
	})

	t.Run("ErrIPAMPoolNotFound", func(t *testing.T) {
		t.Parallel()
		err := ErrIPAMPoolNotFound{ID: "pool-123"}
		assert.Equal(t, "IPAM pool not found: pool-123", err.Error())
	})

	t.Run("ErrIPAMPoolAlreadyExists", func(t *testing.T) {
		t.Parallel()
		err := ErrIPAMPoolAlreadyExists{ID: "pool-123"}
		assert.Equal(t, "IPAM pool already exists: pool-123", err.Error())
	})

	t.Run("ErrIPAMPoolHasAllocations", func(t *testing.T) {
		t.Parallel()
		err := ErrIPAMPoolHasAllocations{ID: "pool-123"}
		assert.Equal(t, "IPAM pool has active allocations: pool-123", err.Error())
	})

	t.Run("ErrIPAMCIDRImmutable", func(t *testing.T) {
		t.Parallel()
		err := ErrIPAMCIDRImmutable{}
		assert.Equal(t, "CIDR cannot be changed after pool creation", err.Error())
	})

	t.Run("ErrIPAllocationNotFound", func(t *testing.T) {
		t.Parallel()
		err := ErrIPAllocationNotFound{IP: "10.0.0.5"}
		assert.Equal(t, "IP allocation not found: 10.0.0.5", err.Error())
	})

	t.Run("ErrIPAlreadyAllocated", func(t *testing.T) {
		t.Parallel()
		err := ErrIPAlreadyAllocated{IP: "10.0.0.5"}
		assert.Equal(t, "IP already allocated: 10.0.0.5", err.Error())
	})

	t.Run("ErrIPAMPoolExhausted", func(t *testing.T) {
		t.Parallel()
		err := ErrIPAMPoolExhausted{ID: "pool-123"}
		assert.Equal(t, "IPAM pool exhausted: pool-123", err.Error())
	})

	t.Run("ErrGatewayOperationFailed", func(t *testing.T) {
		t.Parallel()
		cause := errors.New("underlying error")
		err := ErrGatewayOperationFailed{Operation: "create", Cause: cause}
		assert.Equal(t, "gateway operation create failed: underlying error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrGatewayOperationFailed_unwrap_nil", func(t *testing.T) {
		t.Parallel()
		err := ErrGatewayOperationFailed{Operation: "delete", Cause: nil}
		assert.Equal(t, "gateway operation delete failed: <nil>", err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

// =============================================================================
// Gateway Error Interface Compliance Tests
// =============================================================================

func TestGatewayErrorsImplementError(t *testing.T) {
	t.Parallel()

	// Verify all gateway error types implement the error interface
	tests := []struct {
		name string
		err  error
	}{
		{"ErrGatewayServiceNotAvailable", ErrGatewayServiceNotAvailable{}},
		{"ErrInvalidGatewayMode", ErrInvalidGatewayMode{Mode: 1}},
		{"ErrInvalidPrefix", ErrInvalidPrefix{Prefix: "test"}},
		{"ErrInvalidIPAddress", ErrInvalidIPAddress{IP: "test"}},
		{"ErrInvalidPoolID", ErrInvalidPoolID{ID: "test"}},
		{"ErrBGPNotEnabled", ErrBGPNotEnabled{}},
		{"ErrBGPPeerNotFound", ErrBGPPeerNotFound{Address: "test"}},
		{"ErrPrefixNotFound", ErrPrefixNotFound{Prefix: "test"}},
		{"ErrPrefixAlreadyAnnounced", ErrPrefixAlreadyAnnounced{Prefix: "test"}},
		{"ErrIPAMPoolNotFound", ErrIPAMPoolNotFound{ID: "test"}},
		{"ErrIPAMPoolAlreadyExists", ErrIPAMPoolAlreadyExists{ID: "test"}},
		{"ErrIPAMPoolHasAllocations", ErrIPAMPoolHasAllocations{ID: "test"}},
		{"ErrIPAMCIDRImmutable", ErrIPAMCIDRImmutable{}},
		{"ErrIPAllocationNotFound", ErrIPAllocationNotFound{IP: "test"}},
		{"ErrIPAlreadyAllocated", ErrIPAlreadyAllocated{IP: "test"}},
		{"ErrIPAMPoolExhausted", ErrIPAMPoolExhausted{ID: "test"}},
		{"ErrGatewayOperationFailed", ErrGatewayOperationFailed{Operation: "test", Cause: nil}},
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
// Mock Gateway Service
// =============================================================================

type mockGatewayService struct {
	getStatusResp       *GatewayStatusResponse
	getStatusErr        error
	setModeResp         *SetGatewayModeResponse
	setModeErr          error
	getBGPStatusResp    *BGPStatusResponse
	getBGPStatusErr     error
	listBGPPeersResp    []BGPPeerResponse
	listBGPPeersErr     error
	announcePrefixErr   error
	withdrawPrefixErr   error
	listPrefixesResp    []AnnouncedPrefixResponse
	listPrefixesErr     error
	createPoolResp      *IPAMPoolResponse
	createPoolErr       error
	getPoolResp         *IPAMPoolResponse
	getPoolErr          error
	updatePoolResp      *IPAMPoolResponse
	updatePoolErr       error
	deletePoolErr       error
	listPoolsResp       []IPAMPoolResponse
	listPoolsErr        error
	allocateIPResp      *IPAllocationResponse
	allocateIPErr       error
	releaseIPErr        error
	listAllocationsResp []IPAllocationResponse
	listAllocationsErr  error
	addVIPResp          *LBVIPResponse
	addVIPErr           error
	getVIPResp          *LBVIPResponse
	getVIPErr           error
	listVIPsResp        []LBVIPResponse
	listVIPsErr         error
	removeVIPErr        error
	setVIPBackendsResp  *LBVIPResponse
	setVIPBackendsErr   error
	lbStatusResp        *LBStatusResponse
	lbStatusErr         error
}

func newMockGatewayService() *mockGatewayService {
	return &mockGatewayService{}
}

func (m *mockGatewayService) GetGatewayStatus(ctx context.Context) (*GatewayStatusResponse, error) {
	if m.getStatusErr != nil {
		return nil, m.getStatusErr
	}
	if m.getStatusResp != nil {
		return m.getStatusResp, nil
	}
	return &GatewayStatusResponse{
		ID:            "gateway-1",
		NodeID:        "node-1",
		Modes:         uint32(GatewayModeOverlay),
		Tier:          "tier1",
		Reputation:    0.95,
		UptimeSeconds: 3600,
		Healthy:       true,
		StartedAt:     time.Now().Add(-time.Hour),
	}, nil
}

func (m *mockGatewayService) SetGatewayMode(ctx context.Context, modes uint32) (*SetGatewayModeResponse, error) {
	if m.setModeErr != nil {
		return nil, m.setModeErr
	}
	if m.setModeResp != nil {
		return m.setModeResp, nil
	}
	return &SetGatewayModeResponse{
		Success: true,
		Message: "gateway mode updated",
		GatewayStatus: &GatewayStatusResponse{
			ID:     "gateway-1",
			NodeID: "node-1",
			Modes:  modes,
		},
	}, nil
}

func (m *mockGatewayService) GetBGPStatus(ctx context.Context) (*BGPStatusResponse, error) {
	if m.getBGPStatusErr != nil {
		return nil, m.getBGPStatusErr
	}
	if m.getBGPStatusResp != nil {
		return m.getBGPStatusResp, nil
	}
	return &BGPStatusResponse{
		LocalASN:          65001,
		RouterID:          "10.0.0.1",
		PeerCount:         2,
		EstablishedPeers:  2,
		PrefixesAnnounced: 5,
		Running:           true,
	}, nil
}

func (m *mockGatewayService) ListBGPPeers(ctx context.Context) ([]BGPPeerResponse, error) {
	if m.listBGPPeersErr != nil {
		return nil, m.listBGPPeersErr
	}
	if m.listBGPPeersResp != nil {
		return m.listBGPPeersResp, nil
	}
	return []BGPPeerResponse{
		{
			Address:          "10.0.0.2",
			ASN:              65002,
			State:            "established",
			Description:      "peer-1",
			PrefixesReceived: 10,
			PrefixesSent:     5,
			Uptime:           time.Now().Add(-time.Hour),
		},
	}, nil
}

func (m *mockGatewayService) AnnouncePrefix(ctx context.Context, prefix, nextHop string) error {
	return m.announcePrefixErr
}

func (m *mockGatewayService) WithdrawPrefix(ctx context.Context, prefix string) error {
	return m.withdrawPrefixErr
}

func (m *mockGatewayService) ListAnnouncedPrefixes(ctx context.Context) ([]AnnouncedPrefixResponse, error) {
	if m.listPrefixesErr != nil {
		return nil, m.listPrefixesErr
	}
	if m.listPrefixesResp != nil {
		return m.listPrefixesResp, nil
	}
	return []AnnouncedPrefixResponse{
		{
			Prefix:      "10.0.0.0/8",
			NextHop:     "10.0.0.1",
			AnnouncedAt: time.Now().Add(-time.Minute),
		},
	}, nil
}

func (m *mockGatewayService) CreateIPAMPool(ctx context.Context, req *CreateIPAMPoolRequest) (*IPAMPoolResponse, error) {
	if m.createPoolErr != nil {
		return nil, m.createPoolErr
	}
	if m.createPoolResp != nil {
		return m.createPoolResp, nil
	}
	return &IPAMPoolResponse{
		ID:        "pool-1",
		Name:      req.Name,
		CIDR:      req.CIDR,
		Gateway:   req.Gateway,
		Zone:      req.Zone,
		Total:     254,
		Allocated: 0,
		Available: 254,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}, nil
}

func (m *mockGatewayService) GetIPAMPool(ctx context.Context, poolID string) (*IPAMPoolResponse, error) {
	if m.getPoolErr != nil {
		return nil, m.getPoolErr
	}
	if m.getPoolResp != nil {
		return m.getPoolResp, nil
	}
	return &IPAMPoolResponse{
		ID:        poolID,
		Name:      "test-pool",
		CIDR:      "10.0.0.0/24",
		Gateway:   "10.0.0.1",
		Zone:      "trusted",
		Total:     254,
		Allocated: 10,
		Available: 244,
	}, nil
}

func (m *mockGatewayService) UpdateIPAMPool(ctx context.Context, poolID string, req *UpdateIPAMPoolRequest) (*IPAMPoolResponse, error) {
	if m.updatePoolErr != nil {
		return nil, m.updatePoolErr
	}
	if m.updatePoolResp != nil {
		return m.updatePoolResp, nil
	}
	return &IPAMPoolResponse{
		ID:        poolID,
		Name:      req.Name,
		CIDR:      "10.0.0.0/24",
		Gateway:   req.Gateway,
		Zone:      req.Zone,
		Total:     254,
		Allocated: 10,
		Available: 244,
		UpdatedAt: time.Now().UTC(),
	}, nil
}

func (m *mockGatewayService) DeleteIPAMPool(ctx context.Context, poolID string) error {
	return m.deletePoolErr
}

func (m *mockGatewayService) ListIPAMPools(ctx context.Context, zone string) ([]IPAMPoolResponse, error) {
	if m.listPoolsErr != nil {
		return nil, m.listPoolsErr
	}
	if m.listPoolsResp != nil {
		return m.listPoolsResp, nil
	}
	return []IPAMPoolResponse{
		{
			ID:        "pool-1",
			Name:      "default",
			CIDR:      "10.0.0.0/24",
			Gateway:   "10.0.0.1",
			Total:     254,
			Allocated: 10,
			Available: 244,
		},
	}, nil
}

func (m *mockGatewayService) AllocateIP(ctx context.Context, poolID, deviceID, hostname string) (*IPAllocationResponse, error) {
	if m.allocateIPErr != nil {
		return nil, m.allocateIPErr
	}
	if m.allocateIPResp != nil {
		return m.allocateIPResp, nil
	}
	return &IPAllocationResponse{
		IP:          "10.0.0.10",
		PoolID:      poolID,
		DeviceID:    deviceID,
		Hostname:    hostname,
		AllocatedAt: time.Now(),
	}, nil
}

func (m *mockGatewayService) ReleaseIP(ctx context.Context, ip string) error {
	return m.releaseIPErr
}

func (m *mockGatewayService) ListAllocations(ctx context.Context, poolID string) ([]IPAllocationResponse, error) {
	if m.listAllocationsErr != nil {
		return nil, m.listAllocationsErr
	}
	if m.listAllocationsResp != nil {
		return m.listAllocationsResp, nil
	}
	return []IPAllocationResponse{
		{
			IP:          "10.0.0.10",
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			Hostname:    "host-1",
			AllocatedAt: time.Now(),
		},
	}, nil
}

func (m *mockGatewayService) AddVIP(ctx context.Context, req *LBVIPRequest) (*LBVIPResponse, error) {
	return m.addVIPResp, m.addVIPErr
}

func (m *mockGatewayService) GetVIP(ctx context.Context, protocol, address string, port uint16) (*LBVIPResponse, error) {
	return m.getVIPResp, m.getVIPErr
}

func (m *mockGatewayService) ListVIPs(ctx context.Context) ([]LBVIPResponse, error) {
	return m.listVIPsResp, m.listVIPsErr
}

func (m *mockGatewayService) RemoveVIP(ctx context.Context, protocol, address string, port uint16) error {
	return m.removeVIPErr
}

func (m *mockGatewayService) SetVIPBackends(ctx context.Context, protocol, address string, port uint16, backends []LBBackend) (*LBVIPResponse, error) {
	return m.setVIPBackendsResp, m.setVIPBackendsErr
}

func (m *mockGatewayService) GetLBStatus(ctx context.Context) (*LBStatusResponse, error) {
	return m.lbStatusResp, m.lbStatusErr
}

// =============================================================================
// Test Helpers
// =============================================================================

func setupGatewayTestHandler(svc *mockGatewayService) (*GatewayHandlers, *mux.Router) {
	logger := slog.Default()
	handlers := NewGatewayHandlers(svc, logger)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return handlers, router
}

func decodeGatewayResponse(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	err := json.NewDecoder(resp.Body).Decode(v)
	require.NoError(t, err)
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewGatewayHandlers(t *testing.T) {
	t.Parallel()

	t.Run("creates handlers with service and logger", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		logger := slog.Default()
		handlers := NewGatewayHandlers(svc, logger)
		require.NotNil(t, handlers)
		assert.Equal(t, svc, handlers.gatewayService)
		assert.Equal(t, logger, handlers.logger)
	})

	t.Run("creates handlers with nil logger uses default", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		handlers := NewGatewayHandlers(svc, nil)
		require.NotNil(t, handlers)
		assert.NotNil(t, handlers.logger)
	})

	t.Run("creates handlers with nil service", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		require.NotNil(t, handlers)
		assert.Nil(t, handlers.gatewayService)
	})
}

func TestSetGatewayService(t *testing.T) {
	t.Parallel()

	t.Run("sets gateway service", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		require.Nil(t, handlers.gatewayService)

		svc := newMockGatewayService()
		handlers.SetGatewayService(svc)
		assert.Equal(t, svc, handlers.gatewayService)
	})
}

func TestGatewayRegisterRoutes(t *testing.T) {
	t.Parallel()

	t.Run("registers all gateway routes", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		routes := []struct {
			method string
			path   string
		}{
			{http.MethodGet, "/api/v1/sdn/gateway/status"},
			{http.MethodPut, "/api/v1/sdn/gateway/mode"},
			{http.MethodGet, "/api/v1/sdn/gateway/bgp/status"},
			{http.MethodGet, "/api/v1/sdn/gateway/bgp/peers"},
			{http.MethodPost, "/api/v1/sdn/gateway/bgp/prefixes"},
			{http.MethodDelete, "/api/v1/sdn/gateway/bgp/prefixes/prefix-123"},
			{http.MethodGet, "/api/v1/sdn/gateway/bgp/prefixes"},
			// IPAM pool CRUD
			{http.MethodPost, "/api/v1/sdn/gateway/ipam/pools"},
			{http.MethodGet, "/api/v1/sdn/gateway/ipam/pools"},
			{http.MethodGet, "/api/v1/sdn/gateway/ipam/pools/pool-1"},
			{http.MethodPut, "/api/v1/sdn/gateway/ipam/pools/pool-1"},
			{http.MethodDelete, "/api/v1/sdn/gateway/ipam/pools/pool-1"},
			// IPAM allocations
			{http.MethodPost, "/api/v1/sdn/gateway/ipam/allocations"},
			{http.MethodDelete, "/api/v1/sdn/gateway/ipam/allocations/10.0.0.10"},
			{http.MethodGet, "/api/v1/sdn/gateway/ipam/allocations"},
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
// Gateway Status Handler Tests
// =============================================================================

func TestHandleGetGatewayStatus(t *testing.T) {
	t.Parallel()

	t.Run("returns gateway status successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var status GatewayStatusResponse
		decodeGatewayResponse(t, resp, &status)
		assert.Equal(t, "gateway-1", status.ID)
		assert.Equal(t, "node-1", status.NodeID)
		assert.True(t, status.Healthy)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

		var errResp GatewayErrorResponse
		decodeGatewayResponse(t, resp, &errResp)
		assert.Contains(t, errResp.Error, "gateway service not available")
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.getStatusErr = errors.New("service error")
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// Gateway Mode Handler Tests
// =============================================================================

func TestHandleSetGatewayMode(t *testing.T) {
	t.Parallel()

	t.Run("sets gateway mode successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		reqBody := SetGatewayModeRequest{Modes: uint32(GatewayModeOverlay)}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/gateway/mode", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var modeResp SetGatewayModeResponse
		decodeGatewayResponse(t, resp, &modeResp)
		assert.True(t, modeResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := SetGatewayModeRequest{Modes: uint32(GatewayModeOverlay)}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/gateway/mode", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON body", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/gateway/mode", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid gateway mode", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		reqBody := SetGatewayModeRequest{Modes: 999}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/gateway/mode", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.setModeErr = errors.New("service error")
		_, router := setupGatewayTestHandler(svc)

		reqBody := SetGatewayModeRequest{Modes: uint32(GatewayModeOverlay)}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/gateway/mode", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// BGP Status Handler Tests
// =============================================================================

func TestHandleGetBGPStatus(t *testing.T) {
	t.Parallel()

	t.Run("returns BGP status successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/bgp/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var status BGPStatusResponse
		decodeGatewayResponse(t, resp, &status)
		assert.Equal(t, uint32(65001), status.LocalASN)
		assert.True(t, status.Running)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/bgp/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when BGP not enabled", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.getBGPStatusErr = ErrBGPNotEnabled{}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/bgp/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// BGP Peers Handler Tests
// =============================================================================

func TestHandleListBGPPeers(t *testing.T) {
	t.Parallel()

	t.Run("returns BGP peers successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/bgp/peers", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var peersResp BGPPeerListResponse
		decodeGatewayResponse(t, resp, &peersResp)
		assert.Equal(t, 1, peersResp.Count)
		assert.Equal(t, "10.0.0.2", peersResp.Peers[0].Address)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/bgp/peers", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.listBGPPeersErr = errors.New("service error")
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/bgp/peers", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// Announce Prefix Handler Tests
// =============================================================================

func TestHandleAnnouncePrefix(t *testing.T) {
	t.Parallel()

	t.Run("announces prefix successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		reqBody := AnnouncePrefixRequest{
			Prefix:  "10.0.0.0/8",
			NextHop: "10.0.0.1",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/bgp/prefixes", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var actionResp GatewayActionResponse
		decodeGatewayResponse(t, resp, &actionResp)
		assert.True(t, actionResp.Success)
		assert.Equal(t, "10.0.0.0/8", actionResp.ResourceID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := AnnouncePrefixRequest{
			Prefix:  "10.0.0.0/8",
			NextHop: "10.0.0.1",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/bgp/prefixes", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON body", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/bgp/prefixes", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for missing prefix", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		reqBody := AnnouncePrefixRequest{NextHop: "10.0.0.1"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/bgp/prefixes", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when prefix already announced", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.announcePrefixErr = ErrPrefixAlreadyAnnounced{Prefix: "10.0.0.0/8"}
		_, router := setupGatewayTestHandler(svc)

		reqBody := AnnouncePrefixRequest{Prefix: "10.0.0.0/8"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/bgp/prefixes", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})
}

// =============================================================================
// Withdraw Prefix Handler Tests
// =============================================================================

func TestHandleWithdrawPrefix(t *testing.T) {
	t.Parallel()

	t.Run("withdraws prefix successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/gateway/bgp/prefixes/prefix-10.0.0.0-8", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp GatewayActionResponse
		decodeGatewayResponse(t, resp, &actionResp)
		assert.True(t, actionResp.Success)
		assert.Equal(t, "prefix-10.0.0.0-8", actionResp.ResourceID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/gateway/bgp/prefixes/prefix-123", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when prefix not found", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.withdrawPrefixErr = ErrPrefixNotFound{Prefix: "prefix-10.0.0.0-8"}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/gateway/bgp/prefixes/prefix-10.0.0.0-8", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// =============================================================================
// List Announced Prefixes Handler Tests
// =============================================================================

func TestHandleListAnnouncedPrefixes(t *testing.T) {
	t.Parallel()

	t.Run("lists prefixes successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/bgp/prefixes", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var prefixesResp AnnouncedPrefixListResponse
		decodeGatewayResponse(t, resp, &prefixesResp)
		assert.Equal(t, 1, prefixesResp.Count)
		assert.Equal(t, "10.0.0.0/8", prefixesResp.Prefixes[0].Prefix)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/bgp/prefixes", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.listPrefixesErr = errors.New("service error")
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/bgp/prefixes", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// IPAM Pool CRUD Handler Tests
// =============================================================================

func TestHandleCreateIPAMPool(t *testing.T) {
	t.Parallel()

	t.Run("creates pool successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		reqBody := CreateIPAMPoolRequest{
			Name:    "dev-pool",
			CIDR:    "192.168.10.0/24",
			Gateway: "192.168.10.1",
			Zone:    "dev",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/pools", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var poolResp IPAMPoolResponse
		decodeGatewayResponse(t, resp, &poolResp)
		assert.Equal(t, "pool-1", poolResp.ID)
		assert.Equal(t, "dev-pool", poolResp.Name)
		assert.Equal(t, "192.168.10.0/24", poolResp.CIDR)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := CreateIPAMPoolRequest{Name: "pool", CIDR: "10.0.0.0/24"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/pools", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON body", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/pools", bytes.NewReader([]byte("not-json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		reqBody := CreateIPAMPoolRequest{CIDR: "10.0.0.0/24"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/pools", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for missing cidr", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		reqBody := CreateIPAMPoolRequest{Name: "pool"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/pools", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns conflict when pool already exists", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.createPoolErr = ErrIPAMPoolAlreadyExists{ID: "pool-1"}
		_, router := setupGatewayTestHandler(svc)

		reqBody := CreateIPAMPoolRequest{Name: "pool", CIDR: "10.0.0.0/24"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/pools", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})
}

func TestHandleGetIPAMPool(t *testing.T) {
	t.Parallel()

	t.Run("gets pool successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/ipam/pools/pool-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var poolResp IPAMPoolResponse
		decodeGatewayResponse(t, resp, &poolResp)
		assert.Equal(t, "pool-1", poolResp.ID)
		assert.Equal(t, "test-pool", poolResp.Name)
		assert.Equal(t, "10.0.0.0/24", poolResp.CIDR)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/ipam/pools/pool-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns not found when pool does not exist", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.getPoolErr = ErrIPAMPoolNotFound{ID: "missing-pool"}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/ipam/pools/missing-pool", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestHandleUpdateIPAMPool(t *testing.T) {
	t.Parallel()

	t.Run("updates pool successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		reqBody := UpdateIPAMPoolRequest{
			Name:    "updated-pool",
			Gateway: "10.0.0.254",
			Zone:    "provisioning",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/gateway/ipam/pools/pool-1", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var poolResp IPAMPoolResponse
		decodeGatewayResponse(t, resp, &poolResp)
		assert.Equal(t, "pool-1", poolResp.ID)
		assert.Equal(t, "updated-pool", poolResp.Name)
		// CIDR is immutable — mock always returns 10.0.0.0/24
		assert.Equal(t, "10.0.0.0/24", poolResp.CIDR)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := UpdateIPAMPoolRequest{Name: "pool"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/gateway/ipam/pools/pool-1", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON body", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/gateway/ipam/pools/pool-1", bytes.NewReader([]byte("not-json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns not found when pool does not exist", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.updatePoolErr = ErrIPAMPoolNotFound{ID: "missing-pool"}
		_, router := setupGatewayTestHandler(svc)

		reqBody := UpdateIPAMPoolRequest{Name: "pool"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/gateway/ipam/pools/missing-pool", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns bad request when CIDR change attempted", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.updatePoolErr = ErrIPAMCIDRImmutable{}
		_, router := setupGatewayTestHandler(svc)

		reqBody := UpdateIPAMPoolRequest{Name: "pool"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/gateway/ipam/pools/pool-1", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestHandleDeleteIPAMPool(t *testing.T) {
	t.Parallel()

	t.Run("deletes pool successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/gateway/ipam/pools/pool-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp GatewayActionResponse
		decodeGatewayResponse(t, resp, &actionResp)
		assert.True(t, actionResp.Success)
		assert.Equal(t, "pool-1", actionResp.ResourceID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/gateway/ipam/pools/pool-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns not found when pool does not exist", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.deletePoolErr = ErrIPAMPoolNotFound{ID: "missing-pool"}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/gateway/ipam/pools/missing-pool", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns conflict when pool has active allocations", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.deletePoolErr = ErrIPAMPoolHasAllocations{ID: "pool-1"}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/gateway/ipam/pools/pool-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})
}

// =============================================================================
// IPAM Pools List Handler Tests
// =============================================================================

func TestHandleListIPAMPools(t *testing.T) {
	t.Parallel()

	t.Run("lists IPAM pools successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/ipam/pools", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var poolsResp IPAMPoolListResponse
		decodeGatewayResponse(t, resp, &poolsResp)
		assert.Equal(t, 1, poolsResp.Count)
		assert.Equal(t, "pool-1", poolsResp.Pools[0].ID)
	})

	t.Run("lists pools filtered by zone", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.listPoolsResp = []IPAMPoolResponse{
			{ID: "pool-2", Name: "trusted-pool", CIDR: "10.1.0.0/24", Zone: "trusted"},
		}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/ipam/pools?zone=trusted", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var poolsResp IPAMPoolListResponse
		decodeGatewayResponse(t, resp, &poolsResp)
		assert.Equal(t, 1, poolsResp.Count)
		assert.Equal(t, "trusted", poolsResp.Pools[0].Zone)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/ipam/pools", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.listPoolsErr = errors.New("service error")
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/ipam/pools", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// Allocate IP Handler Tests
// =============================================================================

func TestHandleAllocateIP(t *testing.T) {
	t.Parallel()

	t.Run("allocates IP successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		reqBody := AllocateIPRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
			Hostname: "host-1",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/allocations", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var allocResp IPAllocationResponse
		decodeGatewayResponse(t, resp, &allocResp)
		assert.Equal(t, "10.0.0.10", allocResp.IP)
		assert.Equal(t, "pool-1", allocResp.PoolID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := AllocateIPRequest{PoolID: "pool-1", DeviceID: "device-1"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/allocations", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON body", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/allocations", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for missing pool_id", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		reqBody := AllocateIPRequest{DeviceID: "device-1"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/allocations", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for missing device_id", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		reqBody := AllocateIPRequest{PoolID: "pool-1"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/allocations", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when pool not found", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.allocateIPErr = ErrIPAMPoolNotFound{ID: "pool-1"}
		_, router := setupGatewayTestHandler(svc)

		reqBody := AllocateIPRequest{PoolID: "pool-1", DeviceID: "device-1"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/allocations", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when pool exhausted", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.allocateIPErr = ErrIPAMPoolExhausted{ID: "pool-1"}
		_, router := setupGatewayTestHandler(svc)

		reqBody := AllocateIPRequest{PoolID: "pool-1", DeviceID: "device-1"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/ipam/allocations", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Release IP Handler Tests
// =============================================================================

func TestHandleReleaseIP(t *testing.T) {
	t.Parallel()

	t.Run("releases IP successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/gateway/ipam/allocations/10.0.0.10", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp GatewayActionResponse
		decodeGatewayResponse(t, resp, &actionResp)
		assert.True(t, actionResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/gateway/ipam/allocations/10.0.0.10", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when allocation not found", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.releaseIPErr = ErrIPAllocationNotFound{IP: "10.0.0.10"}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/gateway/ipam/allocations/10.0.0.10", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// =============================================================================
// List Allocations Handler Tests
// =============================================================================

func TestHandleListAllocations(t *testing.T) {
	t.Parallel()

	t.Run("lists allocations successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/ipam/allocations", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var allocsResp IPAllocationListResponse
		decodeGatewayResponse(t, resp, &allocsResp)
		assert.Equal(t, 1, allocsResp.Count)
		assert.Equal(t, "10.0.0.10", allocsResp.Allocations[0].IP)
	})

	t.Run("lists allocations with pool_id filter", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/ipam/allocations?pool_id=pool-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/ipam/allocations", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.listAllocationsErr = errors.New("service error")
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/ipam/allocations", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// Helper Method Tests
// =============================================================================

func TestGatewayWriteGatewayError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"ErrBGPNotEnabled", ErrBGPNotEnabled{}, http.StatusServiceUnavailable},
		{"ErrBGPPeerNotFound", ErrBGPPeerNotFound{Address: "test"}, http.StatusNotFound},
		{"ErrPrefixNotFound", ErrPrefixNotFound{Prefix: "test"}, http.StatusNotFound},
		{"ErrPrefixAlreadyAnnounced", ErrPrefixAlreadyAnnounced{Prefix: "test"}, http.StatusConflict},
		{"ErrIPAMPoolNotFound", ErrIPAMPoolNotFound{ID: "test"}, http.StatusNotFound},
		{"ErrIPAMPoolAlreadyExists", ErrIPAMPoolAlreadyExists{ID: "test"}, http.StatusConflict},
		{"ErrIPAMPoolHasAllocations", ErrIPAMPoolHasAllocations{ID: "test"}, http.StatusConflict},
		{"ErrIPAMCIDRImmutable", ErrIPAMCIDRImmutable{}, http.StatusBadRequest},
		{"ErrIPAllocationNotFound", ErrIPAllocationNotFound{IP: "test"}, http.StatusNotFound},
		{"ErrIPAlreadyAllocated", ErrIPAlreadyAllocated{IP: "test"}, http.StatusConflict},
		{"ErrIPAMPoolExhausted", ErrIPAMPoolExhausted{ID: "test"}, http.StatusServiceUnavailable},
		{"ErrInvalidGatewayMode", ErrInvalidGatewayMode{Mode: 999}, http.StatusBadRequest},
		{"ErrInvalidPrefix", ErrInvalidPrefix{Prefix: "test"}, http.StatusBadRequest},
		{"ErrInvalidIPAddress", ErrInvalidIPAddress{IP: "test"}, http.StatusBadRequest},
		{"ErrInvalidPoolID", ErrInvalidPoolID{ID: "test"}, http.StatusBadRequest},
		{"ErrGatewayServiceNotAvailable", ErrGatewayServiceNotAvailable{}, http.StatusServiceUnavailable},
		{"UnknownError", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handlers := NewGatewayHandlers(nil, nil)
			w := httptest.NewRecorder()
			handlers.writeGatewayError(w, "test_op", tt.err)
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestGatewayWriteJSON(t *testing.T) {
	t.Parallel()

	t.Run("writes JSON response successfully", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
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

func TestGatewayWriteError(t *testing.T) {
	t.Parallel()

	t.Run("writes error response", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		w := httptest.NewRecorder()

		handlers.writeError(w, http.StatusBadRequest, errors.New("test error"))

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var errResp GatewayErrorResponse
		err := json.NewDecoder(w.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "test error", errResp.Error)
		assert.Equal(t, http.StatusBadRequest, errResp.Code)
	})
}
