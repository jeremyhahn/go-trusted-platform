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

package quic

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock Overlay Service
// =============================================================================

// testOverlayService implements OverlayServiceInterface for testing
type testOverlayService struct {
	// Response data
	statusResp  *OverlayStatusInfo
	vtepsResp   []*VTEPInfo
	vtepResp    *VTEPInfo
	vnisResp    []*VNIInfo
	vniResp     *VNIInfo
	tunnelsResp []*TunnelInfo
	macsResp    []*MACEntry

	// Error injection
	statusErr      error
	listVTEPsErr   error
	getVTEPErr     error
	listVNIsErr    error
	createVNIErr   error
	deleteVNIErr   error
	listTunnelsErr error
	listMACsErr    error
	forgetMACErr   error

	// Capture last request for validation
	lastVTEPID  string
	lastVNI     uint32
	lastVNIOpts *VNICreateOptions
	lastMACVNI  uint32
	lastMAC     string
}

func newTestOverlayService() *testOverlayService {
	now := time.Now().Unix()
	return &testOverlayService{
		statusResp: &OverlayStatusInfo{
			Enabled:      true,
			Mode:         "vxlan",
			LocalVTEP:    "10.0.0.1",
			VTEPCount:    3,
			VNICount:     5,
			TunnelCount:  8,
			MACCount:     50,
			UplinkIface:  "eth0",
			MTU:          1450,
			EncapType:    "vxlan",
			HealthStatus: "healthy",
		},
		vtepsResp: []*VTEPInfo{
			{
				ID:          "vtep-1",
				IPAddress:   "10.0.0.1",
				Hostname:    "host-1",
				Status:      "active",
				VNIs:        []uint32{100, 200},
				TunnelCount: 4,
				LastSeen:    now,
			},
			{
				ID:          "vtep-2",
				IPAddress:   "10.0.0.2",
				Hostname:    "host-2",
				Status:      "active",
				VNIs:        []uint32{100, 300},
				TunnelCount: 4,
				LastSeen:    now,
			},
		},
		vtepResp: &VTEPInfo{
			ID:          "vtep-1",
			IPAddress:   "10.0.0.1",
			Hostname:    "host-1",
			Status:      "active",
			VNIs:        []uint32{100, 200},
			TunnelCount: 4,
			LastSeen:    now,
		},
		vnisResp: []*VNIInfo{
			{
				VNI:       100,
				Name:      "production",
				Status:    "active",
				MTU:       1450,
				MACCount:  25,
				VTEPCount: 3,
				Learning:  true,
				ARPProxy:  true,
				CreatedAt: now,
			},
			{
				VNI:       200,
				Name:      "development",
				Status:    "active",
				MTU:       1450,
				MACCount:  10,
				VTEPCount: 2,
				Learning:  true,
				ARPProxy:  false,
				CreatedAt: now,
			},
		},
		vniResp: &VNIInfo{
			VNI:       100,
			Name:      "production",
			Status:    "active",
			MTU:       1450,
			MACCount:  25,
			VTEPCount: 3,
			Learning:  true,
			ARPProxy:  true,
			CreatedAt: now,
		},
		tunnelsResp: []*TunnelInfo{
			{
				ID:         "tunnel-1",
				LocalVTEP:  "10.0.0.1",
				RemoteVTEP: "10.0.0.2",
				VNI:        100,
				Status:     "established",
				EncapType:  "vxlan",
				TxBytes:    1024000,
				RxBytes:    512000,
				CreatedAt:  now,
				LastActive: now,
			},
			{
				ID:         "tunnel-2",
				LocalVTEP:  "10.0.0.1",
				RemoteVTEP: "10.0.0.3",
				VNI:        100,
				Status:     "established",
				EncapType:  "vxlan",
				TxBytes:    2048000,
				RxBytes:    1024000,
				CreatedAt:  now,
				LastActive: now,
			},
		},
		macsResp: []*MACEntry{
			{
				MAC:         "00:11:22:33:44:55",
				VNI:         100,
				VTEP:        "10.0.0.2",
				Type:        "learned",
				Age:         60,
				LastSeen:    now,
				IsPermanent: false,
			},
			{
				MAC:         "00:11:22:33:44:66",
				VNI:         100,
				VTEP:        "10.0.0.3",
				Type:        "learned",
				Age:         30,
				LastSeen:    now,
				IsPermanent: false,
			},
		},
	}
}

func (s *testOverlayService) Status(ctx context.Context) (*OverlayStatusInfo, error) {
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	return s.statusResp, nil
}

func (s *testOverlayService) ListVTEPs(ctx context.Context) ([]*VTEPInfo, error) {
	if s.listVTEPsErr != nil {
		return nil, s.listVTEPsErr
	}
	return s.vtepsResp, nil
}

func (s *testOverlayService) GetVTEP(ctx context.Context, id string) (*VTEPInfo, error) {
	s.lastVTEPID = id
	if s.getVTEPErr != nil {
		return nil, s.getVTEPErr
	}
	return s.vtepResp, nil
}

func (s *testOverlayService) ListVNIs(ctx context.Context) ([]*VNIInfo, error) {
	if s.listVNIsErr != nil {
		return nil, s.listVNIsErr
	}
	return s.vnisResp, nil
}

func (s *testOverlayService) CreateVNI(ctx context.Context, vni uint32, opts *VNICreateOptions) (*VNIInfo, error) {
	s.lastVNI = vni
	s.lastVNIOpts = opts
	if s.createVNIErr != nil {
		return nil, s.createVNIErr
	}
	return s.vniResp, nil
}

func (s *testOverlayService) DeleteVNI(ctx context.Context, vni uint32) error {
	s.lastVNI = vni
	if s.deleteVNIErr != nil {
		return s.deleteVNIErr
	}
	return nil
}

func (s *testOverlayService) ListTunnels(ctx context.Context) ([]*TunnelInfo, error) {
	if s.listTunnelsErr != nil {
		return nil, s.listTunnelsErr
	}
	return s.tunnelsResp, nil
}

func (s *testOverlayService) ListMACs(ctx context.Context, vni uint32) ([]*MACEntry, error) {
	s.lastMACVNI = vni
	if s.listMACsErr != nil {
		return nil, s.listMACsErr
	}
	return s.macsResp, nil
}

func (s *testOverlayService) ForgetMAC(ctx context.Context, vni uint32, mac string) error {
	s.lastMACVNI = vni
	s.lastMAC = mac
	if s.forgetMACErr != nil {
		return s.forgetMACErr
	}
	return nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func newOverlayTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelInfo, nil)
}

func createTestOverlayHandler() (*OverlayHandler, *testOverlayService) {
	logger := newOverlayTestLogger()
	service := newTestOverlayService()
	handler := NewOverlayHandler(logger, service)
	return handler, service
}

// =============================================================================
// Test: NewOverlayHandler
// =============================================================================

func TestNewOverlayHandler(t *testing.T) {
	t.Parallel()

	t.Run("creates handler with valid inputs", func(t *testing.T) {
		t.Parallel()
		logger := newOverlayTestLogger()
		service := newTestOverlayService()
		handler := NewOverlayHandler(logger, service)

		assert.NotNil(t, handler)
		assert.Equal(t, logger, handler.logger)
		assert.Equal(t, service, handler.overlayService)
	})

	t.Run("creates handler with nil service", func(t *testing.T) {
		t.Parallel()
		logger := newOverlayTestLogger()
		handler := NewOverlayHandler(logger, nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.overlayService)
	})
}

// =============================================================================
// Test: HandleRequest
// =============================================================================

func TestOverlayHandleRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("returns error for nil request", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		resp := handler.HandleRequest(ctx, nil)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "request cannot be nil")
	})

	t.Run("returns error for unknown opcode", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		req := &quicwire.Request{
			Opcode:  0xFF,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "unknown overlay operation")
	})

	t.Run("routes to status handler", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})
}

// =============================================================================
// Test: handleStatus
// =============================================================================

func TestOverlayHandleStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("returns status successfully", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var statusResp OverlayStatusResponse
		err := quicwire.DecodePayload(resp.Payload, &statusResp)
		require.NoError(t, err)

		assert.NotNil(t, statusResp.Status)
		assert.True(t, statusResp.Status.Enabled)
		assert.Equal(t, "vxlan", statusResp.Status.Mode)
		assert.Equal(t, "10.0.0.1", statusResp.Status.LocalVTEP)
		assert.Equal(t, "healthy", statusResp.Status.HealthStatus)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewOverlayHandler(newOverlayTestLogger(), nil)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when status fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()
		service.statusErr = errors.New("status unavailable")

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleListVTEPs
// =============================================================================

func TestOverlayHandleListVTEPs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("lists VTEPs successfully", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		listReq := &OverlayListVTEPsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListVTEPs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp OverlayListVTEPsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.VTEPs, 2)
		assert.Equal(t, int32(2), listResp.Count)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewOverlayHandler(newOverlayTestLogger(), nil)

		listReq := &OverlayListVTEPsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListVTEPs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListVTEPs,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		listReq := &OverlayListVTEPsRequest{
			Limit: 1,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListVTEPs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp OverlayListVTEPsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.VTEPs, 1)
		assert.Equal(t, int32(1), listResp.Count)
	})

	t.Run("returns error when list VTEPs fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()
		service.listVTEPsErr = errors.New("failed to list VTEPs")

		listReq := &OverlayListVTEPsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListVTEPs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleGetVTEP
// =============================================================================

func TestOverlayHandleGetVTEP(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("gets VTEP successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()

		getReq := &OverlayGetVTEPRequest{
			ID: "vtep-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayGetVTEP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, "vtep-1", service.lastVTEPID)

		var getResp OverlayGetVTEPResponse
		err = quicwire.DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.VTEP)
		assert.Equal(t, "vtep-1", getResp.VTEP.ID)
		assert.Equal(t, "10.0.0.1", getResp.VTEP.IPAddress)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewOverlayHandler(newOverlayTestLogger(), nil)

		getReq := &OverlayGetVTEPRequest{
			ID: "vtep-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayGetVTEP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing VTEP ID", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		getReq := &OverlayGetVTEPRequest{}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayGetVTEP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "VTEP ID")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayGetVTEP,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when VTEP not found", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()
		service.getVTEPErr = ErrOverlayVTEPNotFound

		getReq := &OverlayGetVTEPRequest{
			ID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayGetVTEP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: handleListVNIs
// =============================================================================

func TestOverlayHandleListVNIs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("lists VNIs successfully", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		listReq := &OverlayListVNIsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListVNIs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp OverlayListVNIsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.VNIs, 2)
		assert.Equal(t, int32(2), listResp.Count)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewOverlayHandler(newOverlayTestLogger(), nil)

		listReq := &OverlayListVNIsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListVNIs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListVNIs,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		listReq := &OverlayListVNIsRequest{
			Limit: 1,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListVNIs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp OverlayListVNIsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.VNIs, 1)
	})

	t.Run("returns error when list VNIs fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()
		service.listVNIsErr = errors.New("failed to list VNIs")

		listReq := &OverlayListVNIsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListVNIs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleCreateVNI
// =============================================================================

func TestOverlayHandleCreateVNI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("creates VNI successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()

		createReq := &OverlayCreateVNIRequest{
			VNI:      500,
			Name:     "test-vni",
			MTU:      1450,
			Learning: true,
			ARPProxy: true,
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayCreateVNI,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, uint32(500), service.lastVNI)
		assert.Equal(t, "test-vni", service.lastVNIOpts.Name)
		assert.Equal(t, 1450, service.lastVNIOpts.MTU)

		var createResp OverlayCreateVNIResponse
		err = quicwire.DecodePayload(resp.Payload, &createResp)
		require.NoError(t, err)

		assert.NotNil(t, createResp.VNI)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewOverlayHandler(newOverlayTestLogger(), nil)

		createReq := &OverlayCreateVNIRequest{
			VNI: 500,
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayCreateVNI,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing VNI", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		createReq := &OverlayCreateVNIRequest{}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayCreateVNI,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "VNI")
	})

	t.Run("returns error for invalid VNI", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		createReq := &OverlayCreateVNIRequest{
			VNI: 16777216, // Exceeds VXLAN max
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayCreateVNI,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayCreateVNI,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when VNI already exists", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()
		service.createVNIErr = ErrOverlayVNIAlreadyExists

		createReq := &OverlayCreateVNIRequest{
			VNI: 100,
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayCreateVNI,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
	})

	t.Run("returns error when create VNI fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()
		service.createVNIErr = errors.New("failed to create VNI")

		createReq := &OverlayCreateVNIRequest{
			VNI: 500,
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayCreateVNI,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleDeleteVNI
// =============================================================================

func TestOverlayHandleDeleteVNI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("deletes VNI successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()

		deleteReq := &OverlayDeleteVNIRequest{
			VNI: 100,
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayDeleteVNI,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, uint32(100), service.lastVNI)

		var deleteResp OverlayDeleteVNIResponse
		err = quicwire.DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.Equal(t, uint32(100), deleteResp.VNI)
		assert.True(t, deleteResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewOverlayHandler(newOverlayTestLogger(), nil)

		deleteReq := &OverlayDeleteVNIRequest{
			VNI: 100,
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayDeleteVNI,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing VNI", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		deleteReq := &OverlayDeleteVNIRequest{}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayDeleteVNI,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayDeleteVNI,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when VNI not found", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()
		service.deleteVNIErr = ErrOverlayVNINotFound

		deleteReq := &OverlayDeleteVNIRequest{
			VNI: 999,
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayDeleteVNI,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: handleListTunnels
// =============================================================================

func TestOverlayHandleListTunnels(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("lists tunnels successfully", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		listReq := &OverlayListTunnelsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListTunns,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp OverlayListTunnelsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Tunnels, 2)
		assert.Equal(t, int32(2), listResp.Count)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewOverlayHandler(newOverlayTestLogger(), nil)

		listReq := &OverlayListTunnelsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListTunns,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListTunns,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		listReq := &OverlayListTunnelsRequest{
			Limit: 1,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListTunns,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp OverlayListTunnelsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Tunnels, 1)
	})

	t.Run("returns error when list tunnels fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()
		service.listTunnelsErr = errors.New("failed to list tunnels")

		listReq := &OverlayListTunnelsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListTunns,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleListMACs
// =============================================================================

func TestOverlayHandleListMACs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("lists MACs successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()

		listReq := &OverlayListMACsRequest{
			VNI: 100,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListMACs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, uint32(100), service.lastMACVNI)

		var listResp OverlayListMACsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.MACs, 2)
		assert.Equal(t, int32(2), listResp.Count)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewOverlayHandler(newOverlayTestLogger(), nil)

		listReq := &OverlayListMACsRequest{
			VNI: 100,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListMACs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("VNI zero lists all MACs", func(t *testing.T) {
		// VNI == 0 means list all MACs across all VNIs (list-all semantics).
		// The server must not reject VNI=0 as an invalid argument.
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		listReq := &OverlayListMACsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListMACs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		var listResp OverlayListMACsResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &listResp))
		assert.NotNil(t, listResp.MACs)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListMACs,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		listReq := &OverlayListMACsRequest{
			VNI:   100,
			Limit: 1,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListMACs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp OverlayListMACsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.MACs, 1)
	})

	t.Run("returns error when list MACs fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()
		service.listMACsErr = errors.New("failed to list MACs")

		listReq := &OverlayListMACsRequest{
			VNI: 100,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayListMACs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleForgetMAC
// =============================================================================

func TestOverlayHandleForgetMAC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("forgets MAC successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()

		forgetReq := &OverlayForgetMACRequest{
			VNI: 100,
			MAC: "00:11:22:33:44:55",
		}

		payload, err := quicwire.EncodePayload(forgetReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayForgetMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, uint32(100), service.lastMACVNI)
		assert.Equal(t, "00:11:22:33:44:55", service.lastMAC)

		var forgetResp OverlayForgetMACResponse
		err = quicwire.DecodePayload(resp.Payload, &forgetResp)
		require.NoError(t, err)

		assert.Equal(t, uint32(100), forgetResp.VNI)
		assert.Equal(t, "00:11:22:33:44:55", forgetResp.MAC)
		assert.True(t, forgetResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewOverlayHandler(newOverlayTestLogger(), nil)

		forgetReq := &OverlayForgetMACRequest{
			VNI: 100,
			MAC: "00:11:22:33:44:55",
		}

		payload, err := quicwire.EncodePayload(forgetReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayForgetMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing VNI", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		forgetReq := &OverlayForgetMACRequest{
			MAC: "00:11:22:33:44:55",
		}

		payload, err := quicwire.EncodePayload(forgetReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayForgetMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "VNI")
	})

	t.Run("returns error for missing MAC", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		forgetReq := &OverlayForgetMACRequest{
			VNI: 100,
		}

		payload, err := quicwire.EncodePayload(forgetReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayForgetMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "MAC")
	})

	t.Run("returns error for invalid MAC format", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		forgetReq := &OverlayForgetMACRequest{
			VNI: 100,
			MAC: "invalid-mac",
		}

		payload, err := quicwire.EncodePayload(forgetReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayForgetMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayForgetMAC,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when MAC not found", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestOverlayHandler()
		service.forgetMACErr = ErrOverlayMACNotFound

		forgetReq := &OverlayForgetMACRequest{
			VNI: 100,
			MAC: "00:11:22:33:44:99",
		}

		payload, err := quicwire.EncodePayload(forgetReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpOverlayForgetMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: errorResponse and overlayErrorResponse
// =============================================================================

func TestOverlayErrorResponse(t *testing.T) {
	t.Parallel()

	t.Run("maps VTEP not found to NotFound status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		resp := handler.overlayErrorResponse(ErrOverlayVTEPNotFound)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("maps VNI not found to NotFound status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		resp := handler.overlayErrorResponse(ErrOverlayVNINotFound)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("maps MAC not found to NotFound status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		resp := handler.overlayErrorResponse(ErrOverlayMACNotFound)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("maps VNI already exists to AlreadyExists status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		resp := handler.overlayErrorResponse(ErrOverlayVNIAlreadyExists)

		assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
	})

	t.Run("maps invalid VNI to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		resp := handler.overlayErrorResponse(ErrOverlayInvalidVNI)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps invalid MAC to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		resp := handler.overlayErrorResponse(ErrOverlayInvalidMAC)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing VTEP ID to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		resp := handler.overlayErrorResponse(ErrOverlayMissingVTEPID)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing VNI to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		resp := handler.overlayErrorResponse(ErrOverlayMissingVNI)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing MAC to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		resp := handler.overlayErrorResponse(ErrOverlayMissingMAC)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps service not available to Unavailable status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		resp := handler.overlayErrorResponse(ErrOverlayServiceNotAvailable)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("maps unknown error to InternalError status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestOverlayHandler()

		resp := handler.overlayErrorResponse(errors.New("unknown error"))

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}
