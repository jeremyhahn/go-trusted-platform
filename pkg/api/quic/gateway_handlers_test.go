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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock Gateway Service
// =============================================================================

// testGatewayService implements GatewayServiceInterface for testing
type testGatewayService struct {
	// Response data
	statusResp      *GatewayStatusInfo
	bgpStatusResp   *BGPStatusInfo
	bgpPeersResp    []*BGPPeerInfo
	prefixesResp    []*PrefixInfo
	ipamPoolsResp   []*IPAMPoolInfo
	createPoolResp  *IPAMPoolInfo
	allocationResp  *IPAllocationInfo
	allocationsResp []*IPAllocationInfo

	// Error injection
	statusErr         error
	setModeErr        error
	bgpStatusErr      error
	bgpPeersErr       error
	announcePrefixErr error
	withdrawPrefixErr error
	listPrefixesErr   error
	listIPAMPoolsErr  error
	createPoolErr     error
	deletePoolErr     error
	allocateIPErr     error
	releaseIPErr      error
	listAllocErr      error

	// Capture last request for validation
	lastMode           string
	lastPrefix         string
	lastPrefixOpts     *AnnouncePrefixOptions
	lastPoolID         string
	lastAllocateOpts   *AllocateIPOptions
	lastReleaseIP      string
	lastCreatePoolOpts *CreateIPAMPoolOptions
	lastDeletePoolID   string
}

func newTestGatewayService() *testGatewayService {
	now := time.Now().Unix()
	return &testGatewayService{
		statusResp: &GatewayStatusInfo{
			Enabled:       true,
			Mode:          GatewayModeL3,
			BGPEnabled:    true,
			BGPRouterID:   "10.0.0.1",
			BGPLocalAS:    65000,
			ExternalIface: "eth0",
			InternalIface: "eth1",
			NATEnabled:    false,
			PeerCount:     2,
			PrefixCount:   5,
			PoolCount:     3,
			HealthStatus:  "healthy",
			Uptime:        3600,
		},
		bgpStatusResp: &BGPStatusInfo{
			Enabled:           true,
			RouterID:          "10.0.0.1",
			LocalAS:           65000,
			HoldTime:          90,
			KeepaliveInterval: 30,
			PeerCount:         2,
			EstablishedCount:  2,
			PrefixesReceived:  10,
			PrefixesSent:      5,
			Uptime:            3600,
		},
		bgpPeersResp: []*BGPPeerInfo{
			{
				Address:          "10.0.0.2",
				RemoteAS:         65001,
				LocalAS:          65000,
				State:            "established",
				HoldTime:         90,
				KeepaliveTime:    30,
				PrefixesReceived: 5,
				PrefixesSent:     3,
				Uptime:           1800,
			},
			{
				Address:          "10.0.0.3",
				RemoteAS:         65002,
				LocalAS:          65000,
				State:            "established",
				HoldTime:         90,
				KeepaliveTime:    30,
				PrefixesReceived: 5,
				PrefixesSent:     2,
				Uptime:           1200,
			},
		},
		prefixesResp: []*PrefixInfo{
			{
				Prefix:      "192.168.1.0/24",
				Origin:      "igp",
				Status:      "active",
				AnnouncedAt: now,
			},
			{
				Prefix:      "192.168.2.0/24",
				Origin:      "igp",
				Status:      "active",
				AnnouncedAt: now,
			},
		},
		ipamPoolsResp: []*IPAMPoolInfo{
			{
				ID:           "pool-1",
				Name:         "Production",
				CIDR:         "10.0.0.0/24",
				Gateway:      "10.0.0.1",
				TotalIPs:     254,
				AllocatedIPs: 50,
				AvailableIPs: 204,
				Type:         "dynamic",
				CreatedAt:    now,
			},
			{
				ID:           "pool-2",
				Name:         "Development",
				CIDR:         "10.0.1.0/24",
				Gateway:      "10.0.1.1",
				TotalIPs:     254,
				AllocatedIPs: 10,
				AvailableIPs: 244,
				Type:         "dynamic",
				CreatedAt:    now,
			},
		},
		createPoolResp: &IPAMPoolInfo{
			ID:           "pool-new",
			Name:         "TestPool",
			CIDR:         "10.0.2.0/24",
			Gateway:      "10.0.2.1",
			TotalIPs:     254,
			AllocatedIPs: 0,
			AvailableIPs: 254,
			Type:         "dynamic",
			CreatedAt:    now,
		},
		allocationResp: &IPAllocationInfo{
			ID:        "alloc-1",
			PoolID:    "pool-1",
			IPAddress: "10.0.0.50",
			Status:    "active",
			Type:      "dynamic",
			CreatedAt: now,
			UpdatedAt: now,
		},
		allocationsResp: []*IPAllocationInfo{
			{
				ID:        "alloc-1",
				PoolID:    "pool-1",
				IPAddress: "10.0.0.50",
				Status:    "active",
				Type:      "dynamic",
				CreatedAt: now,
				UpdatedAt: now,
			},
			{
				ID:        "alloc-2",
				PoolID:    "pool-1",
				IPAddress: "10.0.0.51",
				Status:    "active",
				Type:      "dynamic",
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
	}
}

func (s *testGatewayService) Status(ctx context.Context) (*GatewayStatusInfo, error) {
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	return s.statusResp, nil
}

func (s *testGatewayService) SetMode(ctx context.Context, mode string) error {
	s.lastMode = mode
	if s.setModeErr != nil {
		return s.setModeErr
	}
	return nil
}

func (s *testGatewayService) BGPStatus(ctx context.Context) (*BGPStatusInfo, error) {
	if s.bgpStatusErr != nil {
		return nil, s.bgpStatusErr
	}
	return s.bgpStatusResp, nil
}

func (s *testGatewayService) ListBGPPeers(ctx context.Context) ([]*BGPPeerInfo, error) {
	if s.bgpPeersErr != nil {
		return nil, s.bgpPeersErr
	}
	return s.bgpPeersResp, nil
}

func (s *testGatewayService) AnnouncePrefix(ctx context.Context, prefix string, opts *AnnouncePrefixOptions) error {
	s.lastPrefix = prefix
	s.lastPrefixOpts = opts
	if s.announcePrefixErr != nil {
		return s.announcePrefixErr
	}
	return nil
}

func (s *testGatewayService) WithdrawPrefix(ctx context.Context, prefix string) error {
	s.lastPrefix = prefix
	if s.withdrawPrefixErr != nil {
		return s.withdrawPrefixErr
	}
	return nil
}

func (s *testGatewayService) ListPrefixes(ctx context.Context) ([]*PrefixInfo, error) {
	if s.listPrefixesErr != nil {
		return nil, s.listPrefixesErr
	}
	return s.prefixesResp, nil
}

func (s *testGatewayService) ListIPAMPools(ctx context.Context, zone string) ([]*IPAMPoolInfo, error) {
	if s.listIPAMPoolsErr != nil {
		return nil, s.listIPAMPoolsErr
	}
	return s.ipamPoolsResp, nil
}

func (s *testGatewayService) GetIPAMPool(ctx context.Context, poolID string) (*IPAMPoolInfo, error) {
	if s.listIPAMPoolsErr != nil {
		return nil, s.listIPAMPoolsErr
	}
	for _, p := range s.ipamPoolsResp {
		if p != nil && p.ID == poolID {
			return p, nil
		}
	}
	return nil, ErrGatewayPoolNotFound
}

func (s *testGatewayService) UpdateIPAMPool(ctx context.Context, poolID string, opts *UpdateIPAMPoolOptions) (*IPAMPoolInfo, error) {
	if s.listIPAMPoolsErr != nil {
		return nil, s.listIPAMPoolsErr
	}
	return &IPAMPoolInfo{ID: poolID}, nil
}

func (s *testGatewayService) CreateIPAMPool(ctx context.Context, opts *CreateIPAMPoolOptions) (*IPAMPoolInfo, error) {
	s.lastCreatePoolOpts = opts
	if s.createPoolErr != nil {
		return nil, s.createPoolErr
	}
	return s.createPoolResp, nil
}

func (s *testGatewayService) DeleteIPAMPool(ctx context.Context, poolID string) error {
	s.lastDeletePoolID = poolID
	if s.deletePoolErr != nil {
		return s.deletePoolErr
	}
	return nil
}

func (s *testGatewayService) AllocateIP(ctx context.Context, poolID string, opts *AllocateIPOptions) (*IPAllocationInfo, error) {
	s.lastPoolID = poolID
	s.lastAllocateOpts = opts
	if s.allocateIPErr != nil {
		return nil, s.allocateIPErr
	}
	return s.allocationResp, nil
}

func (s *testGatewayService) ReleaseIP(ctx context.Context, poolID string, ip string) error {
	s.lastPoolID = poolID
	s.lastReleaseIP = ip
	if s.releaseIPErr != nil {
		return s.releaseIPErr
	}
	return nil
}

func (s *testGatewayService) ListAllocations(ctx context.Context, poolID string) ([]*IPAllocationInfo, error) {
	s.lastPoolID = poolID
	if s.listAllocErr != nil {
		return nil, s.listAllocErr
	}
	return s.allocationsResp, nil
}

func (s *testGatewayService) ListNetworkZones(ctx context.Context, lifecycleRole string) ([]*NetworkZoneInfo, error) {
	return []*NetworkZoneInfo{}, nil
}

func (s *testGatewayService) CreateNetworkZone(ctx context.Context, opts *CreateNetworkZoneOptions) (*NetworkZoneInfo, error) {
	return &NetworkZoneInfo{Name: opts.Name}, nil
}

func (s *testGatewayService) UpdateNetworkZone(ctx context.Context, name string, opts *UpdateNetworkZoneOptions) (*NetworkZoneInfo, error) {
	return &NetworkZoneInfo{Name: name}, nil
}

func (s *testGatewayService) DeleteNetworkZone(ctx context.Context, name string) (bool, error) {
	return false, nil
}

func (s *testGatewayService) AssignNetworkZone(ctx context.Context, network string, zoneName string) (bool, error) {
	return false, nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func newGatewayTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelInfo, nil)
}

func createTestGatewayHandler() (*GatewayHandler, *testGatewayService) {
	logger := newGatewayTestLogger()
	service := newTestGatewayService()
	handler := NewGatewayHandler(logger, service)
	return handler, service
}

// =============================================================================
// Test: NewGatewayHandler
// =============================================================================

func TestNewGatewayHandler(t *testing.T) {
	t.Parallel()

	t.Run("creates handler with valid inputs", func(t *testing.T) {
		t.Parallel()
		logger := newGatewayTestLogger()
		service := newTestGatewayService()
		handler := NewGatewayHandler(logger, service)

		assert.NotNil(t, handler)
		assert.Equal(t, logger, handler.logger)
		assert.Equal(t, service, handler.gatewayService)
	})

	t.Run("creates handler with nil service", func(t *testing.T) {
		t.Parallel()
		logger := newGatewayTestLogger()
		handler := NewGatewayHandler(logger, nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.gatewayService)
	})
}

// =============================================================================
// Test: HandleRequest
// =============================================================================

func TestGatewayHandleRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("returns error for nil request", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.HandleRequest(ctx, nil)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "request cannot be nil")
	})

	t.Run("returns error for unknown opcode", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  0xFF,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "unknown gateway operation")
	})

	t.Run("routes to status handler", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})
}

// =============================================================================
// Test: handleStatus
// =============================================================================

func TestGatewayHandleStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("returns status successfully", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var statusResp GatewayStatusResponse
		err := DecodePayload(resp.Payload, &statusResp)
		require.NoError(t, err)

		assert.NotNil(t, statusResp.Status)
		assert.Equal(t, true, statusResp.Status.Enabled)
		assert.Equal(t, GatewayModeL3, statusResp.Status.Mode)
		assert.Equal(t, "healthy", statusResp.Status.HealthStatus)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		req := &Request{
			Opcode:  OpGatewayStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error when status fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.statusErr = errors.New("status unavailable")

		req := &Request{
			Opcode:  OpGatewayStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleSetMode
// =============================================================================

func TestGatewayHandleSetMode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("sets mode successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()

		setReq := &GatewaySetModeRequest{
			Mode: GatewayModeL2,
		}

		payload, err := EncodePayload(setReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewaySetMode,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
		assert.Equal(t, GatewayModeL2, service.lastMode)

		var setResp GatewaySetModeResponse
		err = DecodePayload(resp.Payload, &setResp)
		require.NoError(t, err)

		assert.Equal(t, GatewayModeL2, setResp.Mode)
		assert.True(t, setResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		setReq := &GatewaySetModeRequest{
			Mode: GatewayModeL3,
		}

		payload, err := EncodePayload(setReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewaySetMode,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing mode", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		setReq := &GatewaySetModeRequest{}

		payload, err := EncodePayload(setReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewaySetMode,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "mode")
	})

	t.Run("returns error for invalid mode", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		setReq := &GatewaySetModeRequest{
			Mode: "invalid-mode",
		}

		payload, err := EncodePayload(setReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewaySetMode,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewaySetMode,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when set mode fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.setModeErr = errors.New("failed to set mode")

		setReq := &GatewaySetModeRequest{
			Mode: GatewayModeNAT,
		}

		payload, err := EncodePayload(setReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewaySetMode,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})

	t.Run("sets all valid modes", func(t *testing.T) {
		t.Parallel()
		modes := []string{GatewayModeL2, GatewayModeL3, GatewayModeNAT, GatewayModeDisabled}

		for _, mode := range modes {
			handler, service := createTestGatewayHandler()

			setReq := &GatewaySetModeRequest{
				Mode: mode,
			}

			payload, err := EncodePayload(setReq)
			require.NoError(t, err)

			req := &Request{
				Opcode:  OpGatewaySetMode,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)

			assert.Equal(t, StatusOK, resp.Status, "mode %s should be valid", mode)
			assert.Equal(t, mode, service.lastMode)
		}
	})
}

// =============================================================================
// Test: handleBGPStatus
// =============================================================================

func TestGatewayHandleBGPStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("returns BGP status successfully", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayBGPStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var bgpResp GatewayBGPStatusResponse
		err := DecodePayload(resp.Payload, &bgpResp)
		require.NoError(t, err)

		assert.NotNil(t, bgpResp.Status)
		assert.True(t, bgpResp.Status.Enabled)
		assert.Equal(t, "10.0.0.1", bgpResp.Status.RouterID)
		assert.Equal(t, uint32(65000), bgpResp.Status.LocalAS)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		req := &Request{
			Opcode:  OpGatewayBGPStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error when BGP status fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.bgpStatusErr = ErrGatewayBGPNotEnabled

		req := &Request{
			Opcode:  OpGatewayBGPStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})
}

// =============================================================================
// Test: handleBGPPeers
// =============================================================================

func TestGatewayHandleBGPPeers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("lists BGP peers successfully", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayBGPPeersRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayBGPPeers,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var peersResp GatewayBGPPeersResponse
		err = DecodePayload(resp.Payload, &peersResp)
		require.NoError(t, err)

		assert.Len(t, peersResp.Peers, 2)
		assert.Equal(t, int32(2), peersResp.Count)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		listReq := &GatewayBGPPeersRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayBGPPeers,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayBGPPeers,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayBGPPeersRequest{
			Limit: 1,
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayBGPPeers,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var peersResp GatewayBGPPeersResponse
		err = DecodePayload(resp.Payload, &peersResp)
		require.NoError(t, err)

		assert.Len(t, peersResp.Peers, 1)
		assert.Equal(t, int32(1), peersResp.Count)
	})

	t.Run("returns error when list BGP peers fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.bgpPeersErr = errors.New("failed to list peers")

		listReq := &GatewayBGPPeersRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayBGPPeers,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleAnnouncePrefix
// =============================================================================

func TestGatewayHandleAnnouncePrefix(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("announces prefix successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()

		announceReq := &GatewayAnnouncePrefixRequest{
			Prefix:    "192.168.100.0/24",
			NextHop:   "10.0.0.1",
			LocalPref: 100,
		}

		payload, err := EncodePayload(announceReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayAnnouncePrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
		assert.Equal(t, "192.168.100.0/24", service.lastPrefix)
		assert.Equal(t, "10.0.0.1", service.lastPrefixOpts.NextHop)

		var announceResp GatewayAnnouncePrefixResponse
		err = DecodePayload(resp.Payload, &announceResp)
		require.NoError(t, err)

		assert.Equal(t, "192.168.100.0/24", announceResp.Prefix)
		assert.True(t, announceResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		announceReq := &GatewayAnnouncePrefixRequest{
			Prefix: "192.168.100.0/24",
		}

		payload, err := EncodePayload(announceReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayAnnouncePrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing prefix", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		announceReq := &GatewayAnnouncePrefixRequest{}

		payload, err := EncodePayload(announceReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayAnnouncePrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "prefix")
	})

	t.Run("returns error for invalid prefix format", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		announceReq := &GatewayAnnouncePrefixRequest{
			Prefix: "invalid-prefix",
		}

		payload, err := EncodePayload(announceReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayAnnouncePrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayAnnouncePrefix,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when announce fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.announcePrefixErr = ErrGatewayPrefixAlreadyExists

		announceReq := &GatewayAnnouncePrefixRequest{
			Prefix: "192.168.100.0/24",
		}

		payload, err := EncodePayload(announceReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayAnnouncePrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusAlreadyExists, resp.Status)
	})
}

// =============================================================================
// Test: handleWithdrawPrefix
// =============================================================================

func TestGatewayHandleWithdrawPrefix(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("withdraws prefix successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()

		withdrawReq := &GatewayWithdrawPrefixRequest{
			Prefix: "192.168.100.0/24",
		}

		payload, err := EncodePayload(withdrawReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayWithdrawPrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
		assert.Equal(t, "192.168.100.0/24", service.lastPrefix)

		var withdrawResp GatewayWithdrawPrefixResponse
		err = DecodePayload(resp.Payload, &withdrawResp)
		require.NoError(t, err)

		assert.Equal(t, "192.168.100.0/24", withdrawResp.Prefix)
		assert.True(t, withdrawResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		withdrawReq := &GatewayWithdrawPrefixRequest{
			Prefix: "192.168.100.0/24",
		}

		payload, err := EncodePayload(withdrawReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayWithdrawPrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing prefix", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		withdrawReq := &GatewayWithdrawPrefixRequest{}

		payload, err := EncodePayload(withdrawReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayWithdrawPrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid prefix format", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		withdrawReq := &GatewayWithdrawPrefixRequest{
			Prefix: "not-a-cidr",
		}

		payload, err := EncodePayload(withdrawReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayWithdrawPrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayWithdrawPrefix,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when withdraw fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.withdrawPrefixErr = ErrGatewayPrefixNotFound

		withdrawReq := &GatewayWithdrawPrefixRequest{
			Prefix: "192.168.100.0/24",
		}

		payload, err := EncodePayload(withdrawReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayWithdrawPrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: handleListPrefixes
// =============================================================================

func TestGatewayHandleListPrefixes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("lists prefixes successfully", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayListPrefixesRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListPrefixes,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp GatewayListPrefixesResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Prefixes, 2)
		assert.Equal(t, int32(2), listResp.Count)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		listReq := &GatewayListPrefixesRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListPrefixes,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayListPrefixes,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayListPrefixesRequest{
			Limit: 1,
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListPrefixes,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp GatewayListPrefixesResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Prefixes, 1)
	})

	t.Run("returns error when list prefixes fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.listPrefixesErr = errors.New("failed to list prefixes")

		listReq := &GatewayListPrefixesRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListPrefixes,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleListIPAMPools
// =============================================================================

func TestGatewayHandleListIPAMPools(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("lists IPAM pools successfully", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayListIPAMPoolsRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListIPAMPools,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp GatewayListIPAMPoolsResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Pools, 2)
		assert.Equal(t, int32(2), listResp.Count)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		listReq := &GatewayListIPAMPoolsRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListIPAMPools,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayListIPAMPools,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayListIPAMPoolsRequest{
			Limit: 1,
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListIPAMPools,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp GatewayListIPAMPoolsResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Pools, 1)
	})

	t.Run("returns error when list IPAM pools fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.listIPAMPoolsErr = errors.New("failed to list pools")

		listReq := &GatewayListIPAMPoolsRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListIPAMPools,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleCreateIPAMPool
// =============================================================================

func TestGatewayHandleCreateIPAMPool(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("creates IPAM pool successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()

		createReq := &GatewayCreateIPAMPoolRequest{
			Name:    "TestPool",
			CIDR:    "10.0.2.0/24",
			Gateway: "10.0.2.1",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
		assert.Equal(t, "TestPool", service.lastCreatePoolOpts.Name)
		assert.Equal(t, "10.0.2.0/24", service.lastCreatePoolOpts.CIDR)
		assert.Equal(t, "10.0.2.1", service.lastCreatePoolOpts.Gateway)

		var createResp GatewayCreateIPAMPoolResponse
		err = DecodePayload(resp.Payload, &createResp)
		require.NoError(t, err)

		assert.NotNil(t, createResp.Pool)
		assert.Equal(t, "pool-new", createResp.Pool.ID)
		assert.Equal(t, "TestPool", createResp.Pool.Name)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		createReq := &GatewayCreateIPAMPoolRequest{
			Name: "TestPool",
			CIDR: "10.0.2.0/24",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		createReq := &GatewayCreateIPAMPoolRequest{
			CIDR: "10.0.2.0/24",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "pool name")
	})

	t.Run("returns error for missing CIDR", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		createReq := &GatewayCreateIPAMPoolRequest{
			Name: "TestPool",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "pool CIDR")
	})

	t.Run("returns error for invalid CIDR format", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		createReq := &GatewayCreateIPAMPoolRequest{
			Name: "TestPool",
			CIDR: "not-a-cidr",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayCreateIPAMPool,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when pool already exists", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.createPoolErr = ErrGatewayPoolAlreadyExists

		createReq := &GatewayCreateIPAMPoolRequest{
			Name: "TestPool",
			CIDR: "10.0.2.0/24",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusAlreadyExists, resp.Status)
	})

	t.Run("returns error when create fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.createPoolErr = errors.New("failed to create pool")

		createReq := &GatewayCreateIPAMPoolRequest{
			Name: "TestPool",
			CIDR: "10.0.2.0/24",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleDeleteIPAMPool
// =============================================================================

func TestGatewayHandleDeleteIPAMPool(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("deletes IPAM pool successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()

		deleteReq := &GatewayDeleteIPAMPoolRequest{
			PoolID: "pool-1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayDeleteIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
		assert.Equal(t, "pool-1", service.lastDeletePoolID)

		var deleteResp GatewayDeleteIPAMPoolResponse
		err = DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.Equal(t, "pool-1", deleteResp.PoolID)
		assert.True(t, deleteResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		deleteReq := &GatewayDeleteIPAMPoolRequest{
			PoolID: "pool-1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayDeleteIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing pool ID", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		deleteReq := &GatewayDeleteIPAMPoolRequest{}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayDeleteIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "pool ID")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayDeleteIPAMPool,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when pool not found", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.deletePoolErr = ErrGatewayPoolNotFound

		deleteReq := &GatewayDeleteIPAMPoolRequest{
			PoolID: "nonexistent-pool",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayDeleteIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error when delete fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.deletePoolErr = errors.New("failed to delete pool")

		deleteReq := &GatewayDeleteIPAMPoolRequest{
			PoolID: "pool-1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayDeleteIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleGetIPAMPool
// =============================================================================

func TestGatewayHandleGetIPAMPool(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("returns pool successfully", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		getReq := &GatewayGetIPAMPoolRequest{PoolID: "pool-1"}
		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{Opcode: OpGatewayGetIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var getResp GatewayGetIPAMPoolResponse
		err = DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Pool)
		assert.Equal(t, "pool-1", getResp.Pool.ID)
		assert.Equal(t, "Production", getResp.Pool.Name)
		assert.Equal(t, "10.0.0.0/24", getResp.Pool.CIDR)
	})

	t.Run("returns not found when pool does not exist", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		getReq := &GatewayGetIPAMPoolRequest{PoolID: "pool-does-not-exist"}
		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{Opcode: OpGatewayGetIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error for missing pool ID", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		getReq := &GatewayGetIPAMPoolRequest{PoolID: ""}
		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{Opcode: OpGatewayGetIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		getReq := &GatewayGetIPAMPoolRequest{PoolID: "pool-1"}
		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{Opcode: OpGatewayGetIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error when get fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.listIPAMPoolsErr = errors.New("backend error")

		getReq := &GatewayGetIPAMPoolRequest{PoolID: "pool-1"}
		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{Opcode: OpGatewayGetIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleUpdateIPAMPool
// =============================================================================

func TestGatewayHandleUpdateIPAMPool(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("updates pool successfully", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		updateReq := &GatewayUpdateIPAMPoolRequest{
			PoolID:      "pool-1",
			Name:        "UpdatedName",
			Description: "updated description",
		}
		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{Opcode: OpGatewayUpdateIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var updateResp GatewayUpdateIPAMPoolResponse
		err = DecodePayload(resp.Payload, &updateResp)
		require.NoError(t, err)

		assert.NotNil(t, updateResp.Pool)
		assert.Equal(t, "pool-1", updateResp.Pool.ID)
	})

	t.Run("returns error for missing pool ID", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		updateReq := &GatewayUpdateIPAMPoolRequest{PoolID: "", Name: "NewName"}
		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{Opcode: OpGatewayUpdateIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		updateReq := &GatewayUpdateIPAMPoolRequest{PoolID: "pool-1", Name: "NewName"}
		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{Opcode: OpGatewayUpdateIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error when update fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.listIPAMPoolsErr = errors.New("backend error")

		updateReq := &GatewayUpdateIPAMPoolRequest{PoolID: "pool-1", Name: "NewName"}
		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{Opcode: OpGatewayUpdateIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{Opcode: OpGatewayUpdateIPAMPool, Payload: []byte("invalid payload")}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: handleAllocateIP
// =============================================================================

func TestGatewayHandleAllocateIP(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("allocates IP successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()

		allocReq := &GatewayAllocateIPRequest{
			PoolID:   "pool-1",
			Hostname: "test-host",
			Owner:    "test-owner",
		}

		payload, err := EncodePayload(allocReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
		assert.Equal(t, "pool-1", service.lastPoolID)
		assert.Equal(t, "test-host", service.lastAllocateOpts.Hostname)

		var allocResp GatewayAllocateIPResponse
		err = DecodePayload(resp.Payload, &allocResp)
		require.NoError(t, err)

		assert.NotNil(t, allocResp.Allocation)
		assert.Equal(t, "10.0.0.50", allocResp.Allocation.IPAddress)
	})

	t.Run("allocates specific IP successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()

		allocReq := &GatewayAllocateIPRequest{
			PoolID:    "pool-1",
			IPAddress: "10.0.0.100",
		}

		payload, err := EncodePayload(allocReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
		assert.Equal(t, "10.0.0.100", service.lastAllocateOpts.IPAddress)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		allocReq := &GatewayAllocateIPRequest{
			PoolID: "pool-1",
		}

		payload, err := EncodePayload(allocReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing pool ID", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		allocReq := &GatewayAllocateIPRequest{}

		payload, err := EncodePayload(allocReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "pool ID")
	})

	t.Run("returns error for invalid IP address", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		allocReq := &GatewayAllocateIPRequest{
			PoolID:    "pool-1",
			IPAddress: "invalid-ip",
		}

		payload, err := EncodePayload(allocReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayAllocateIP,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when pool exhausted", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.allocateIPErr = ErrGatewayPoolExhausted

		allocReq := &GatewayAllocateIPRequest{
			PoolID: "pool-1",
		}

		payload, err := EncodePayload(allocReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusResourceExhausted, resp.Status)
	})

	t.Run("returns error when pool not found", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.allocateIPErr = ErrGatewayPoolNotFound

		allocReq := &GatewayAllocateIPRequest{
			PoolID: "nonexistent-pool",
		}

		payload, err := EncodePayload(allocReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: handleReleaseIP
// =============================================================================

func TestGatewayHandleReleaseIP(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("releases IP successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()

		releaseReq := &GatewayReleaseIPRequest{
			PoolID:    "pool-1",
			IPAddress: "10.0.0.50",
		}

		payload, err := EncodePayload(releaseReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayReleaseIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
		assert.Equal(t, "pool-1", service.lastPoolID)
		assert.Equal(t, "10.0.0.50", service.lastReleaseIP)

		var releaseResp GatewayReleaseIPResponse
		err = DecodePayload(resp.Payload, &releaseResp)
		require.NoError(t, err)

		assert.Equal(t, "pool-1", releaseResp.PoolID)
		assert.Equal(t, "10.0.0.50", releaseResp.IPAddress)
		assert.True(t, releaseResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		releaseReq := &GatewayReleaseIPRequest{
			PoolID:    "pool-1",
			IPAddress: "10.0.0.50",
		}

		payload, err := EncodePayload(releaseReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayReleaseIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing pool ID", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		releaseReq := &GatewayReleaseIPRequest{
			IPAddress: "10.0.0.50",
		}

		payload, err := EncodePayload(releaseReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayReleaseIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "pool ID")
	})

	t.Run("returns error for missing IP address", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		releaseReq := &GatewayReleaseIPRequest{
			PoolID: "pool-1",
		}

		payload, err := EncodePayload(releaseReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayReleaseIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "IP address")
	})

	t.Run("returns error for invalid IP address", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		releaseReq := &GatewayReleaseIPRequest{
			PoolID:    "pool-1",
			IPAddress: "invalid-ip",
		}

		payload, err := EncodePayload(releaseReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayReleaseIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayReleaseIP,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when allocation not found", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.releaseIPErr = ErrGatewayAllocationNotFound

		releaseReq := &GatewayReleaseIPRequest{
			PoolID:    "pool-1",
			IPAddress: "10.0.0.99",
		}

		payload, err := EncodePayload(releaseReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayReleaseIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: handleListAllocations
// =============================================================================

func TestGatewayHandleListAllocations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("lists allocations successfully", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()

		listReq := &GatewayListAllocationsRequest{
			PoolID: "pool-1",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListAllocations,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
		assert.Equal(t, "pool-1", service.lastPoolID)

		var listResp GatewayListAllocationsResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Allocations, 2)
		assert.Equal(t, int32(2), listResp.Count)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		listReq := &GatewayListAllocationsRequest{
			PoolID: "pool-1",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListAllocations,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("empty pool ID lists all allocations", func(t *testing.T) {
		// Empty PoolID means list all allocations (list-all semantics, same as gRPC ListAllocations).
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayListAllocationsRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListAllocations,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
		var listResp GatewayListAllocationsResponse
		require.NoError(t, DecodePayload(resp.Payload, &listResp))
		assert.NotNil(t, listResp.Allocations)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &Request{
			Opcode:  OpGatewayListAllocations,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayListAllocationsRequest{
			PoolID: "pool-1",
			Limit:  1,
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListAllocations,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp GatewayListAllocationsResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Allocations, 1)
	})

	t.Run("returns error when list allocations fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.listAllocErr = errors.New("failed to list allocations")

		listReq := &GatewayListAllocationsRequest{
			PoolID: "pool-1",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpGatewayListAllocations,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: errorResponse and gatewayErrorResponse
// =============================================================================

func TestGatewayHandlerErrorResponse(t *testing.T) {
	t.Parallel()

	t.Run("maps prefix not found to NotFound status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayPrefixNotFound)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("maps pool not found to NotFound status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayPoolNotFound)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("maps allocation not found to NotFound status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayAllocationNotFound)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("maps BGP peer not found to NotFound status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayBGPPeerNotFound)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("maps prefix already exists to AlreadyExists status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayPrefixAlreadyExists)

		assert.Equal(t, StatusAlreadyExists, resp.Status)
	})

	t.Run("maps pool already exists to AlreadyExists status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayPoolAlreadyExists)

		assert.Equal(t, StatusAlreadyExists, resp.Status)
	})

	t.Run("maps pool exhausted to ResourceExhausted status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayPoolExhausted)

		assert.Equal(t, StatusResourceExhausted, resp.Status)
	})

	t.Run("maps invalid mode to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayInvalidMode)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("maps invalid prefix to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayInvalidPrefix)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("maps invalid IP address to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayInvalidIPAddress)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("maps invalid pool CIDR to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayInvalidPoolCIDR)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing mode to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayMissingMode)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing prefix to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayMissingPrefix)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing pool ID to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayMissingPoolID)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing pool name to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayMissingPoolName)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing pool CIDR to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayMissingPoolCIDR)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing IP address to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayMissingIPAddress)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("maps BGP not enabled to Unavailable status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayBGPNotEnabled)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("maps service not available to Unavailable status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayServiceNotAvailable)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("maps unknown error to InternalError status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(errors.New("unknown error"))

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}
