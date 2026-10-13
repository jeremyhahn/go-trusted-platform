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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// =============================================================================
// Mock Gateway Service
// =============================================================================

// testGatewayService implements GatewayServiceInterface for testing
type testGatewayService struct {
	// Zone fake state: zoneErr fails every zone call; the last* fields
	// record what the handler passed.
	zoneErr        error
	lastZoneCreate *CreateNetworkZoneOptions
	lastZoneUpdate *UpdateNetworkZoneOptions
	lastZoneName   string
	lastZoneRole   string

	// Response data
	statusResp      *GatewayStatusInfo
	bgpStatusResp   *BGPStatusInfo
	bgpPeersResp    []*BGPPeerInfo
	prefixesResp    []*PrefixInfo
	ipamPoolsResp   []*IPAMPoolInfo
	createPoolResp  *IPAMPoolInfo
	allocationResp  *IPAllocationInfo
	allocationsResp []*IPAllocationInfo
	snapshotResp    *GatewaySnapshotInfo
	snapshotsResp   []*GatewaySnapshotInfo
	lastSnapshotID  string

	// Error injection
	statusErr         error
	snapshotErr       error
	snapshotsErr      error
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

	// Load balancer responses and error injection
	vipResp           *LBVIPInfo
	vipsResp          []*LBVIPInfo
	lbStatusResp      *LBStatusInfo
	nat64StatusResp   *quicwire.NAT64StatusInfo
	addVIPErr         error
	removeVIPErr      error
	getVIPErr         error
	listVIPsErr       error
	setVIPBackendsErr error
	lbStatusErr       error
	nat64StatusErr    error
	lastVIPSpec       *LBVIPSpec

	// Capture last request for validation
	lastModes          uint32
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
			ID:            "gw-1",
			NodeID:        "node-1",
			Modes:         quicwire.GatewayModeOverlay | quicwire.GatewayModeEdge,
			Tier:          "edge",
			Reputation:    0.9,
			UptimeSeconds: 3600,
			Healthy:       true,
			StartedAt:     now - 3600,
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

func (s *testGatewayService) Snapshot(ctx context.Context, gatewayID string) (*GatewaySnapshotInfo, error) {
	s.lastSnapshotID = gatewayID
	if s.snapshotErr != nil {
		return nil, s.snapshotErr
	}
	return s.snapshotResp, nil
}

func (s *testGatewayService) ListSnapshots(ctx context.Context) ([]*GatewaySnapshotInfo, error) {
	if s.snapshotsErr != nil {
		return nil, s.snapshotsErr
	}
	return s.snapshotsResp, nil
}

func (s *testGatewayService) GetAdmittedVTEP(_ context.Context, _, _ string) (*quicwire.GatewayAdmittedVTEPInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}

func (s *testGatewayService) ListAdmittedVTEPs(_ context.Context, _ string) ([]*quicwire.GatewayAdmittedVTEPInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}

func (s *testGatewayService) SetModes(ctx context.Context, modes uint32) (*GatewayStatusInfo, error) {
	s.lastModes = modes
	if s.setModeErr != nil {
		return nil, s.setModeErr
	}
	status := *s.statusResp
	status.Modes = modes
	return &status, nil
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
	s.lastZoneRole = lifecycleRole
	if s.zoneErr != nil {
		return nil, s.zoneErr
	}
	return []*NetworkZoneInfo{{
		Name:          "provisioning",
		Offset:        5,
		LifecycleRole: lifecycleRole,
		Numbering:     &NetworkZoneNumberingInfo{VLAN: 405, Subnet4: "192.0.2.0/24", Gateway: "192.0.2.1"},
	}}, nil
}

func (s *testGatewayService) CreateNetworkZone(ctx context.Context, opts *CreateNetworkZoneOptions) (*NetworkZoneInfo, error) {
	s.lastZoneCreate = opts
	if s.zoneErr != nil {
		return nil, s.zoneErr
	}
	return &NetworkZoneInfo{Name: opts.Name, Offset: opts.Offset, RestartRequired: true}, nil
}

func (s *testGatewayService) UpdateNetworkZone(ctx context.Context, name string, opts *UpdateNetworkZoneOptions) (*NetworkZoneInfo, error) {
	s.lastZoneName = name
	s.lastZoneUpdate = opts
	if s.zoneErr != nil {
		return nil, s.zoneErr
	}
	return &NetworkZoneInfo{Name: name, RestartRequired: true}, nil
}

func (s *testGatewayService) DeleteNetworkZone(ctx context.Context, name string) (bool, error) {
	s.lastZoneName = name
	if s.zoneErr != nil {
		return false, s.zoneErr
	}
	return true, nil
}

// Load balancer fake state
func (s *testGatewayService) AddVIP(ctx context.Context, spec *LBVIPSpec) (*LBVIPInfo, error) {
	if s.addVIPErr != nil {
		return nil, s.addVIPErr
	}
	s.lastVIPSpec = spec
	return s.vipResp, nil
}

func (s *testGatewayService) RemoveVIP(ctx context.Context, protocol, address string, port uint16) error {
	return s.removeVIPErr
}

func (s *testGatewayService) GetVIP(ctx context.Context, protocol, address string, port uint16) (*LBVIPInfo, error) {
	if s.getVIPErr != nil {
		return nil, s.getVIPErr
	}
	return s.vipResp, nil
}

func (s *testGatewayService) ListVIPs(ctx context.Context) ([]*LBVIPInfo, error) {
	if s.listVIPsErr != nil {
		return nil, s.listVIPsErr
	}
	return s.vipsResp, nil
}

func (s *testGatewayService) SetVIPBackends(ctx context.Context, protocol, address string, port uint16, backends []*LBBackendSpec) (*LBVIPInfo, error) {
	if s.setVIPBackendsErr != nil {
		return nil, s.setVIPBackendsErr
	}
	return s.vipResp, nil
}

func (s *testGatewayService) LBStatus(ctx context.Context) (*LBStatusInfo, error) {
	if s.lbStatusErr != nil {
		return nil, s.lbStatusErr
	}
	return s.lbStatusResp, nil
}

func (s *testGatewayService) NAT64Status(ctx context.Context) (*quicwire.NAT64StatusInfo, error) {
	if s.nat64StatusErr != nil {
		return nil, s.nat64StatusErr
	}
	return s.nat64StatusResp, nil
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

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "request cannot be nil")
	})

	t.Run("returns error for unknown opcode", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  0xFF,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "unknown gateway operation")
	})

	t.Run("routes to status handler", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
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

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var statusResp GatewayStatusResponse
		err := quicwire.DecodePayload(resp.Payload, &statusResp)
		require.NoError(t, err)

		assert.NotNil(t, statusResp.Status)
		assert.True(t, statusResp.Status.Healthy)
		assert.Equal(t, quicwire.GatewayModeOverlay|quicwire.GatewayModeEdge, statusResp.Status.Modes)
		assert.Equal(t, "gw-1", statusResp.Status.ID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when status fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.statusErr = errors.New("status unavailable")

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: handleSetMode
// =============================================================================

func TestGatewayHandleSetMode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	setMode := func(t *testing.T, handler *GatewayHandler, modes uint32) *quicwire.Response {
		t.Helper()
		payload, err := quicwire.EncodePayload(&GatewaySetModeRequest{Modes: modes})
		require.NoError(t, err)
		return handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpGatewaySetMode,
			Payload: payload,
		})
	}

	t.Run("sets modes and returns the status after the change", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		want := quicwire.GatewayModeEdge | quicwire.GatewayModeTransit

		resp := setMode(t, handler, want)

		require.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, want, service.lastModes)
		var setResp GatewaySetModeResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &setResp))
		assert.True(t, setResp.Success)
		require.NotNil(t, setResp.Status)
		assert.Equal(t, want, setResp.Status.Modes)
	})

	t.Run("accepts every single mode and all three together", func(t *testing.T) {
		t.Parallel()
		for _, modes := range []uint32{
			quicwire.GatewayModeOverlay,
			quicwire.GatewayModeEdge,
			quicwire.GatewayModeTransit,
			quicwire.GatewayModesAll,
		} {
			handler, service := createTestGatewayHandler()
			resp := setMode(t, handler, modes)
			assert.Equal(t, quicwire.StatusOK, resp.Status, "modes %d should be valid", modes)
			assert.Equal(t, modes, service.lastModes)
		}
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		resp := setMode(t, handler, quicwire.GatewayModeEdge)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("refuses an empty mode set before the service", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()

		resp := setMode(t, handler, 0)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "mode")
		assert.Zero(t, service.lastModes)
	})

	t.Run("refuses an undefined mode bit before the service", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()

		resp := setMode(t, handler, quicwire.GatewayModeEdge|8)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Zero(t, service.lastModes)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewaySetMode,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when set mode fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.setModeErr = errors.New("failed to set mode")

		resp := setMode(t, handler, quicwire.GatewayModeTransit)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("maps a gRPC status from the service to its QUIC status", func(t *testing.T) {
		t.Parallel()
		cases := map[codes.Code]byte{
			codes.Unavailable:     quicwire.StatusUnavailable,
			codes.InvalidArgument: quicwire.StatusInvalidArgument,
			codes.NotFound:        quicwire.StatusNotFound,
		}
		for code, want := range cases {
			handler, service := createTestGatewayHandler()
			service.setModeErr = grpcstatus.Error(code, "from the gateway service")

			resp := setMode(t, handler, quicwire.GatewayModeEdge)

			assert.Equal(t, want, resp.Status, "gRPC code %s", code)
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

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayBGPStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var bgpResp GatewayBGPStatusResponse
		err := quicwire.DecodePayload(resp.Payload, &bgpResp)
		require.NoError(t, err)

		assert.NotNil(t, bgpResp.Status)
		assert.True(t, bgpResp.Status.Enabled)
		assert.Equal(t, "10.0.0.1", bgpResp.Status.RouterID)
		assert.Equal(t, uint32(65000), bgpResp.Status.LocalAS)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayBGPStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when BGP status fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.bgpStatusErr = ErrGatewayBGPNotEnabled

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayBGPStatus,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
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

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayBGPPeers,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var peersResp GatewayBGPPeersResponse
		err = quicwire.DecodePayload(resp.Payload, &peersResp)
		require.NoError(t, err)

		assert.Len(t, peersResp.Peers, 2)
		assert.Equal(t, int32(2), peersResp.Count)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		listReq := &GatewayBGPPeersRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayBGPPeers,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayBGPPeers,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayBGPPeersRequest{
			Limit: 1,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayBGPPeers,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var peersResp GatewayBGPPeersResponse
		err = quicwire.DecodePayload(resp.Payload, &peersResp)
		require.NoError(t, err)

		assert.Len(t, peersResp.Peers, 1)
		assert.Equal(t, int32(1), peersResp.Count)
	})

	t.Run("returns error when list BGP peers fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.bgpPeersErr = errors.New("failed to list peers")

		listReq := &GatewayBGPPeersRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayBGPPeers,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
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

		payload, err := quicwire.EncodePayload(announceReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAnnouncePrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, "192.168.100.0/24", service.lastPrefix)
		assert.Equal(t, "10.0.0.1", service.lastPrefixOpts.NextHop)

		var announceResp GatewayAnnouncePrefixResponse
		err = quicwire.DecodePayload(resp.Payload, &announceResp)
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

		payload, err := quicwire.EncodePayload(announceReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAnnouncePrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing prefix", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		announceReq := &GatewayAnnouncePrefixRequest{}

		payload, err := quicwire.EncodePayload(announceReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAnnouncePrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "prefix")
	})

	t.Run("returns error for invalid prefix format", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		announceReq := &GatewayAnnouncePrefixRequest{
			Prefix: "invalid-prefix",
		}

		payload, err := quicwire.EncodePayload(announceReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAnnouncePrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAnnouncePrefix,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when announce fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.announcePrefixErr = ErrGatewayPrefixAlreadyExists

		announceReq := &GatewayAnnouncePrefixRequest{
			Prefix: "192.168.100.0/24",
		}

		payload, err := quicwire.EncodePayload(announceReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAnnouncePrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
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

		payload, err := quicwire.EncodePayload(withdrawReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayWithdrawPrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, "192.168.100.0/24", service.lastPrefix)

		var withdrawResp GatewayWithdrawPrefixResponse
		err = quicwire.DecodePayload(resp.Payload, &withdrawResp)
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

		payload, err := quicwire.EncodePayload(withdrawReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayWithdrawPrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing prefix", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		withdrawReq := &GatewayWithdrawPrefixRequest{}

		payload, err := quicwire.EncodePayload(withdrawReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayWithdrawPrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid prefix format", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		withdrawReq := &GatewayWithdrawPrefixRequest{
			Prefix: "not-a-cidr",
		}

		payload, err := quicwire.EncodePayload(withdrawReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayWithdrawPrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayWithdrawPrefix,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when withdraw fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.withdrawPrefixErr = ErrGatewayPrefixNotFound

		withdrawReq := &GatewayWithdrawPrefixRequest{
			Prefix: "192.168.100.0/24",
		}

		payload, err := quicwire.EncodePayload(withdrawReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayWithdrawPrefix,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
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

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListPrefixes,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp GatewayListPrefixesResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Prefixes, 2)
		assert.Equal(t, int32(2), listResp.Count)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		listReq := &GatewayListPrefixesRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListPrefixes,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListPrefixes,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayListPrefixesRequest{
			Limit: 1,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListPrefixes,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp GatewayListPrefixesResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Prefixes, 1)
	})

	t.Run("returns error when list prefixes fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.listPrefixesErr = errors.New("failed to list prefixes")

		listReq := &GatewayListPrefixesRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListPrefixes,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestGatewayPage(t *testing.T) {
	t.Parallel()
	items := make([]int, 2500)
	for i := range items {
		items[i] = i
	}

	cases := []struct {
		name          string
		offset, limit int32
		wantFirst     int
		wantLen       int
	}{
		{name: "no limit is the default page", offset: 0, limit: 0, wantFirst: 0, wantLen: int(gatewayDefaultLimit)},
		{name: "a limit above the cap is capped", offset: 0, limit: 5000, wantFirst: 0, wantLen: int(gatewayMaxLimit)},
		{name: "an offset starts the page", offset: 2000, limit: 1000, wantFirst: 2000, wantLen: 500},
		{name: "an offset at the end is an empty page", offset: 2500, limit: 10, wantLen: 0},
		{name: "an offset past the end is an empty page", offset: 9000, limit: 10, wantLen: 0},
	}
	for _, tc := range cases {
		page, total, err := gatewayPage(items, tc.offset, tc.limit)
		require.NoError(t, err, tc.name)
		assert.Equal(t, int32(2500), total, tc.name)
		require.Len(t, page, tc.wantLen, tc.name)
		if tc.wantLen > 0 {
			assert.Equal(t, tc.wantFirst, page[0], tc.name)
		}
	}

	_, _, err := gatewayPage(items, -1, 10)
	assert.ErrorIs(t, err, ErrGatewayNegativeOffset)
}

// gatewayListCall sends one list request to the handler.
func gatewayListCall(t *testing.T, handler *GatewayHandler, opcode byte, req interface{}) *quicwire.Response {
	t.Helper()
	payload, err := quicwire.EncodePayload(req)
	require.NoError(t, err)
	return handler.HandleRequest(context.Background(), &quicwire.Request{Opcode: opcode, Payload: payload})
}

// TestGatewayBGPListsPageByOffset proves a client walking the offsets
// receives all of more peers and prefixes than the daemon's 1000 cap, with
// the total on every page, and that a negative offset is refused.
func TestGatewayBGPListsPageByOffset(t *testing.T) {
	t.Parallel()
	const entries = 2500
	handler, service := createTestGatewayHandler()
	service.bgpPeersResp = make([]*BGPPeerInfo, entries)
	service.prefixesResp = make([]*PrefixInfo, entries)
	for i := range entries {
		service.bgpPeersResp[i] = &BGPPeerInfo{RemoteAS: uint32(i)}
		service.prefixesResp[i] = &PrefixInfo{AnnouncedAt: int64(i)}
	}

	var peers []*BGPPeerInfo
	for offset := int32(0); ; {
		resp := gatewayListCall(t, handler, quicwire.OpGatewayBGPPeers,
			&GatewayBGPPeersRequest{Limit: gatewayMaxLimit, Offset: offset})
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var page GatewayBGPPeersResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &page))
		assert.Equal(t, int32(entries), page.Total)
		assert.Equal(t, int32(len(page.Peers)), page.Count)
		if len(page.Peers) == 0 {
			break
		}
		peers = append(peers, page.Peers...)
		offset += page.Count
	}
	require.Len(t, peers, entries)
	for i, peer := range peers {
		require.Equal(t, uint32(i), peer.RemoteAS, "peer %d out of order", i)
	}

	var prefixes []*PrefixInfo
	for offset := int32(0); ; {
		resp := gatewayListCall(t, handler, quicwire.OpGatewayListPrefixes,
			&GatewayListPrefixesRequest{Limit: gatewayMaxLimit, Offset: offset})
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var page GatewayListPrefixesResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &page))
		assert.Equal(t, int32(entries), page.Total)
		if len(page.Prefixes) == 0 {
			break
		}
		prefixes = append(prefixes, page.Prefixes...)
		offset += page.Count
	}
	require.Len(t, prefixes, entries)
	for i, prefix := range prefixes {
		require.Equal(t, int64(i), prefix.AnnouncedAt, "prefix %d out of order", i)
	}

	resp := gatewayListCall(t, handler, quicwire.OpGatewayBGPPeers, &GatewayBGPPeersRequest{Offset: -1})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	resp = gatewayListCall(t, handler, quicwire.OpGatewayListPrefixes, &GatewayListPrefixesRequest{Offset: -1})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
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

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListIPAMPools,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp GatewayListIPAMPoolsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Pools, 2)
		assert.Equal(t, int32(2), listResp.Count)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		listReq := &GatewayListIPAMPoolsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListIPAMPools,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListIPAMPools,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayListIPAMPoolsRequest{
			Limit: 1,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListIPAMPools,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp GatewayListIPAMPoolsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Pools, 1)
	})

	t.Run("returns error when list IPAM pools fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.listIPAMPoolsErr = errors.New("failed to list pools")

		listReq := &GatewayListIPAMPoolsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListIPAMPools,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
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

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, "TestPool", service.lastCreatePoolOpts.Name)
		assert.Equal(t, "10.0.2.0/24", service.lastCreatePoolOpts.CIDR)
		assert.Equal(t, "10.0.2.1", service.lastCreatePoolOpts.Gateway)

		var createResp GatewayCreateIPAMPoolResponse
		err = quicwire.DecodePayload(resp.Payload, &createResp)
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

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		createReq := &GatewayCreateIPAMPoolRequest{
			CIDR: "10.0.2.0/24",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "pool name")
	})

	t.Run("returns error for missing CIDR", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		createReq := &GatewayCreateIPAMPoolRequest{
			Name: "TestPool",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "pool CIDR")
	})

	t.Run("returns error for invalid CIDR format", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		createReq := &GatewayCreateIPAMPoolRequest{
			Name: "TestPool",
			CIDR: "not-a-cidr",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayCreateIPAMPool,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when pool already exists", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.createPoolErr = ErrGatewayPoolAlreadyExists

		createReq := &GatewayCreateIPAMPoolRequest{
			Name: "TestPool",
			CIDR: "10.0.2.0/24",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
	})

	t.Run("returns error when create fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.createPoolErr = errors.New("failed to create pool")

		createReq := &GatewayCreateIPAMPoolRequest{
			Name: "TestPool",
			CIDR: "10.0.2.0/24",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayCreateIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
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

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayDeleteIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, "pool-1", service.lastDeletePoolID)

		var deleteResp GatewayDeleteIPAMPoolResponse
		err = quicwire.DecodePayload(resp.Payload, &deleteResp)
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

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayDeleteIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing pool ID", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		deleteReq := &GatewayDeleteIPAMPoolRequest{}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayDeleteIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "pool ID")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayDeleteIPAMPool,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when pool not found", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.deletePoolErr = ErrGatewayPoolNotFound

		deleteReq := &GatewayDeleteIPAMPoolRequest{
			PoolID: "nonexistent-pool",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayDeleteIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("returns error when delete fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.deletePoolErr = errors.New("failed to delete pool")

		deleteReq := &GatewayDeleteIPAMPoolRequest{
			PoolID: "pool-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayDeleteIPAMPool,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
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
		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{Opcode: quicwire.OpGatewayGetIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var getResp GatewayGetIPAMPoolResponse
		err = quicwire.DecodePayload(resp.Payload, &getResp)
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
		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{Opcode: quicwire.OpGatewayGetIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("returns error for missing pool ID", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		getReq := &GatewayGetIPAMPoolRequest{PoolID: ""}
		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{Opcode: quicwire.OpGatewayGetIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		getReq := &GatewayGetIPAMPoolRequest{PoolID: "pool-1"}
		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{Opcode: quicwire.OpGatewayGetIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when get fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.listIPAMPoolsErr = errors.New("backend error")

		getReq := &GatewayGetIPAMPoolRequest{PoolID: "pool-1"}
		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{Opcode: quicwire.OpGatewayGetIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
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
		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{Opcode: quicwire.OpGatewayUpdateIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var updateResp GatewayUpdateIPAMPoolResponse
		err = quicwire.DecodePayload(resp.Payload, &updateResp)
		require.NoError(t, err)

		assert.NotNil(t, updateResp.Pool)
		assert.Equal(t, "pool-1", updateResp.Pool.ID)
	})

	t.Run("returns error for missing pool ID", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		updateReq := &GatewayUpdateIPAMPoolRequest{PoolID: "", Name: "NewName"}
		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{Opcode: quicwire.OpGatewayUpdateIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		updateReq := &GatewayUpdateIPAMPoolRequest{PoolID: "pool-1", Name: "NewName"}
		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{Opcode: quicwire.OpGatewayUpdateIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when update fails", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.listIPAMPoolsErr = errors.New("backend error")

		updateReq := &GatewayUpdateIPAMPoolRequest{PoolID: "pool-1", Name: "NewName"}
		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{Opcode: quicwire.OpGatewayUpdateIPAMPool, Payload: payload}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{Opcode: quicwire.OpGatewayUpdateIPAMPool, Payload: []byte("invalid payload")}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
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

		payload, err := quicwire.EncodePayload(allocReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, "pool-1", service.lastPoolID)
		assert.Equal(t, "test-host", service.lastAllocateOpts.Hostname)

		var allocResp GatewayAllocateIPResponse
		err = quicwire.DecodePayload(resp.Payload, &allocResp)
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

		payload, err := quicwire.EncodePayload(allocReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, "10.0.0.100", service.lastAllocateOpts.IPAddress)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		t.Parallel()
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)

		allocReq := &GatewayAllocateIPRequest{
			PoolID: "pool-1",
		}

		payload, err := quicwire.EncodePayload(allocReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing pool ID", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		allocReq := &GatewayAllocateIPRequest{}

		payload, err := quicwire.EncodePayload(allocReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "pool ID")
	})

	t.Run("returns error for invalid IP address", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		allocReq := &GatewayAllocateIPRequest{
			PoolID:    "pool-1",
			IPAddress: "invalid-ip",
		}

		payload, err := quicwire.EncodePayload(allocReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAllocateIP,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when pool exhausted", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.allocateIPErr = ErrGatewayPoolExhausted

		allocReq := &GatewayAllocateIPRequest{
			PoolID: "pool-1",
		}

		payload, err := quicwire.EncodePayload(allocReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusResourceExhausted, resp.Status)
	})

	t.Run("returns error when pool not found", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.allocateIPErr = ErrGatewayPoolNotFound

		allocReq := &GatewayAllocateIPRequest{
			PoolID: "nonexistent-pool",
		}

		payload, err := quicwire.EncodePayload(allocReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayAllocateIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
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

		payload, err := quicwire.EncodePayload(releaseReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayReleaseIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, "pool-1", service.lastPoolID)
		assert.Equal(t, "10.0.0.50", service.lastReleaseIP)

		var releaseResp GatewayReleaseIPResponse
		err = quicwire.DecodePayload(resp.Payload, &releaseResp)
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

		payload, err := quicwire.EncodePayload(releaseReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayReleaseIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("releases by address alone", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()

		// pool_id is optional, as on gRPC, REST and the CLI, which release
		// by address; it used to be required on QUIC alone (#730).
		releaseReq := &GatewayReleaseIPRequest{
			IPAddress: "10.0.0.50",
		}

		payload, err := quicwire.EncodePayload(releaseReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayReleaseIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Empty(t, service.lastPoolID)
		assert.Equal(t, "10.0.0.50", service.lastReleaseIP)
	})

	t.Run("returns error for missing IP address", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		releaseReq := &GatewayReleaseIPRequest{
			PoolID: "pool-1",
		}

		payload, err := quicwire.EncodePayload(releaseReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayReleaseIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "IP address")
	})

	t.Run("returns error for invalid IP address", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		releaseReq := &GatewayReleaseIPRequest{
			PoolID:    "pool-1",
			IPAddress: "invalid-ip",
		}

		payload, err := quicwire.EncodePayload(releaseReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayReleaseIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayReleaseIP,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when allocation not found", func(t *testing.T) {
		t.Parallel()
		handler, service := createTestGatewayHandler()
		service.releaseIPErr = ErrGatewayAllocationNotFound

		releaseReq := &GatewayReleaseIPRequest{
			PoolID:    "pool-1",
			IPAddress: "10.0.0.99",
		}

		payload, err := quicwire.EncodePayload(releaseReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayReleaseIP,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
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

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListAllocations,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, "pool-1", service.lastPoolID)

		var listResp GatewayListAllocationsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
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

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListAllocations,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("empty pool ID lists all allocations", func(t *testing.T) {
		// Empty PoolID means list all allocations (list-all semantics, same as gRPC ListAllocations).
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayListAllocationsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListAllocations,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		var listResp GatewayListAllocationsResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &listResp))
		assert.NotNil(t, listResp.Allocations)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListAllocations,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		listReq := &GatewayListAllocationsRequest{
			PoolID: "pool-1",
			Limit:  1,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListAllocations,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp GatewayListAllocationsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
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

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpGatewayListAllocations,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
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

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("maps pool not found to NotFound status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayPoolNotFound)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("maps allocation not found to NotFound status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayAllocationNotFound)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("maps BGP peer not found to NotFound status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayBGPPeerNotFound)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("maps prefix already exists to AlreadyExists status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayPrefixAlreadyExists)

		assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
	})

	t.Run("maps pool already exists to AlreadyExists status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayPoolAlreadyExists)

		assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
	})

	t.Run("maps pool exhausted to ResourceExhausted status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayPoolExhausted)

		assert.Equal(t, quicwire.StatusResourceExhausted, resp.Status)
	})

	t.Run("maps invalid mode to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayInvalidMode)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps invalid prefix to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayInvalidPrefix)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps invalid IP address to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayInvalidIPAddress)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps invalid pool CIDR to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayInvalidPoolCIDR)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing mode to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayMissingMode)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing prefix to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayMissingPrefix)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing pool ID to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayMissingPoolID)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing pool name to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayMissingPoolName)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing pool CIDR to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayMissingPoolCIDR)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps missing IP address to InvalidArgument status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayMissingIPAddress)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("maps BGP not enabled to Unavailable status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayBGPNotEnabled)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("maps service not available to Unavailable status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(ErrGatewayServiceNotAvailable)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("maps unknown error to InternalError status", func(t *testing.T) {
		t.Parallel()
		handler, _ := createTestGatewayHandler()

		resp := handler.gatewayErrorResponse(errors.New("unknown error"))

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// TestGatewayHandlerErrorResponse_APreconditionIsNotAFault: a host that
// cannot carry a configured service (a kernel without the NAT64 module) is
// gRPC's FailedPrecondition, which the QUIC delegates bridge to
// StatusInvalidRequest. It answered StatusInternalError before the #661
// review, which reads as a daemon fault to retry or escalate.
func TestGatewayHandlerErrorResponse_APreconditionIsNotAFault(t *testing.T) {
	handler, service := createTestGatewayHandler()
	service.nat64StatusErr = ErrGatewayPreconditionDetail{Reason: "module jool not found"}

	resp := handler.handleNAT64Status(context.Background(), &quicwire.Request{})
	if resp.Status != quicwire.StatusInvalidRequest {
		t.Fatalf("status = %#x, want StatusInvalidRequest", resp.Status)
	}
	if !bytes.Contains(resp.Payload, []byte("module jool not found")) {
		t.Fatalf("payload %q drops the kernel's reason", resp.Payload)
	}
	if !errors.Is(ErrGatewayPreconditionDetail{Reason: "x"}, ErrGatewayPreconditionFailed) {
		t.Fatal("the detail does not match its sentinel")
	}
}

// TestGatewayHandlerErrorResponse_AllocationRefusals pins the statuses of the
// refusals QUIC allocation gained when it was wired to the daemon's IPAM
// allocator (#730): a caller's mistake is InvalidArgument, a taken address
// AlreadyExists -- never the InternalError an unmapped error falls through to.
func TestGatewayHandlerErrorResponse_AllocationRefusals(t *testing.T) {
	t.Parallel()
	handler, _ := createTestGatewayHandler()

	tests := []struct {
		err  error
		want byte
	}{
		{ErrGatewayMissingOwner, quicwire.StatusInvalidArgument},
		{ErrGatewayMACNotRecorded, quicwire.StatusInvalidArgument},
		{ErrGatewayInvalidAllocationType, quicwire.StatusInvalidArgument},
		{ErrGatewayIPAlreadyAllocated, quicwire.StatusAlreadyExists},
	}
	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			assert.Equal(t, tt.want, handler.gatewayErrorResponse(tt.err).Status)
		})
	}
}
