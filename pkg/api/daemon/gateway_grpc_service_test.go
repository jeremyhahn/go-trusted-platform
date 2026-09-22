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

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockGateway implements GatewayInterface for testing.
type mockGateway struct {
	running     bool
	operational bool
	status      *gateway.GatewayStatus
	node        gateway.GatewayNode
	config      *gateway.GatewayConfig

	// activeModes is the legacy mode bitmask in the uint32 form the
	// platform.v1 wire messages carry.
	activeModes uint32

	uptime          time.Duration
	activateModeErr error
	deactivateErr   error
}

func newMockGateway() *mockGateway {
	return &mockGateway{
		running:     true,
		operational: true,
		status: &gateway.GatewayStatus{
			ID:    "gw-1",
			State: gateway.GatewayStateRunning,
			// node.go:317 still populates this bitmask for API compatibility, so
			// the fixture must carry it or this service's mapping goes untested.
			ActiveModes: gateway.GatewayModeOverlay, //nolint:staticcheck // SA1019: covering the compat field production still serves.
			StartedAt:   time.Now().Add(-30 * time.Second),
		},
		node: gateway.GatewayNode{
			ID:         "gw-1",
			NodeID:     12345,
			Reputation: 0.95,
		},
		config: &gateway.GatewayConfig{
			ID:   "gw-1",
			Tier: "datacenter",
		},
		activeModes: uint32(gateway.GatewayModeOverlay),
		uptime:      30 * time.Second,
	}
}

func (m *mockGateway) IsRunning() bool {
	return m.running
}

func (m *mockGateway) IsOperational() bool {
	return m.operational
}

func (m *mockGateway) GetStatus() *gateway.GatewayStatus {
	return m.status
}

func (m *mockGateway) GetNode() gateway.GatewayNode {
	return m.node
}

func (m *mockGateway) GetConfig() *gateway.GatewayConfig {
	return m.config
}

func (m *mockGateway) ActiveModeBitmask() uint32 {
	return m.activeModes
}

func (m *mockGateway) Uptime() time.Duration {
	return m.uptime
}

// SetModeBitmask mirrors Gateway.SetModeBitmask: it activates every mode
// named in modes and deactivates every active mode absent from it.
func (m *mockGateway) SetModeBitmask(ctx context.Context, modes uint32) error {
	// Mirror the wording pkg/sdn/gateway produces so the service is
	// tested against the message a caller actually sees. Naming the
	// gateway package's typed mode errors here would drag its deprecated
	// surface back across the package boundary, which is exactly what
	// SetModeBitmask exists to prevent.
	if added := modes &^ m.activeModes; added != 0 && m.activateModeErr != nil {
		return fmt.Errorf("failed to activate gateway mode %#x: %w", added, m.activateModeErr)
	}
	if removed := m.activeModes &^ modes; removed != 0 && m.deactivateErr != nil {
		return fmt.Errorf("failed to deactivate gateway mode %#x: %w", removed, m.deactivateErr)
	}
	m.activeModes = modes
	m.status.SetLegacyModeBitmask(modes)
	return nil
}

// mockBGPSpeaker implements BGPSpeakerInterface for testing.
type mockBGPSpeaker struct {
	started           bool
	status            *bgp.SpeakerStatus
	peers             []bgp.PeerInfo
	paths             map[bgp.AddressFamily][]bgp.Path
	announcePrefixErr error
	withdrawPrefixErr error
	getStatusErr      error
	listPeersErr      error
	listPathsErr      error
}

func newMockBGPSpeaker() *mockBGPSpeaker {
	return &mockBGPSpeaker{
		started: true,
		status: &bgp.SpeakerStatus{
			RouterID:         netip.MustParseAddr("10.0.0.1"),
			ASN:              65001,
			Running:          true,
			PeerCount:        2,
			EstablishedPeers: 2,
			TotalPrefixes:    10,
		},
		peers: []bgp.PeerInfo{
			{
				Address:     netip.MustParseAddr("10.0.0.2"),
				ASN:         65002,
				State:       bgp.PeerStateEstablished,
				Description: "peer-1",
			},
		},
		paths: make(map[bgp.AddressFamily][]bgp.Path),
	}
}

func (m *mockBGPSpeaker) IsStarted() bool {
	return m.started
}

func (m *mockBGPSpeaker) GetStatus(ctx context.Context) (*bgp.SpeakerStatus, error) {
	if m.getStatusErr != nil {
		return nil, m.getStatusErr
	}
	return m.status, nil
}

func (m *mockBGPSpeaker) ListPeers(ctx context.Context) ([]bgp.PeerInfo, error) {
	if m.listPeersErr != nil {
		return nil, m.listPeersErr
	}
	return m.peers, nil
}

func (m *mockBGPSpeaker) AnnouncePrefix(ctx context.Context, route *bgp.TransitRoute) error {
	return m.announcePrefixErr
}

func (m *mockBGPSpeaker) WithdrawPrefix(ctx context.Context, prefix netip.Prefix) error {
	return m.withdrawPrefixErr
}

func (m *mockBGPSpeaker) ListPaths(ctx context.Context, family bgp.AddressFamily, ribType bgp.RIBType) ([]bgp.Path, error) {
	if m.listPathsErr != nil {
		return nil, m.listPathsErr
	}
	return m.paths[family], nil
}

// mockIPAMAllocator implements ipam.Allocator for testing.
type mockIPAMAllocator struct {
	pools        map[string]*ipam.Pool
	allocations  map[netip.Addr]*ipam.Allocation
	allocateErr  error
	releaseErr   error
	listPoolsErr error
}

func newMockIPAMAllocator() *mockIPAMAllocator {
	return &mockIPAMAllocator{
		pools:       make(map[string]*ipam.Pool),
		allocations: make(map[netip.Addr]*ipam.Allocation),
	}
}

func (m *mockIPAMAllocator) CreatePool(ctx context.Context, pool *ipam.Pool) error {
	m.pools[pool.ID] = pool
	return nil
}

func (m *mockIPAMAllocator) GetPool(ctx context.Context, poolID string) (*ipam.Pool, error) {
	if pool, exists := m.pools[poolID]; exists {
		return pool, nil
	}
	return nil, errors.New("pool not found")
}

func (m *mockIPAMAllocator) GetPoolByName(ctx context.Context, name string) (*ipam.Pool, error) {
	for _, pool := range m.pools {
		if pool.Name == name {
			return pool, nil
		}
	}
	return nil, errors.New("pool not found")
}

func (m *mockIPAMAllocator) GetPoolByCIDR(ctx context.Context, cidr netip.Prefix) (*ipam.Pool, error) {
	for _, pool := range m.pools {
		if pool.CIDR == cidr {
			return pool, nil
		}
	}
	return nil, errors.New("pool not found")
}

func (m *mockIPAMAllocator) ListPools(ctx context.Context) ([]*ipam.Pool, error) {
	if m.listPoolsErr != nil {
		return nil, m.listPoolsErr
	}
	result := make([]*ipam.Pool, 0, len(m.pools))
	for _, pool := range m.pools {
		result = append(result, pool)
	}
	return result, nil
}

func (m *mockIPAMAllocator) ListPoolsByZone(ctx context.Context, zone string) ([]*ipam.Pool, error) {
	if m.listPoolsErr != nil {
		return nil, m.listPoolsErr
	}
	result := make([]*ipam.Pool, 0)
	for _, pool := range m.pools {
		if zone == "" || pool.Zone == zone {
			result = append(result, pool)
		}
	}
	return result, nil
}

func (m *mockIPAMAllocator) UpdatePool(ctx context.Context, pool *ipam.Pool) error {
	if _, exists := m.pools[pool.ID]; !exists {
		return errors.New("pool not found")
	}
	m.pools[pool.ID] = pool
	return nil
}

func (m *mockIPAMAllocator) DeletePool(ctx context.Context, poolID string) error {
	delete(m.pools, poolID)
	return nil
}

func (m *mockIPAMAllocator) GetPoolStats(ctx context.Context, poolID string) (*ipam.PoolStats, error) {
	return &ipam.PoolStats{PoolID: poolID}, nil
}

func (m *mockIPAMAllocator) Allocate(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	if m.allocateErr != nil {
		return nil, m.allocateErr
	}
	ip := netip.MustParseAddr("192.168.1.10")
	alloc := &ipam.Allocation{
		ID:          "alloc-1",
		PoolID:      req.PoolID,
		IP:          ip,
		DeviceID:    req.DeviceID,
		Hostname:    req.Hostname,
		AllocatedAt: time.Now(),
		Status:      ipam.AllocationStatusActive,
	}
	m.allocations[ip] = alloc
	return alloc, nil
}

func (m *mockIPAMAllocator) AllocateSpecific(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	return m.Allocate(ctx, req)
}

func (m *mockIPAMAllocator) Release(ctx context.Context, ip netip.Addr) error {
	if m.releaseErr != nil {
		return m.releaseErr
	}
	delete(m.allocations, ip)
	return nil
}

func (m *mockIPAMAllocator) ReleaseByDeviceID(ctx context.Context, deviceID string) (int, error) {
	return 0, nil
}

func (m *mockIPAMAllocator) Renew(ctx context.Context, ip netip.Addr) error {
	return nil
}

func (m *mockIPAMAllocator) GetAllocation(ctx context.Context, ip netip.Addr) (*ipam.Allocation, error) {
	if alloc, exists := m.allocations[ip]; exists {
		return alloc, nil
	}
	return nil, errors.New("allocation not found")
}

func (m *mockIPAMAllocator) GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error) {
	var result []*ipam.Allocation
	for _, alloc := range m.allocations {
		if alloc.DeviceID == deviceID {
			result = append(result, alloc)
		}
	}
	return result, nil
}

func (m *mockIPAMAllocator) GetAllocationsByPool(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	var result []*ipam.Allocation
	for _, alloc := range m.allocations {
		if alloc.PoolID == poolID {
			result = append(result, alloc)
		}
	}
	return result, nil
}

func (m *mockIPAMAllocator) ExpireInactive(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	return nil, nil
}

func (m *mockIPAMAllocator) Ping(ctx context.Context) error {
	return nil
}

func (m *mockIPAMAllocator) Close() error {
	return nil
}

func TestNewGatewayService(t *testing.T) {
	t.Run("creates service without dependencies", func(t *testing.T) {
		svc := NewGatewayService()
		assert.NotNil(t, svc)
		assert.Nil(t, svc.Gateway())
		assert.Nil(t, svc.BGPSpeaker())
		assert.Nil(t, svc.IPAMAllocator())
	})

	t.Run("creates service with all options", func(t *testing.T) {
		gw := newMockGateway()
		bgpSpeaker := newMockBGPSpeaker()
		allocator := newMockIPAMAllocator()

		svc := NewGatewayService(
			WithGateway(gw),
			WithBGPSpeaker(bgpSpeaker),
			WithIPAMAllocator(allocator),
		)

		assert.NotNil(t, svc)
		assert.Equal(t, gw, svc.Gateway())
		assert.Equal(t, bgpSpeaker, svc.BGPSpeaker())
		assert.Equal(t, allocator, svc.IPAMAllocator())
	})
}

func TestGatewayService_SetDependencies(t *testing.T) {
	svc := NewGatewayService()

	gw := newMockGateway()
	svc.SetGateway(gw)
	assert.Equal(t, gw, svc.Gateway())

	bgpSpeaker := newMockBGPSpeaker()
	svc.SetBGPSpeaker(bgpSpeaker)
	assert.Equal(t, bgpSpeaker, svc.BGPSpeaker())

	allocator := newMockIPAMAllocator()
	svc.SetIPAMAllocator(allocator)
	assert.Equal(t, allocator, svc.IPAMAllocator())
}

func TestGatewayService_GetGatewayStatus(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func() *mockGateway
		expectError   bool
		errorContains string
	}{
		{
			name:        "success",
			setupMock:   newMockGateway,
			expectError: false,
		},
		{
			name: "gateway not configured",
			setupMock: func() *mockGateway {
				return nil
			},
			expectError:   true,
			errorContains: "gateway not configured",
		},
		{
			name: "nil status",
			setupMock: func() *mockGateway {
				mock := newMockGateway()
				mock.status = nil
				return mock
			},
			expectError:   true,
			errorContains: "failed to get gateway status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewGatewayService()
			if mock != nil {
				svc.SetGateway(mock)
			}

			ctx := context.Background()
			resp, err := svc.GetGatewayStatus(ctx, &platformv1.GetGatewayStatusRequest{})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotNil(t, resp.Status)
			}
		})
	}
}

func TestGatewayService_SetGatewayMode(t *testing.T) {
	tests := []struct {
		name          string
		modes         uint32
		setupMock     func() *mockGateway
		expectError   bool
		errorContains string
	}{
		{
			name:        "success activate mode",
			modes:       uint32(gateway.GatewayModeOverlay | gateway.GatewayModeEdge),
			setupMock:   newMockGateway,
			expectError: false,
		},
		{
			name:          "zero modes",
			modes:         0,
			setupMock:     newMockGateway,
			expectError:   true,
			errorContains: "modes is required",
		},
		{
			name:  "gateway not configured",
			modes: uint32(gateway.GatewayModeOverlay),
			setupMock: func() *mockGateway {
				return nil
			},
			expectError:   true,
			errorContains: "gateway not configured",
		},
		{
			name:  "gateway not running",
			modes: uint32(gateway.GatewayModeOverlay),
			setupMock: func() *mockGateway {
				mock := newMockGateway()
				mock.running = false
				return mock
			},
			expectError:   true,
			errorContains: "gateway is not running",
		},
		{
			name:  "activate mode error",
			modes: uint32(gateway.GatewayModeTransit),
			setupMock: func() *mockGateway {
				mock := newMockGateway()
				mock.activeModes = 0 // No active modes
				mock.activateModeErr = errors.New("activation failed")
				return mock
			},
			expectError:   true,
			errorContains: "failed to activate gateway mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewGatewayService()
			if mock != nil {
				svc.SetGateway(mock)
			}

			ctx := context.Background()
			resp, err := svc.SetGatewayMode(ctx, &platformv1.SetGatewayModeRequest{Modes: tt.modes})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Status.Success)
			}
		})
	}
}

func TestGatewayService_GetBGPStatus(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func() *mockBGPSpeaker
		expectError   bool
		errorContains string
	}{
		{
			name:        "success",
			setupMock:   newMockBGPSpeaker,
			expectError: false,
		},
		{
			name: "speaker not configured",
			setupMock: func() *mockBGPSpeaker {
				return nil
			},
			expectError:   true,
			errorContains: "BGP speaker not configured",
		},
		{
			name: "get status error",
			setupMock: func() *mockBGPSpeaker {
				mock := newMockBGPSpeaker()
				mock.getStatusErr = errors.New("internal error")
				return mock
			},
			expectError:   true,
			errorContains: "failed to get BGP status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewGatewayService()
			if mock != nil {
				svc.SetBGPSpeaker(mock)
			}

			ctx := context.Background()
			resp, err := svc.GetBGPStatus(ctx, &platformv1.GetBGPStatusRequest{})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotNil(t, resp.Status)
			}
		})
	}
}

func TestGatewayService_ListBGPPeers(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func() *mockBGPSpeaker
		expectError   bool
		expectedCount int
	}{
		{
			name: "success",
			setupMock: func() *mockBGPSpeaker {
				mock := newMockBGPSpeaker()
				mock.peers = []bgp.PeerInfo{
					{Address: netip.MustParseAddr("10.0.0.2"), ASN: 65002, State: bgp.PeerStateEstablished},
					{Address: netip.MustParseAddr("10.0.0.3"), ASN: 65003, State: bgp.PeerStateActive},
				}
				return mock
			},
			expectError:   false,
			expectedCount: 2,
		},
		{
			name: "speaker not configured",
			setupMock: func() *mockBGPSpeaker {
				return nil
			},
			expectError: true,
		},
		{
			name: "list peers error",
			setupMock: func() *mockBGPSpeaker {
				mock := newMockBGPSpeaker()
				mock.listPeersErr = errors.New("internal error")
				return mock
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewGatewayService()
			if mock != nil {
				svc.SetBGPSpeaker(mock)
			}

			ctx := context.Background()
			resp, err := svc.ListBGPPeers(ctx, &platformv1.ListBGPPeersRequest{})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Len(t, resp.Peers, tt.expectedCount)
			}
		})
	}
}

func TestGatewayService_AnnouncePrefix(t *testing.T) {
	tests := []struct {
		name          string
		prefix        string
		nextHop       string
		setupMock     func() *mockBGPSpeaker
		expectError   bool
		errorContains string
	}{
		{
			name:        "success",
			prefix:      "10.0.0.0/24",
			nextHop:     "192.168.1.1",
			setupMock:   newMockBGPSpeaker,
			expectError: false,
		},
		{
			name:        "success without next_hop",
			prefix:      "10.0.0.0/24",
			nextHop:     "",
			setupMock:   newMockBGPSpeaker,
			expectError: false,
		},
		{
			name:          "empty prefix",
			prefix:        "",
			setupMock:     newMockBGPSpeaker,
			expectError:   true,
			errorContains: "prefix is required",
		},
		{
			name:          "invalid prefix",
			prefix:        "invalid",
			setupMock:     newMockBGPSpeaker,
			expectError:   true,
			errorContains: "invalid prefix",
		},
		{
			name:          "invalid next_hop",
			prefix:        "10.0.0.0/24",
			nextHop:       "invalid",
			setupMock:     newMockBGPSpeaker,
			expectError:   true,
			errorContains: "invalid next_hop",
		},
		{
			name:   "speaker not configured",
			prefix: "10.0.0.0/24",
			setupMock: func() *mockBGPSpeaker {
				return nil
			},
			expectError:   true,
			errorContains: "BGP speaker not configured",
		},
		{
			name:   "speaker not running",
			prefix: "10.0.0.0/24",
			setupMock: func() *mockBGPSpeaker {
				mock := newMockBGPSpeaker()
				mock.started = false
				return mock
			},
			expectError:   true,
			errorContains: "BGP speaker is not running",
		},
		{
			name:   "announce error",
			prefix: "10.0.0.0/24",
			setupMock: func() *mockBGPSpeaker {
				mock := newMockBGPSpeaker()
				mock.announcePrefixErr = errors.New("internal error")
				return mock
			},
			expectError:   true,
			errorContains: "failed to announce prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewGatewayService()
			if mock != nil {
				svc.SetBGPSpeaker(mock)
			}

			ctx := context.Background()
			resp, err := svc.AnnouncePrefix(ctx, &platformv1.AnnouncePrefixRequest{
				Prefix:  tt.prefix,
				NextHop: tt.nextHop,
			})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Status.Success)
			}
		})
	}
}

func TestGatewayService_WithdrawPrefix(t *testing.T) {
	tests := []struct {
		name          string
		prefix        string
		setupMock     func() *mockBGPSpeaker
		expectError   bool
		errorContains string
	}{
		{
			name:        "success",
			prefix:      "10.0.0.0/24",
			setupMock:   newMockBGPSpeaker,
			expectError: false,
		},
		{
			name:          "empty prefix",
			prefix:        "",
			setupMock:     newMockBGPSpeaker,
			expectError:   true,
			errorContains: "prefix is required",
		},
		{
			name:          "invalid prefix",
			prefix:        "invalid",
			setupMock:     newMockBGPSpeaker,
			expectError:   true,
			errorContains: "invalid prefix",
		},
		{
			name:   "speaker not configured",
			prefix: "10.0.0.0/24",
			setupMock: func() *mockBGPSpeaker {
				return nil
			},
			expectError:   true,
			errorContains: "BGP speaker not configured",
		},
		{
			name:   "withdraw error",
			prefix: "10.0.0.0/24",
			setupMock: func() *mockBGPSpeaker {
				mock := newMockBGPSpeaker()
				mock.withdrawPrefixErr = errors.New("internal error")
				return mock
			},
			expectError:   true,
			errorContains: "failed to withdraw prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewGatewayService()
			if mock != nil {
				svc.SetBGPSpeaker(mock)
			}

			ctx := context.Background()
			resp, err := svc.WithdrawPrefix(ctx, &platformv1.WithdrawPrefixRequest{Prefix: tt.prefix})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Status.Success)
			}
		})
	}
}

func TestGatewayService_ListAnnouncedPrefixes(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func() *mockBGPSpeaker
		expectError   bool
		expectedCount int
	}{
		{
			name: "success",
			setupMock: func() *mockBGPSpeaker {
				mock := newMockBGPSpeaker()
				mock.paths[bgp.AFamilyIPv4Unicast] = []bgp.Path{
					{Prefix: netip.MustParsePrefix("10.0.0.0/24"), NextHop: netip.MustParseAddr("192.168.1.1")},
				}
				mock.paths[bgp.AFamilyIPv6Unicast] = []bgp.Path{
					{Prefix: netip.MustParsePrefix("2001:db8::/32"), NextHop: netip.MustParseAddr("::1")},
				}
				return mock
			},
			expectError:   false,
			expectedCount: 2,
		},
		{
			name: "speaker not configured",
			setupMock: func() *mockBGPSpeaker {
				return nil
			},
			expectError: true,
		},
		{
			name: "list paths error",
			setupMock: func() *mockBGPSpeaker {
				mock := newMockBGPSpeaker()
				mock.listPathsErr = errors.New("internal error")
				return mock
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewGatewayService()
			if mock != nil {
				svc.SetBGPSpeaker(mock)
			}

			ctx := context.Background()
			resp, err := svc.ListAnnouncedPrefixes(ctx, &platformv1.ListAnnouncedPrefixesRequest{})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Len(t, resp.Prefixes, tt.expectedCount)
			}
		})
	}
}

func TestGatewayService_ListIPAMPools(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func() *mockIPAMAllocator
		expectError   bool
		expectedCount int
	}{
		{
			name: "success",
			setupMock: func() *mockIPAMAllocator {
				mock := newMockIPAMAllocator()
				mock.pools["pool-1"] = &ipam.Pool{
					ID:           "pool-1",
					Name:         "default",
					CIDR:         netip.MustParsePrefix("192.168.1.0/24"),
					TotalIPs:     254,
					AllocatedIPs: 10,
					AvailableIPs: 244,
				}
				return mock
			},
			expectError:   false,
			expectedCount: 1,
		},
		{
			name: "IPAM not configured",
			setupMock: func() *mockIPAMAllocator {
				return nil
			},
			expectError: true,
		},
		{
			name: "list pools error",
			setupMock: func() *mockIPAMAllocator {
				mock := newMockIPAMAllocator()
				mock.listPoolsErr = errors.New("internal error")
				return mock
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewGatewayService()
			if mock != nil {
				svc.SetIPAMAllocator(mock)
			}

			ctx := context.Background()
			resp, err := svc.ListIPAMPools(ctx, &platformv1.ListIPAMPoolsRequest{})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Len(t, resp.Pools, tt.expectedCount)
			}
		})
	}
}

func TestGatewayService_AllocateIP(t *testing.T) {
	tests := []struct {
		name          string
		poolID        string
		deviceID      string
		setupMock     func() *mockIPAMAllocator
		expectError   bool
		errorContains string
	}{
		{
			name:        "success",
			poolID:      "pool-1",
			deviceID:    "device-1",
			setupMock:   newMockIPAMAllocator,
			expectError: false,
		},
		{
			name:          "empty pool_id",
			poolID:        "",
			deviceID:      "device-1",
			setupMock:     newMockIPAMAllocator,
			expectError:   true,
			errorContains: "pool_id is required",
		},
		{
			name:          "empty device_id",
			poolID:        "pool-1",
			deviceID:      "",
			setupMock:     newMockIPAMAllocator,
			expectError:   true,
			errorContains: "device_id is required",
		},
		{
			name:     "IPAM not configured",
			poolID:   "pool-1",
			deviceID: "device-1",
			setupMock: func() *mockIPAMAllocator {
				return nil
			},
			expectError:   true,
			errorContains: "IPAM not configured",
		},
		{
			name:     "allocate error",
			poolID:   "pool-1",
			deviceID: "device-1",
			setupMock: func() *mockIPAMAllocator {
				mock := newMockIPAMAllocator()
				mock.allocateErr = errors.New("pool exhausted")
				return mock
			},
			expectError:   true,
			errorContains: "IPAM operation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewGatewayService()
			if mock != nil {
				svc.SetIPAMAllocator(mock)
			}

			ctx := context.Background()
			resp, err := svc.AllocateIP(ctx, &platformv1.AllocateIPRequest{
				PoolId:   tt.poolID,
				DeviceId: tt.deviceID,
			})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Status.Success)
				assert.NotNil(t, resp.Allocation)
			}
		})
	}
}

func TestGatewayService_ReleaseIP(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		setupMock     func() *mockIPAMAllocator
		expectError   bool
		errorContains string
	}{
		{
			name:        "success",
			ip:          "192.168.1.10",
			setupMock:   newMockIPAMAllocator,
			expectError: false,
		},
		{
			name:          "empty ip",
			ip:            "",
			setupMock:     newMockIPAMAllocator,
			expectError:   true,
			errorContains: "ip is required",
		},
		{
			name:          "invalid ip",
			ip:            "invalid",
			setupMock:     newMockIPAMAllocator,
			expectError:   true,
			errorContains: "invalid IP address",
		},
		{
			name: "IPAM not configured",
			ip:   "192.168.1.10",
			setupMock: func() *mockIPAMAllocator {
				return nil
			},
			expectError:   true,
			errorContains: "IPAM not configured",
		},
		{
			name: "release error",
			ip:   "192.168.1.10",
			setupMock: func() *mockIPAMAllocator {
				mock := newMockIPAMAllocator()
				mock.releaseErr = errors.New("not found")
				return mock
			},
			expectError:   true,
			errorContains: "IPAM operation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewGatewayService()
			if mock != nil {
				svc.SetIPAMAllocator(mock)
			}

			ctx := context.Background()
			resp, err := svc.ReleaseIP(ctx, &platformv1.ReleaseIPRequest{Ip: tt.ip})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Status.Success)
			}
		})
	}
}

func TestGatewayService_ListAllocations(t *testing.T) {
	tests := []struct {
		name          string
		poolID        string
		setupMock     func() *mockIPAMAllocator
		expectError   bool
		expectedCount int
	}{
		{
			name:   "success all allocations",
			poolID: "",
			setupMock: func() *mockIPAMAllocator {
				mock := newMockIPAMAllocator()
				mock.pools["pool-1"] = &ipam.Pool{ID: "pool-1"}
				mock.allocations[netip.MustParseAddr("192.168.1.10")] = &ipam.Allocation{
					ID:       "alloc-1",
					PoolID:   "pool-1",
					IP:       netip.MustParseAddr("192.168.1.10"),
					DeviceID: "device-1",
				}
				return mock
			},
			expectError:   false,
			expectedCount: 1,
		},
		{
			name:   "success filtered by pool",
			poolID: "pool-1",
			setupMock: func() *mockIPAMAllocator {
				mock := newMockIPAMAllocator()
				mock.allocations[netip.MustParseAddr("192.168.1.10")] = &ipam.Allocation{
					ID:       "alloc-1",
					PoolID:   "pool-1",
					IP:       netip.MustParseAddr("192.168.1.10"),
					DeviceID: "device-1",
				}
				return mock
			},
			expectError:   false,
			expectedCount: 1,
		},
		{
			name:   "IPAM not configured",
			poolID: "",
			setupMock: func() *mockIPAMAllocator {
				return nil
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewGatewayService()
			if mock != nil {
				svc.SetIPAMAllocator(mock)
			}

			ctx := context.Background()
			resp, err := svc.ListAllocations(ctx, &platformv1.ListAllocationsRequest{PoolId: tt.poolID})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Len(t, resp.Allocations, tt.expectedCount)
			}
		})
	}
}

func TestPeerInfoToProto(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := peerInfoToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("valid input", func(t *testing.T) {
		info := &bgp.PeerInfo{
			Address:          netip.MustParseAddr("10.0.0.2"),
			ASN:              65002,
			State:            bgp.PeerStateEstablished,
			Description:      "test-peer",
			PrefixesReceived: 100,
			PrefixesSent:     50,
			Uptime:           30 * time.Second,
		}
		result := peerInfoToProto(info)
		require.NotNil(t, result)
		assert.Equal(t, "10.0.0.2", result.Address)
		assert.Equal(t, uint32(65002), result.Asn)
		assert.Equal(t, "Established", result.State)
		assert.Equal(t, "test-peer", result.Description)
		assert.Equal(t, uint32(100), result.PrefixesReceived)
		assert.Equal(t, uint32(50), result.PrefixesSent)
	})
}

func TestPathToAnnouncedPrefix(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := pathToAnnouncedPrefix(nil)
		assert.Nil(t, result)
	})

	t.Run("valid input", func(t *testing.T) {
		now := time.Now()
		path := &bgp.Path{
			Prefix:  netip.MustParsePrefix("10.0.0.0/24"),
			NextHop: netip.MustParseAddr("192.168.1.1"),
			Age:     now,
		}
		result := pathToAnnouncedPrefix(path)
		require.NotNil(t, result)
		assert.Equal(t, "10.0.0.0/24", result.Prefix)
		assert.Equal(t, "192.168.1.1", result.NextHop)
	})
}

func TestIpamPoolToProto(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := ipamPoolToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("valid input", func(t *testing.T) {
		pool := &ipam.Pool{
			ID:           "pool-1",
			CIDR:         netip.MustParsePrefix("192.168.1.0/24"),
			Gateway:      netip.MustParseAddr("192.168.1.1"),
			TotalIPs:     254,
			AllocatedIPs: 10,
			AvailableIPs: 244,
		}
		result := ipamPoolToProto(pool)
		require.NotNil(t, result)
		assert.Equal(t, "pool-1", result.Id)
		assert.Equal(t, "192.168.1.0/24", result.Cidr)
		assert.Equal(t, "192.168.1.1", result.Gateway)
		assert.Equal(t, uint64(254), result.Total)
		assert.Equal(t, uint64(10), result.Allocated)
		assert.Equal(t, uint64(244), result.Available)
	})
}

func TestIpamAllocationToProto(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := ipamAllocationToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("valid input without expiry", func(t *testing.T) {
		now := time.Now()
		alloc := &ipam.Allocation{
			IP:          netip.MustParseAddr("192.168.1.10"),
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			Hostname:    "host-1",
			AllocatedAt: now,
		}
		result := ipamAllocationToProto(alloc)
		require.NotNil(t, result)
		assert.Equal(t, "192.168.1.10", result.Ip)
		assert.Equal(t, "pool-1", result.PoolId)
		assert.Equal(t, "device-1", result.DeviceId)
		assert.Equal(t, "host-1", result.Hostname)
		assert.Nil(t, result.ExpiresAt)
	})

	t.Run("valid input with expiry", func(t *testing.T) {
		now := time.Now()
		expires := now.Add(24 * time.Hour)
		alloc := &ipam.Allocation{
			IP:          netip.MustParseAddr("192.168.1.10"),
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			AllocatedAt: now,
			ExpiresAt:   expires,
		}
		result := ipamAllocationToProto(alloc)
		require.NotNil(t, result)
		assert.NotNil(t, result.ExpiresAt)
	})
}

func TestFormatUint64(t *testing.T) {
	tests := []struct {
		input    uint64
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{12345, "12345"},
		{18446744073709551615, "18446744073709551615"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatUint64(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestGatewayService_NotConfiguredCarriesDiscriminator pins the
// asymmetry the WebUI depends on: an ABSENT gateway service (a control
// plane, where gatewayd runs on the edge role) is a topology fact the
// console renders as an informational state, while a gateway that is
// present but STOPPED is an operator-actionable failure that must keep
// surfacing as an error. Both answer codes.Unavailable, so only the
// ErrorInfo detail separates them.
func TestGatewayService_NotConfiguredCarriesDiscriminator(t *testing.T) {
	ctx := context.Background()

	t.Run("absent gateway", func(t *testing.T) {
		svc := NewGatewayService()

		_, err := svc.GetGatewayStatus(ctx, &platformv1.GetGatewayStatusRequest{})

		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
		assert.Equal(t, "gateway", notConfiguredServiceName(t, st))
	})

	t.Run("absent BGP speaker", func(t *testing.T) {
		svc := NewGatewayService()

		_, err := svc.GetBGPStatus(ctx, &platformv1.GetBGPStatusRequest{})

		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
		assert.Equal(t, "gateway", notConfiguredServiceName(t, st))
	})

	t.Run("stopped gateway is not not-configured", func(t *testing.T) {
		mock := newMockGateway()
		mock.running = false
		svc := NewGatewayService()
		svc.SetGateway(mock)

		_, err := svc.SetGatewayMode(ctx, &platformv1.SetGatewayModeRequest{
			Modes: uint32(gateway.GatewayModeOverlay),
		})

		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
		assert.Contains(t, st.Message(), "not running")
		assert.Empty(t, st.Details(),
			"a stopped gateway must not carry the not-configured discriminator")
	})
}
