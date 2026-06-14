//go:build integration

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

package sdn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// =============================================================================
// Stub Overlay Controller
// =============================================================================

// stubOverlayController implements daemon.OverlayControllerInterface for testing.
// It returns minimal data sufficient to exercise the gRPC handlers.
type stubOverlayController struct {
	mu        sync.RWMutex
	startTime time.Time
	vnis      map[uint32]*overlay.VNIInfo
}

// IsRunning returns true indicating the controller is operational.
func (s *stubOverlayController) IsRunning() bool {
	return true
}

// GetState returns the current overlay state.
func (s *stubOverlayController) GetState() *overlay.State {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var vnis []overlay.VNIInfo
	for _, vni := range s.vnis {
		vnis = append(vnis, *vni)
	}

	return &overlay.State{
		VTEPs:      []overlay.VTEPInfo{},
		VNIs:       vnis,
		Tunnels:    []overlay.TunnelInfo{},
		RemoteMACs: []overlay.RemoteMACEntry{},
	}
}

// GetConfig returns the overlay configuration with realistic default values.
func (s *stubOverlayController) GetConfig() *overlay.Config {
	return &overlay.Config{
		NodeID:      "test-node-001",
		VTEPIP:      netip.MustParseAddr("10.0.0.1"),
		VXLANPort:   4789, // Standard VXLAN port
		UnderlayMTU: 1500, // Standard MTU
		VNIBase:     10000,
	}
}

// Uptime returns how long the controller has been running.
func (s *stubOverlayController) Uptime() time.Duration {
	if s.startTime.IsZero() {
		s.startTime = time.Now()
	}
	return time.Since(s.startTime)
}

// ListVTEPs returns known VTEPs.
func (s *stubOverlayController) ListVTEPs(ctx context.Context) ([]overlay.VTEPInfo, error) {
	// Return local VTEP for testing
	return []overlay.VTEPInfo{
		{
			NodeID:   "test-node-001",
			IP:       netip.MustParseAddr("10.0.0.1"),
			Healthy:  true,
			LastSeen: time.Now(),
		},
	}, nil
}

// GetVTEP retrieves a specific VTEP.
func (s *stubOverlayController) GetVTEP(ctx context.Context, ip netip.Addr) (*overlay.VTEPInfo, error) {
	if ip == netip.MustParseAddr("10.0.0.1") {
		return &overlay.VTEPInfo{
			NodeID:   "test-node-001",
			IP:       netip.MustParseAddr("10.0.0.1"),
			Healthy:  true,
			LastSeen: time.Now(),
		}, nil
	}
	return nil, overlay.ErrVTEPNotFound
}

// AddVNI creates a new VNI.
func (s *stubOverlayController) AddVNI(ctx context.Context, config *overlay.VNIConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.vnis == nil {
		s.vnis = make(map[uint32]*overlay.VNIInfo)
	}

	if config.VNI == 0 {
		return &overlay.ErrInvalidVNI{VNI: config.VNI}
	}

	s.vnis[config.VNI] = &overlay.VNIInfo{
		VNI:       config.VNI,
		VLAN:      config.VLAN,
		CreatedAt: time.Now(),
	}
	return nil
}

// RemoveVNI removes a VNI.
func (s *stubOverlayController) RemoveVNI(ctx context.Context, vni uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.vnis == nil {
		s.vnis = make(map[uint32]*overlay.VNIInfo)
	}

	if _, exists := s.vnis[vni]; !exists {
		return overlay.ErrVNINotFound
	}

	delete(s.vnis, vni)
	return nil
}

// ListVNIs returns all VNIs.
func (s *stubOverlayController) ListVNIs(ctx context.Context) ([]overlay.VNIInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var vnis []overlay.VNIInfo
	for _, vni := range s.vnis {
		vnis = append(vnis, *vni)
	}
	return vnis, nil
}

// GetVNI retrieves a specific VNI.
func (s *stubOverlayController) GetVNI(ctx context.Context, vni uint32) (*overlay.VNIInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.vnis == nil {
		return nil, overlay.ErrVNINotFound
	}

	info, exists := s.vnis[vni]
	if !exists {
		return nil, overlay.ErrVNINotFound
	}
	return info, nil
}

// GetRemoteMACs returns remote MAC entries for a VNI.
func (s *stubOverlayController) GetRemoteMACs(ctx context.Context, vni uint32) ([]overlay.RemoteMACEntry, error) {
	return []overlay.RemoteMACEntry{}, nil
}

// ForgetMAC removes a learned MAC.
func (s *stubOverlayController) ForgetMAC(ctx context.Context, mac net.HardwareAddr, vni uint32) error {
	return overlay.ErrMACNotFound
}

// =============================================================================
// Stub Gateway
// =============================================================================

// stubGateway implements daemon.GatewayInterface for testing.
type stubGateway struct {
	mu          sync.RWMutex
	startTime   time.Time
	activeModes gateway.GatewayMode
}

// IsRunning returns true indicating the gateway is running.
func (g *stubGateway) IsRunning() bool {
	return true
}

// IsOperational returns true indicating the gateway is operational.
func (g *stubGateway) IsOperational() bool {
	return true
}

// GetStatus returns the gateway status.
func (g *stubGateway) GetStatus() *gateway.GatewayStatus {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return &gateway.GatewayStatus{
		ID:                "test-gateway-001",
		State:             gateway.GatewayStateRunning,
		ActiveModes:       g.activeModes,
		Uptime:            g.Uptime(),
		StartedAt:         g.startTime,
		LastHealthCheck:   time.Now(),
		HealthCheckPassed: true,
	}
}

// GetNode returns the gateway node information.
func (g *stubGateway) GetNode() gateway.GatewayNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return gateway.GatewayNode{
		ID:         "test-gateway-001",
		NodeID:     12345,
		Tier:       bgp.SpeakerTierCoordinator,
		Reputation: 0.95,
		Age:        180 * 24 * time.Hour,
		Uptime:     99.9,
	}
}

// GetConfig returns the gateway configuration.
func (g *stubGateway) GetConfig() *gateway.GatewayConfig {
	return &gateway.GatewayConfig{
		Tier: "coordinator",
	}
}

// GetActiveModes returns currently active modes.
func (g *stubGateway) GetActiveModes() gateway.GatewayMode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.activeModes
}

// Uptime returns how long the gateway has been running.
func (g *stubGateway) Uptime() time.Duration {
	if g.startTime.IsZero() {
		g.startTime = time.Now()
	}
	return time.Since(g.startTime)
}

// ActivateMode activates a gateway mode.
func (g *stubGateway) ActivateMode(ctx context.Context, mode gateway.GatewayMode) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.activeModes |= mode
	return nil
}

// DeactivateMode deactivates a gateway mode.
func (g *stubGateway) DeactivateMode(ctx context.Context, mode gateway.GatewayMode) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.activeModes &^= mode
	return nil
}

// HasMode checks if a mode is active.
func (g *stubGateway) HasMode(mode gateway.GatewayMode) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.activeModes.HasMode(mode)
}

// =============================================================================
// Stub BGP Speaker
// =============================================================================

// stubBGPSpeaker implements daemon.BGPSpeakerInterface for testing.
type stubBGPSpeaker struct {
	mu        sync.RWMutex
	startTime time.Time
	prefixes  []bgp.Path
}

// IsStarted returns true indicating the BGP speaker is running.
func (s *stubBGPSpeaker) IsStarted() bool {
	return true
}

// GetStatus returns the BGP speaker status.
func (s *stubBGPSpeaker) GetStatus(ctx context.Context) (*bgp.SpeakerStatus, error) {
	if s.startTime.IsZero() {
		s.startTime = time.Now()
	}

	return &bgp.SpeakerStatus{
		RouterID:         netip.MustParseAddr("10.0.0.1"),
		ASN:              65001,
		Tier:             bgp.SpeakerTierCoordinator,
		Running:          true,
		StartedAt:        s.startTime,
		PeerCount:        0,
		EstablishedPeers: 0,
		TotalPrefixes:    0,
	}, nil
}

// ListPeers returns configured BGP peers.
func (s *stubBGPSpeaker) ListPeers(ctx context.Context) ([]bgp.PeerInfo, error) {
	return []bgp.PeerInfo{}, nil
}

// AnnouncePrefix announces a prefix.
func (s *stubBGPSpeaker) AnnouncePrefix(ctx context.Context, route *bgp.TransitRoute) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.prefixes = append(s.prefixes, bgp.Path{
		Prefix:  route.Prefix,
		NextHop: route.NextHop,
		Age:     time.Now(),
	})
	return nil
}

// WithdrawPrefix withdraws a prefix.
func (s *stubBGPSpeaker) WithdrawPrefix(ctx context.Context, prefix netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var newPrefixes []bgp.Path
	for _, p := range s.prefixes {
		if p.Prefix != prefix {
			newPrefixes = append(newPrefixes, p)
		}
	}
	s.prefixes = newPrefixes
	return nil
}

// ListPaths returns announced paths.
func (s *stubBGPSpeaker) ListPaths(ctx context.Context, family bgp.AddressFamily, ribType bgp.RIBType) ([]bgp.Path, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.prefixes, nil
}

// =============================================================================
// Stub IPAM Allocator
// =============================================================================

// stubIPAMAllocator implements ipam.Allocator for testing.
type stubIPAMAllocator struct {
	mu          sync.RWMutex
	pools       map[string]*ipam.Pool
	allocations map[string]*ipam.Allocation
}

// CreatePool creates a new IP pool.
func (a *stubIPAMAllocator) CreatePool(ctx context.Context, pool *ipam.Pool) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.pools == nil {
		a.pools = make(map[string]*ipam.Pool)
	}
	a.pools[pool.ID] = pool
	return nil
}

// GetPool retrieves a pool by ID.
func (a *stubIPAMAllocator) GetPool(ctx context.Context, poolID string) (*ipam.Pool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	pool, ok := a.pools[poolID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ipam.ErrPoolNotFound, poolID)
	}
	return pool, nil
}

// GetPoolByName retrieves a pool by name.
func (a *stubIPAMAllocator) GetPoolByName(ctx context.Context, name string) (*ipam.Pool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, pool := range a.pools {
		if pool.Name == name {
			return pool, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ipam.ErrPoolNotFound, name)
}

// GetPoolByCIDR retrieves a pool by CIDR.
func (a *stubIPAMAllocator) GetPoolByCIDR(ctx context.Context, cidr netip.Prefix) (*ipam.Pool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, pool := range a.pools {
		if pool.CIDR == cidr {
			return pool, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ipam.ErrPoolNotFound, cidr.String())
}

// ListPools returns all pools.
func (a *stubIPAMAllocator) ListPools(ctx context.Context) ([]*ipam.Pool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var pools []*ipam.Pool
	for _, pool := range a.pools {
		pools = append(pools, pool)
	}
	return pools, nil
}

// ListPoolsByZone returns pools matching the given zone.
// An empty zone returns all pools.
func (a *stubIPAMAllocator) ListPoolsByZone(ctx context.Context, zone string) ([]*ipam.Pool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var pools []*ipam.Pool
	for _, pool := range a.pools {
		if zone == "" || pool.Zone == zone {
			pools = append(pools, pool)
		}
	}
	return pools, nil
}

// UpdatePool updates a pool.
func (a *stubIPAMAllocator) UpdatePool(ctx context.Context, pool *ipam.Pool) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.pools == nil {
		return fmt.Errorf("%w: %s", ipam.ErrPoolNotFound, pool.ID)
	}
	if _, ok := a.pools[pool.ID]; !ok {
		return fmt.Errorf("%w: %s", ipam.ErrPoolNotFound, pool.ID)
	}
	a.pools[pool.ID] = pool
	return nil
}

// DeletePool removes a pool.
func (a *stubIPAMAllocator) DeletePool(ctx context.Context, poolID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.pools == nil {
		return fmt.Errorf("%w: %s", ipam.ErrPoolNotFound, poolID)
	}
	if _, ok := a.pools[poolID]; !ok {
		return fmt.Errorf("%w: %s", ipam.ErrPoolNotFound, poolID)
	}
	delete(a.pools, poolID)
	return nil
}

// GetPoolStats returns pool statistics.
func (a *stubIPAMAllocator) GetPoolStats(ctx context.Context, poolID string) (*ipam.PoolStats, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	pool, ok := a.pools[poolID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ipam.ErrPoolNotFound, poolID)
	}

	return &ipam.PoolStats{
		PoolID:       pool.ID,
		TotalIPs:     pool.TotalIPs,
		AllocatedIPs: pool.AllocatedIPs,
		AvailableIPs: pool.AvailableIPs,
	}, nil
}

// Allocate allocates an IP from a pool.
func (a *stubIPAMAllocator) Allocate(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.pools == nil {
		return nil, fmt.Errorf("%w: %s", ipam.ErrPoolNotFound, req.PoolID)
	}

	pool, ok := a.pools[req.PoolID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ipam.ErrPoolNotFound, req.PoolID)
	}

	if a.allocations == nil {
		a.allocations = make(map[string]*ipam.Allocation)
	}

	// Allocate next available IP from pool
	ip := pool.CIDR.Addr()
	for i := 0; i < int(pool.TotalIPs); i++ {
		candidateIP := ip
		for j := 0; j < i+1; j++ {
			candidateIP = candidateIP.Next()
		}
		if _, allocated := a.allocations[candidateIP.String()]; !allocated {
			alloc := &ipam.Allocation{
				IP:          candidateIP,
				PoolID:      req.PoolID,
				DeviceID:    req.DeviceID,
				Hostname:    req.Hostname,
				AllocatedAt: time.Now(),
				ExpiresAt:   time.Now().Add(24 * time.Hour),
			}
			a.allocations[candidateIP.String()] = alloc
			pool.AllocatedIPs++
			pool.AvailableIPs--
			return alloc, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ipam.ErrPoolExhausted, req.PoolID)
}

// AllocateSpecific allocates a specific IP.
func (a *stubIPAMAllocator) AllocateSpecific(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	return a.Allocate(ctx, req)
}

// Release releases an IP.
func (a *stubIPAMAllocator) Release(ctx context.Context, ip netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.allocations == nil {
		return fmt.Errorf("%w: %s", ipam.ErrAllocationNotFound, ip.String())
	}

	alloc, ok := a.allocations[ip.String()]
	if !ok {
		return fmt.Errorf("%w: %s", ipam.ErrAllocationNotFound, ip.String())
	}

	delete(a.allocations, ip.String())

	// Update pool stats
	if pool, poolOk := a.pools[alloc.PoolID]; poolOk {
		pool.AllocatedIPs--
		pool.AvailableIPs++
	}

	return nil
}

// ReleaseByDeviceID releases all IPs for a device.
func (a *stubIPAMAllocator) ReleaseByDeviceID(ctx context.Context, deviceID string) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var released int
	for ip, alloc := range a.allocations {
		if alloc.DeviceID == deviceID {
			delete(a.allocations, ip)
			if pool, ok := a.pools[alloc.PoolID]; ok {
				pool.AllocatedIPs--
				pool.AvailableIPs++
			}
			released++
		}
	}
	return released, nil
}

// Renew extends an allocation lease.
func (a *stubIPAMAllocator) Renew(ctx context.Context, ip netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	alloc, ok := a.allocations[ip.String()]
	if !ok {
		return fmt.Errorf("%w: %s", ipam.ErrAllocationNotFound, ip.String())
	}

	alloc.ExpiresAt = time.Now().Add(24 * time.Hour)
	return nil
}

// GetAllocation retrieves an allocation.
func (a *stubIPAMAllocator) GetAllocation(ctx context.Context, ip netip.Addr) (*ipam.Allocation, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	alloc, ok := a.allocations[ip.String()]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ipam.ErrAllocationNotFound, ip.String())
	}
	return alloc, nil
}

// GetAllocationsByDevice retrieves allocations for a device.
func (a *stubIPAMAllocator) GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var allocs []*ipam.Allocation
	for _, alloc := range a.allocations {
		if alloc.DeviceID == deviceID {
			allocs = append(allocs, alloc)
		}
	}
	return allocs, nil
}

// GetAllocationsByPool retrieves allocations for a pool.
func (a *stubIPAMAllocator) GetAllocationsByPool(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if _, ok := a.pools[poolID]; !ok {
		return nil, fmt.Errorf("%w: %s", ipam.ErrPoolNotFound, poolID)
	}

	var allocs []*ipam.Allocation
	for _, alloc := range a.allocations {
		if alloc.PoolID == poolID {
			allocs = append(allocs, alloc)
		}
	}
	return allocs, nil
}

// ExpireInactive expires inactive allocations.
func (a *stubIPAMAllocator) ExpireInactive(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.pools[poolID]; !ok {
		return nil, fmt.Errorf("%w: %s", ipam.ErrPoolNotFound, poolID)
	}

	// For testing, just return empty - no inactive allocations
	return []*ipam.Allocation{}, nil
}

// Ping checks if the allocator is available.
func (a *stubIPAMAllocator) Ping(ctx context.Context) error {
	return nil
}

// Close releases resources.
func (a *stubIPAMAllocator) Close() error {
	return nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure our stubs implement the required interfaces.
var (
	_                = (*stubOverlayController)(nil)
	_                = (*stubGateway)(nil)
	_                = (*stubBGPSpeaker)(nil)
	_ ipam.Allocator = (*stubIPAMAllocator)(nil)
)
