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
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GatewayInterface abstracts gateway operations for testing.
type GatewayInterface interface {
	// Lifecycle and state
	IsRunning() bool
	IsOperational() bool
	GetStatus() *gateway.GatewayStatus
	GetNode() gateway.GatewayNode
	GetConfig() *gateway.GatewayConfig
	Uptime() time.Duration

	// Legacy mode bitmask, spoken in the uint32 form platform.v1 carries
	// on the wire. The mode/service translation stays inside pkg/sdn/gateway;
	// this layer never names GatewayMode.
	ActiveModeBitmask() uint32
	SetModeBitmask(ctx context.Context, modes uint32) error
}

// BGPSpeakerInterface abstracts BGP speaker operations for testing.
type BGPSpeakerInterface interface {
	// Status and info
	IsStarted() bool
	GetStatus(ctx context.Context) (*bgp.SpeakerStatus, error)
	ListPeers(ctx context.Context) ([]bgp.PeerInfo, error)

	// Route operations
	AnnouncePrefix(ctx context.Context, route *bgp.TransitRoute) error
	WithdrawPrefix(ctx context.Context, prefix netip.Prefix) error
	ListPaths(ctx context.Context, family bgp.AddressFamily, ribType bgp.RIBType) ([]bgp.Path, error)
}

// Ensure gateway.Gateway implements GatewayInterface.
var _ GatewayInterface = (*gateway.Gateway)(nil)

// GatewayService implements the GatewayService gRPC API for gateway operations.
type GatewayService struct {
	platformv1.UnimplementedGatewayServiceServer

	gateway    GatewayInterface
	bgpSpeaker BGPSpeakerInterface
	ipam       ipam.Allocator
	lb         GatewayLoadBalancerInterface
	perf       GatewayPerfInterface
	startedAt  time.Time
	mu         sync.RWMutex
}

// GatewayServiceOption is a functional option for configuring the GatewayService.
type GatewayServiceOption func(*GatewayService)

// WithGateway sets the gateway for the service.
func WithGateway(gw GatewayInterface) GatewayServiceOption {
	return func(s *GatewayService) {
		s.gateway = gw
	}
}

// WithBGPSpeaker sets the BGP speaker for the service.
func WithBGPSpeaker(speaker BGPSpeakerInterface) GatewayServiceOption {
	return func(s *GatewayService) {
		s.bgpSpeaker = speaker
	}
}

// WithIPAMAllocator sets the IPAM allocator for the service.
func WithIPAMAllocator(allocator ipam.Allocator) GatewayServiceOption {
	return func(s *GatewayService) {
		s.ipam = allocator
	}
}

// NewGatewayService creates a new gateway gRPC service with the given options.
func NewGatewayService(opts ...GatewayServiceOption) *GatewayService {
	svc := &GatewayService{
		startedAt: time.Now(),
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// Gateway returns the underlying gateway for testing purposes.
func (s *GatewayService) Gateway() GatewayInterface {
	return s.gateway
}

// SetGateway sets the gateway (useful for testing).
func (s *GatewayService) SetGateway(gw GatewayInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gateway = gw
}

// BGPSpeaker returns the underlying BGP speaker for testing purposes.
func (s *GatewayService) BGPSpeaker() BGPSpeakerInterface {
	return s.bgpSpeaker
}

// SetBGPSpeaker sets the BGP speaker (useful for testing).
func (s *GatewayService) SetBGPSpeaker(speaker BGPSpeakerInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bgpSpeaker = speaker
}

// IPAMAllocator returns the IPAM allocator for testing purposes.
func (s *GatewayService) IPAMAllocator() ipam.Allocator {
	return s.ipam
}

// SetIPAMAllocator sets the IPAM allocator (useful for testing).
func (s *GatewayService) SetIPAMAllocator(allocator ipam.Allocator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipam = allocator
}

// requireIPAM returns an error when the IPAM allocator is not configured.
func (s *GatewayService) requireIPAM() error {
	if s.ipam == nil {
		return status.Error(codes.Unavailable, "IPAM not configured")
	}
	return nil
}

// GetGatewayStatus returns the current status of the gateway.
func (s *GatewayService) GetGatewayStatus(ctx context.Context, req *platformv1.GetGatewayStatusRequest) (*platformv1.GetGatewayStatusResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.gateway == nil {
		return nil, status.Error(codes.Unavailable, "gateway not configured")
	}

	gwStatus := s.gateway.GetStatus()
	if gwStatus == nil {
		return nil, status.Error(codes.Internal, "failed to get gateway status")
	}

	config := s.gateway.GetConfig()
	node := s.gateway.GetNode()

	var tier string
	if config != nil {
		tier = config.Tier
	}

	return &platformv1.GetGatewayStatusResponse{
		Status: &platformv1.GatewayStatus{
			Id:            gwStatus.ID,
			NodeId:        formatUint64(node.NodeID),
			Modes:         gwStatus.LegacyModeBitmask(),
			Tier:          tier,
			Reputation:    node.Reputation,
			UptimeSeconds: uint64(s.gateway.Uptime().Seconds()),
			Healthy:       gwStatus.State.IsHealthy(),
			StartedAt:     timestamppb.New(gwStatus.StartedAt),
		},
	}, nil
}

// SetGatewayMode activates or deactivates gateway modes.
//
// Deprecated: This RPC is the mode-based compatibility surface. New callers
// configure services through GatewayConfig; the RPC stays until platform.v1
// exposes a service-name equivalent.
func (s *GatewayService) SetGatewayMode(ctx context.Context, req *platformv1.SetGatewayModeRequest) (*platformv1.SetGatewayModeResponse, error) {
	if req.GetModes() == 0 {
		return nil, status.Error(codes.InvalidArgument, "modes is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.gateway == nil {
		return nil, status.Error(codes.Unavailable, "gateway not configured")
	}

	if !s.gateway.IsRunning() {
		return nil, status.Error(codes.Unavailable, "gateway is not running")
	}

	if err := s.gateway.SetModeBitmask(ctx, req.GetModes()); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update gateway modes: %v", err)
	}

	gwStatus := s.gateway.GetStatus()
	node := s.gateway.GetNode()
	config := s.gateway.GetConfig()

	var tier string
	if config != nil {
		tier = config.Tier
	}

	return &platformv1.SetGatewayModeResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "gateway modes updated successfully",
		},
		GatewayStatus: &platformv1.GatewayStatus{
			Id:            gwStatus.ID,
			NodeId:        formatUint64(node.NodeID),
			Modes:         gwStatus.LegacyModeBitmask(),
			Tier:          tier,
			Reputation:    node.Reputation,
			UptimeSeconds: uint64(s.gateway.Uptime().Seconds()),
			Healthy:       gwStatus.State.IsHealthy(),
			StartedAt:     timestamppb.New(gwStatus.StartedAt),
		},
	}, nil
}

// GetBGPStatus returns the current status of the BGP speaker.
func (s *GatewayService) GetBGPStatus(ctx context.Context, req *platformv1.GetBGPStatusRequest) (*platformv1.GetBGPStatusResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bgpSpeaker == nil {
		return nil, status.Error(codes.Unavailable, "BGP speaker not configured")
	}

	bgpStatus, err := s.bgpSpeaker.GetStatus(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get BGP status: %v", err)
	}

	return &platformv1.GetBGPStatusResponse{
		Status: &platformv1.BGPStatus{
			LocalAsn:          bgpStatus.ASN,
			RouterId:          bgpStatus.RouterID.String(),
			PeerCount:         uint32(bgpStatus.PeerCount),
			EstablishedPeers:  uint32(bgpStatus.EstablishedPeers),
			PrefixesAnnounced: bgpStatus.TotalPrefixes,
			Running:           bgpStatus.Running,
		},
	}, nil
}

// ListBGPPeers returns all configured BGP peers.
func (s *GatewayService) ListBGPPeers(ctx context.Context, req *platformv1.ListBGPPeersRequest) (*platformv1.ListBGPPeersResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bgpSpeaker == nil {
		return nil, status.Error(codes.Unavailable, "BGP speaker not configured")
	}

	peers, err := s.bgpSpeaker.ListPeers(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list BGP peers: %v", err)
	}

	result := make([]*platformv1.BGPPeer, 0, len(peers))
	for i := range peers {
		result = append(result, peerInfoToProto(&peers[i]))
	}

	return &platformv1.ListBGPPeersResponse{Peers: result}, nil
}

// AnnouncePrefix announces a prefix via BGP.
func (s *GatewayService) AnnouncePrefix(ctx context.Context, req *platformv1.AnnouncePrefixRequest) (*platformv1.AnnouncePrefixResponse, error) {
	if req.GetPrefix() == "" {
		return nil, status.Error(codes.InvalidArgument, "prefix is required")
	}

	prefix, err := netip.ParsePrefix(req.GetPrefix())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid prefix: %v", err)
	}

	var nextHop netip.Addr
	if req.GetNextHop() != "" {
		nextHop, err = netip.ParseAddr(req.GetNextHop())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid next_hop: %v", err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.bgpSpeaker == nil {
		return nil, status.Error(codes.Unavailable, "BGP speaker not configured")
	}

	if !s.bgpSpeaker.IsStarted() {
		return nil, status.Error(codes.Unavailable, "BGP speaker is not running")
	}

	route := &bgp.TransitRoute{
		Prefix:  prefix,
		NextHop: nextHop,
		Origin:  bgp.OriginIGP,
	}

	if err := s.bgpSpeaker.AnnouncePrefix(ctx, route); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to announce prefix: %v", err)
	}

	return &platformv1.AnnouncePrefixResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "prefix announced successfully",
		},
	}, nil
}

// WithdrawPrefix withdraws a previously announced prefix.
func (s *GatewayService) WithdrawPrefix(ctx context.Context, req *platformv1.WithdrawPrefixRequest) (*platformv1.WithdrawPrefixResponse, error) {
	if req.GetPrefix() == "" {
		return nil, status.Error(codes.InvalidArgument, "prefix is required")
	}

	prefix, err := netip.ParsePrefix(req.GetPrefix())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid prefix: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.bgpSpeaker == nil {
		return nil, status.Error(codes.Unavailable, "BGP speaker not configured")
	}

	if !s.bgpSpeaker.IsStarted() {
		return nil, status.Error(codes.Unavailable, "BGP speaker is not running")
	}

	if err := s.bgpSpeaker.WithdrawPrefix(ctx, prefix); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to withdraw prefix: %v", err)
	}

	return &platformv1.WithdrawPrefixResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "prefix withdrawn successfully",
		},
	}, nil
}

// ListAnnouncedPrefixes returns all prefixes being announced via BGP.
func (s *GatewayService) ListAnnouncedPrefixes(ctx context.Context, req *platformv1.ListAnnouncedPrefixesRequest) (*platformv1.ListAnnouncedPrefixesResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bgpSpeaker == nil {
		return nil, status.Error(codes.Unavailable, "BGP speaker not configured")
	}

	// List IPv4 paths from Adj-RIB-Out
	ipv4Paths, err := s.bgpSpeaker.ListPaths(ctx, bgp.AFamilyIPv4Unicast, bgp.RIBAdjOut)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list IPv4 paths: %v", err)
	}

	// List IPv6 paths from Adj-RIB-Out
	ipv6Paths, err := s.bgpSpeaker.ListPaths(ctx, bgp.AFamilyIPv6Unicast, bgp.RIBAdjOut)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list IPv6 paths: %v", err)
	}

	result := make([]*platformv1.AnnouncedPrefix, 0, len(ipv4Paths)+len(ipv6Paths))

	for i := range ipv4Paths {
		result = append(result, pathToAnnouncedPrefix(&ipv4Paths[i]))
	}
	for i := range ipv6Paths {
		result = append(result, pathToAnnouncedPrefix(&ipv6Paths[i]))
	}

	return &platformv1.ListAnnouncedPrefixesResponse{Prefixes: result}, nil
}

// =============================================================================
// IPAM Pool CRUD
// =============================================================================

// CreateIPAMPool creates a new IPAM address pool.
func (s *GatewayService) CreateIPAMPool(ctx context.Context, req *platformv1.CreateIPAMPoolRequest) (*platformv1.CreateIPAMPoolResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.GetCidr() == "" {
		return nil, status.Error(codes.InvalidArgument, "cidr is required")
	}

	cidr, err := netip.ParsePrefix(req.GetCidr())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid cidr: %v", err)
	}
	cidr = cidr.Masked()

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireIPAM(); err != nil {
		return nil, err
	}

	id := req.GetId()
	if id == "" {
		id = uuid.New().String()
	}

	pool := &ipam.Pool{
		ID:          id,
		Name:        req.GetName(),
		CIDR:        cidr,
		Zone:        req.GetZone(),
		Description: req.GetDescription(),
	}

	if req.GetGateway() != "" {
		gw, parseErr := netip.ParseAddr(req.GetGateway())
		if parseErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid gateway: %v", parseErr)
		}
		pool.Gateway = gw
	}

	if req.GetDefaultLeaseDurationNanos() > 0 {
		pool.DefaultLeaseDuration = time.Duration(req.GetDefaultLeaseDurationNanos())
	}
	if req.GetInactivityTimeoutNanos() > 0 {
		pool.InactivityTimeout = time.Duration(req.GetInactivityTimeoutNanos())
	}

	if err := s.ipam.CreatePool(ctx, pool); err != nil {
		return nil, ipamErrToGRPC(err)
	}

	// Fetch the freshly stored pool to get server-populated fields.
	created, err := s.ipam.GetPool(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "pool created but could not be retrieved: %v", err)
	}

	return &platformv1.CreateIPAMPoolResponse{
		Status: &platformv1.Status{Success: true, Message: "pool created successfully"},
		Pool:   ipamPoolToProto(created),
	}, nil
}

// GetIPAMPool retrieves a pool by ID.
func (s *GatewayService) GetIPAMPool(ctx context.Context, req *platformv1.GetIPAMPoolRequest) (*platformv1.GetIPAMPoolResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.requireIPAM(); err != nil {
		return nil, err
	}

	pool, err := s.ipam.GetPool(ctx, req.GetId())
	if err != nil {
		return nil, ipamErrToGRPC(err)
	}

	return &platformv1.GetIPAMPoolResponse{Pool: ipamPoolToProto(pool)}, nil
}

// UpdateIPAMPool updates mutable fields on an existing pool.
// The CIDR is immutable; attempting to change it returns INVALID_ARGUMENT.
func (s *GatewayService) UpdateIPAMPool(ctx context.Context, req *platformv1.UpdateIPAMPoolRequest) (*platformv1.UpdateIPAMPoolResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireIPAM(); err != nil {
		return nil, err
	}

	existing, err := s.ipam.GetPool(ctx, req.GetId())
	if err != nil {
		return nil, ipamErrToGRPC(err)
	}

	// Apply mutable fields; preserve CIDR and counter fields.
	updated := existing.Clone()
	if req.GetName() != "" {
		updated.Name = req.GetName()
	}
	if req.GetGateway() != "" {
		gw, parseErr := netip.ParseAddr(req.GetGateway())
		if parseErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid gateway: %v", parseErr)
		}
		updated.Gateway = gw
	}
	updated.Zone = req.GetZone()
	updated.Description = req.GetDescription()
	if req.GetDefaultLeaseDurationNanos() >= 0 {
		updated.DefaultLeaseDuration = time.Duration(req.GetDefaultLeaseDurationNanos())
	}
	if req.GetInactivityTimeoutNanos() >= 0 {
		updated.InactivityTimeout = time.Duration(req.GetInactivityTimeoutNanos())
	}

	if err := s.ipam.UpdatePool(ctx, updated); err != nil {
		return nil, ipamErrToGRPC(err)
	}

	refreshed, err := s.ipam.GetPool(ctx, req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "pool updated but could not be retrieved: %v", err)
	}

	return &platformv1.UpdateIPAMPoolResponse{
		Status: &platformv1.Status{Success: true, Message: "pool updated successfully"},
		Pool:   ipamPoolToProto(refreshed),
	}, nil
}

// DeleteIPAMPool deletes a pool by ID.
// Returns NOT_FOUND when the pool does not exist.
// Returns FAILED_PRECONDITION when active allocations exist.
func (s *GatewayService) DeleteIPAMPool(ctx context.Context, req *platformv1.DeleteIPAMPoolRequest) (*platformv1.DeleteIPAMPoolResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireIPAM(); err != nil {
		return nil, err
	}

	if err := s.ipam.DeletePool(ctx, req.GetId()); err != nil {
		return nil, ipamErrToGRPC(err)
	}

	return &platformv1.DeleteIPAMPoolResponse{
		Status: &platformv1.Status{Success: true, Message: "pool deleted successfully"},
	}, nil
}

// ListIPAMPools returns all IPAM address pools, optionally filtered by zone.
func (s *GatewayService) ListIPAMPools(ctx context.Context, req *platformv1.ListIPAMPoolsRequest) (*platformv1.ListIPAMPoolsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.requireIPAM(); err != nil {
		return nil, err
	}

	pools, err := s.ipam.ListPoolsByZone(ctx, req.GetZone())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list IPAM pools: %v", err)
	}

	result := make([]*platformv1.IPAMPool, 0, len(pools))
	for _, pool := range pools {
		result = append(result, ipamPoolToProto(pool))
	}

	return &platformv1.ListIPAMPoolsResponse{Pools: result}, nil
}

// =============================================================================
// IPAM Allocation Operations
// =============================================================================

// AllocateIP allocates an IP address from a pool.
func (s *GatewayService) AllocateIP(ctx context.Context, req *platformv1.AllocateIPRequest) (*platformv1.AllocateIPResponse, error) {
	if req.GetPoolId() == "" {
		return nil, status.Error(codes.InvalidArgument, "pool_id is required")
	}

	if req.GetDeviceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireIPAM(); err != nil {
		return nil, err
	}

	allocReq := &ipam.AllocationRequest{
		PoolID:   req.GetPoolId(),
		DeviceID: req.GetDeviceId(),
		Hostname: req.GetHostname(),
	}

	allocation, err := s.ipam.Allocate(ctx, allocReq)
	if err != nil {
		return nil, ipamErrToGRPC(err)
	}

	return &platformv1.AllocateIPResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "IP allocated successfully",
		},
		Allocation: ipamAllocationToProto(allocation),
	}, nil
}

// ReleaseIP releases an allocated IP address back to the pool.
func (s *GatewayService) ReleaseIP(ctx context.Context, req *platformv1.ReleaseIPRequest) (*platformv1.ReleaseIPResponse, error) {
	if req.GetIp() == "" {
		return nil, status.Error(codes.InvalidArgument, "ip is required")
	}

	ip, err := netip.ParseAddr(req.GetIp())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid IP address: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireIPAM(); err != nil {
		return nil, err
	}

	if err := s.ipam.Release(ctx, ip); err != nil {
		return nil, ipamErrToGRPC(err)
	}

	return &platformv1.ReleaseIPResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "IP released successfully",
		},
	}, nil
}

// ListAllocations returns all IP allocations, optionally filtered by pool.
func (s *GatewayService) ListAllocations(ctx context.Context, req *platformv1.ListAllocationsRequest) (*platformv1.ListAllocationsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.requireIPAM(); err != nil {
		return nil, err
	}

	var allocations []*ipam.Allocation
	var listErr error

	if req.GetPoolId() != "" {
		allocations, listErr = s.ipam.GetAllocationsByPool(ctx, req.GetPoolId())
	} else {
		// List all allocations by iterating all pools.
		pools, poolErr := s.ipam.ListPools(ctx)
		if poolErr != nil {
			return nil, status.Errorf(codes.Internal, "failed to list pools: %v", poolErr)
		}
		for _, pool := range pools {
			poolAllocs, allocErr := s.ipam.GetAllocationsByPool(ctx, pool.ID)
			if allocErr != nil {
				continue // Skip pools we can't read.
			}
			allocations = append(allocations, poolAllocs...)
		}
	}

	if listErr != nil {
		return nil, ipamErrToGRPC(listErr)
	}

	// Exclude Released allocations — they are logically gone from the active
	// pool even though the memory backend retains them for audit.
	result := make([]*platformv1.IPAllocation, 0, len(allocations))
	for _, alloc := range allocations {
		if alloc.Status == ipam.AllocationStatusReleased {
			continue
		}
		result = append(result, ipamAllocationToProto(alloc))
	}

	return &platformv1.ListAllocationsResponse{Allocations: result}, nil
}

// =============================================================================
// Helper conversion functions
// =============================================================================

func peerInfoToProto(p *bgp.PeerInfo) *platformv1.BGPPeer {
	if p == nil {
		return nil
	}

	var uptimeTimestamp *timestamppb.Timestamp
	if p.Uptime > 0 {
		uptimeTimestamp = timestamppb.New(time.Now().Add(-p.Uptime))
	}

	return &platformv1.BGPPeer{
		Address:          p.Address.String(),
		Asn:              p.ASN,
		State:            p.State.String(),
		Description:      p.Description,
		PrefixesReceived: uint32(p.PrefixesReceived),
		PrefixesSent:     uint32(p.PrefixesSent),
		Uptime:           uptimeTimestamp,
	}
}

func pathToAnnouncedPrefix(p *bgp.Path) *platformv1.AnnouncedPrefix {
	if p == nil {
		return nil
	}
	return &platformv1.AnnouncedPrefix{
		Prefix:      p.Prefix.String(),
		NextHop:     p.NextHop.String(),
		AnnouncedAt: timestamppb.New(p.Age),
	}
}

// ipamPoolToProto converts an ipam.Pool to its proto representation.
func ipamPoolToProto(p *ipam.Pool) *platformv1.IPAMPool {
	if p == nil {
		return nil
	}

	var gatewayStr string
	if p.Gateway.IsValid() {
		gatewayStr = p.Gateway.String()
	}

	proto := &platformv1.IPAMPool{
		Id:                        p.ID,
		Name:                      p.Name,
		Cidr:                      p.CIDR.String(),
		Gateway:                   gatewayStr,
		Zone:                      p.Zone,
		Description:               p.Description,
		Total:                     p.TotalIPs,
		Allocated:                 p.AllocatedIPs,
		Available:                 p.AvailableIPs,
		DefaultLeaseDurationNanos: int64(p.DefaultLeaseDuration),
		InactivityTimeoutNanos:    int64(p.InactivityTimeout),
	}

	if !p.CreatedAt.IsZero() {
		proto.CreatedAt = timestamppb.New(p.CreatedAt)
	}
	if !p.UpdatedAt.IsZero() {
		proto.UpdatedAt = timestamppb.New(p.UpdatedAt)
	}

	return proto
}

func ipamAllocationToProto(a *ipam.Allocation) *platformv1.IPAllocation {
	if a == nil {
		return nil
	}

	var expiresAt *timestamppb.Timestamp
	if !a.ExpiresAt.IsZero() {
		expiresAt = timestamppb.New(a.ExpiresAt)
	}

	return &platformv1.IPAllocation{
		Ip:          a.IP.String(),
		PoolId:      a.PoolID,
		DeviceId:    a.DeviceID,
		Hostname:    a.Hostname,
		AllocatedAt: timestamppb.New(a.AllocatedAt),
		ExpiresAt:   expiresAt,
	}
}

// ipamErrToGRPC maps ipam package errors to gRPC status codes.
func ipamErrToGRPC(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, ipam.ErrPoolNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ipam.ErrAllocationNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ipam.ErrPoolAlreadyExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, ipam.ErrPoolNameExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, ipam.ErrPoolCIDROverlaps):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, ipam.ErrIPAlreadyAllocated):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, ipam.ErrPoolHasAllocations):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, ipam.ErrPoolExhausted):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, ipam.ErrInvalidCIDR),
		errors.Is(err, ipam.ErrInvalidIP),
		errors.Is(err, ipam.ErrInvalidGateway),
		errors.Is(err, ipam.ErrInvalidPoolID),
		errors.Is(err, ipam.ErrInvalidPoolName),
		errors.Is(err, ipam.ErrDeviceIDRequired),
		errors.Is(err, ipam.ErrPoolIDRequired):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ipam.ErrBackendUnavailable),
		errors.Is(err, ipam.ErrBackendTimeout):
		return status.Error(codes.Unavailable, err.Error())
	default:
		var opFail *ipam.ErrPoolOperationFailed
		if errors.As(err, &opFail) && errors.Is(opFail.Cause, ipam.ErrInvalidCIDR) {
			return status.Error(codes.InvalidArgument, "CIDR cannot be changed after pool creation")
		}
		return status.Errorf(codes.Internal, "IPAM operation failed: %v", err)
	}
}
