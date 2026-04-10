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
	"net/netip"
	"sync"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
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
	GetActiveModes() gateway.GatewayMode
	Uptime() time.Duration

	// Mode operations
	ActivateMode(ctx context.Context, mode gateway.GatewayMode) error
	DeactivateMode(ctx context.Context, mode gateway.GatewayMode) error
	HasMode(mode gateway.GatewayMode) bool
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
			Modes:         uint32(gwStatus.ActiveModes),
			Tier:          tier,
			Reputation:    node.Reputation,
			UptimeSeconds: uint64(s.gateway.Uptime().Seconds()),
			Healthy:       gwStatus.State.IsHealthy(),
			StartedAt:     timestamppb.New(gwStatus.StartedAt),
		},
	}, nil
}

// SetGatewayMode activates or deactivates gateway modes.
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

	requestedModes := gateway.GatewayMode(req.GetModes())
	currentModes := s.gateway.GetActiveModes()

	// Deactivate modes that are no longer requested
	for _, mode := range currentModes.Modes() {
		if !requestedModes.HasMode(mode) {
			if err := s.gateway.DeactivateMode(ctx, mode); err != nil {
				return nil, status.Errorf(codes.Internal, "failed to deactivate mode %s: %v", mode.String(), err)
			}
		}
	}

	// Activate new modes
	for _, mode := range requestedModes.Modes() {
		if !currentModes.HasMode(mode) {
			if err := s.gateway.ActivateMode(ctx, mode); err != nil {
				return nil, status.Errorf(codes.Internal, "failed to activate mode %s: %v", mode.String(), err)
			}
		}
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
			Modes:         uint32(gwStatus.ActiveModes),
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

// ListIPAMPools returns all IPAM address pools.
func (s *GatewayService) ListIPAMPools(ctx context.Context, req *platformv1.ListIPAMPoolsRequest) (*platformv1.ListIPAMPoolsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.ipam == nil {
		return nil, status.Error(codes.Unavailable, "IPAM not configured")
	}

	pools, err := s.ipam.ListPools(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list IPAM pools: %v", err)
	}

	result := make([]*platformv1.IPAMPool, 0, len(pools))
	for _, pool := range pools {
		result = append(result, ipamPoolToProto(pool))
	}

	return &platformv1.ListIPAMPoolsResponse{Pools: result}, nil
}

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

	if s.ipam == nil {
		return nil, status.Error(codes.Unavailable, "IPAM not configured")
	}

	allocReq := &ipam.AllocationRequest{
		PoolID:   req.GetPoolId(),
		DeviceID: req.GetDeviceId(),
		Hostname: req.GetHostname(),
	}

	allocation, err := s.ipam.Allocate(ctx, allocReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to allocate IP: %v", err)
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

	if s.ipam == nil {
		return nil, status.Error(codes.Unavailable, "IPAM not configured")
	}

	if err := s.ipam.Release(ctx, ip); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to release IP: %v", err)
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

	if s.ipam == nil {
		return nil, status.Error(codes.Unavailable, "IPAM not configured")
	}

	var allocations []*ipam.Allocation
	var err error

	if req.GetPoolId() != "" {
		allocations, err = s.ipam.GetAllocationsByPool(ctx, req.GetPoolId())
	} else {
		// List all allocations by listing pools and getting allocations for each
		pools, listErr := s.ipam.ListPools(ctx)
		if listErr != nil {
			return nil, status.Errorf(codes.Internal, "failed to list pools: %v", listErr)
		}

		for _, pool := range pools {
			poolAllocs, allocErr := s.ipam.GetAllocationsByPool(ctx, pool.ID)
			if allocErr != nil {
				continue // Skip pools we can't read
			}
			allocations = append(allocations, poolAllocs...)
		}
	}

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list allocations: %v", err)
	}

	result := make([]*platformv1.IPAllocation, 0, len(allocations))
	for _, alloc := range allocations {
		result = append(result, ipamAllocationToProto(alloc))
	}

	return &platformv1.ListAllocationsResponse{Allocations: result}, nil
}

// Helper conversion functions

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

func ipamPoolToProto(p *ipam.Pool) *platformv1.IPAMPool {
	if p == nil {
		return nil
	}

	var gatewayStr string
	if p.Gateway.IsValid() {
		gatewayStr = p.Gateway.String()
	}

	return &platformv1.IPAMPool{
		Id:        p.ID,
		Cidr:      p.CIDR.String(),
		Gateway:   gatewayStr,
		Total:     uint32(p.TotalIPs),
		Allocated: uint32(p.AllocatedIPs),
		Available: uint32(p.AvailableIPs),
	}
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
