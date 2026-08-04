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
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
)

// ErrGatewayRESTNotConfigured is returned for gateway REST operations that
// require a hardware gateway controller (BGP, mode, status) when none is
// configured. Clients see it as 503 Service Unavailable.
type ErrGatewayRESTNotConfigured struct{ Feature string }

// Error implements the error interface.
func (e ErrGatewayRESTNotConfigured) Error() string {
	return fmt.Sprintf("gateway feature not configured: %s", e.Feature)
}

// gatewayRESTService implements rest.GatewayServiceInterface using the
// daemon's ipam.Allocator directly. Gateway status/BGP/mode methods return
// ErrGatewayRESTNotConfigured because those features require a full gateway
// controller that is only present when an SDN fabric is wired in.
//
// This service is always registered so that IPAM pool CRUD and IP allocation
// endpoints work over REST even without an SDN controller.
type gatewayRESTService struct {
	ipam   ipam.Allocator
	logger *slog.Logger
}

// Compile-time check: gatewayRESTService implements rest.GatewayServiceInterface.
var _ rest.GatewayServiceInterface = (*gatewayRESTService)(nil)

// newGatewayRESTService creates a gatewayRESTService backed by a default
// in-memory IPAM allocator. The caller may pass a pre-configured allocator
// via opt to override the default.
func newGatewayRESTService(allocator ipam.Allocator, logger *slog.Logger) *gatewayRESTService {
	if allocator == nil {
		allocator = backends.NewMemoryBackend()
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &gatewayRESTService{
		ipam:   allocator,
		logger: logger,
	}
}

// =============================================================================
// Gateway status / mode — not available without a hardware gateway
// =============================================================================

// GetGatewayStatus returns ErrGatewayRESTNotConfigured; no hardware gateway is wired.
func (s *gatewayRESTService) GetGatewayStatus(_ context.Context) (*rest.GatewayStatusResponse, error) {
	return nil, ErrGatewayRESTNotConfigured{Feature: "gateway status"}
}

// SetGatewayMode returns ErrGatewayRESTNotConfigured; no hardware gateway is wired.
func (s *gatewayRESTService) SetGatewayMode(_ context.Context, _ uint32) (*rest.SetGatewayModeResponse, error) {
	return nil, ErrGatewayRESTNotConfigured{Feature: "gateway mode"}
}

// =============================================================================
// BGP operations — not available without a BGP speaker
// =============================================================================

// GetBGPStatus returns ErrGatewayRESTNotConfigured; no BGP speaker is wired.
func (s *gatewayRESTService) GetBGPStatus(_ context.Context) (*rest.BGPStatusResponse, error) {
	return nil, ErrGatewayRESTNotConfigured{Feature: "bgp"}
}

// ListBGPPeers returns ErrGatewayRESTNotConfigured; no BGP speaker is wired.
func (s *gatewayRESTService) ListBGPPeers(_ context.Context) ([]rest.BGPPeerResponse, error) {
	return nil, ErrGatewayRESTNotConfigured{Feature: "bgp"}
}

// AnnouncePrefix returns ErrGatewayRESTNotConfigured; no BGP speaker is wired.
func (s *gatewayRESTService) AnnouncePrefix(_ context.Context, _, _ string) error {
	return ErrGatewayRESTNotConfigured{Feature: "bgp"}
}

// WithdrawPrefix returns ErrGatewayRESTNotConfigured; no BGP speaker is wired.
func (s *gatewayRESTService) WithdrawPrefix(_ context.Context, _ string) error {
	return ErrGatewayRESTNotConfigured{Feature: "bgp"}
}

// ListAnnouncedPrefixes returns ErrGatewayRESTNotConfigured; no BGP speaker is wired.
func (s *gatewayRESTService) ListAnnouncedPrefixes(_ context.Context) ([]rest.AnnouncedPrefixResponse, error) {
	return nil, ErrGatewayRESTNotConfigured{Feature: "bgp"}
}

// =============================================================================
// IPAM pool CRUD — backed by ipam.Allocator
// =============================================================================

// CreateIPAMPool creates a new IPAM pool.
func (s *gatewayRESTService) CreateIPAMPool(ctx context.Context, req *rest.CreateIPAMPoolRequest) (*rest.IPAMPoolResponse, error) {
	if req.Name == "" {
		return nil, &MessageError{Msg: "name is required"}
	}
	if req.CIDR == "" {
		return nil, &MessageError{Msg: "cidr is required"}
	}
	cidr, err := netip.ParsePrefix(req.CIDR)
	if err != nil {
		return nil, &WrappedError{Msg: "invalid cidr", Err: err}
	}
	cidr = cidr.Masked()

	id := req.ID
	if id == "" {
		id = uuid.New().String()
	}

	pool := &ipam.Pool{
		ID:          id,
		Name:        req.Name,
		CIDR:        cidr,
		Zone:        req.Zone,
		Description: req.Description,
	}

	if req.Gateway != "" {
		gw, parseErr := netip.ParseAddr(req.Gateway)
		if parseErr != nil {
			return nil, &WrappedError{Msg: "invalid gateway", Err: parseErr}
		}
		pool.Gateway = gw
	}
	if req.DefaultLeaseDurationNs > 0 {
		pool.DefaultLeaseDuration = time.Duration(req.DefaultLeaseDurationNs)
	}
	if req.InactivityTimeoutNs > 0 {
		pool.InactivityTimeout = time.Duration(req.InactivityTimeoutNs)
	}

	if err := s.ipam.CreatePool(ctx, pool); err != nil {
		return nil, s.mapIPAMError(err)
	}

	created, err := s.ipam.GetPool(ctx, id)
	if err != nil {
		return nil, &WrappedError{Msg: "pool created but could not be retrieved", Err: err}
	}
	return ipamPoolToRESTResponse(created), nil
}

// GetIPAMPool retrieves an IPAM pool by ID.
func (s *gatewayRESTService) GetIPAMPool(ctx context.Context, poolID string) (*rest.IPAMPoolResponse, error) {
	pool, err := s.ipam.GetPool(ctx, poolID)
	if err != nil {
		return nil, s.mapIPAMError(err)
	}
	return ipamPoolToRESTResponse(pool), nil
}

// UpdateIPAMPool updates mutable fields of an IPAM pool. CIDR is immutable.
func (s *gatewayRESTService) UpdateIPAMPool(ctx context.Context, poolID string, req *rest.UpdateIPAMPoolRequest) (*rest.IPAMPoolResponse, error) {
	pool, err := s.ipam.GetPool(ctx, poolID)
	if err != nil {
		return nil, s.mapIPAMError(err)
	}

	if req.Name != "" {
		pool.Name = req.Name
	}
	if req.Zone != "" {
		pool.Zone = req.Zone
	}
	if req.Description != "" {
		pool.Description = req.Description
	}
	if req.Gateway != "" {
		gw, parseErr := netip.ParseAddr(req.Gateway)
		if parseErr != nil {
			return nil, &WrappedError{Msg: "invalid gateway", Err: parseErr}
		}
		pool.Gateway = gw
	}
	if req.DefaultLeaseDurationNs > 0 {
		pool.DefaultLeaseDuration = time.Duration(req.DefaultLeaseDurationNs)
	}
	if req.InactivityTimeoutNs > 0 {
		pool.InactivityTimeout = time.Duration(req.InactivityTimeoutNs)
	}

	if err := s.ipam.UpdatePool(ctx, pool); err != nil {
		return nil, s.mapIPAMError(err)
	}

	updated, err := s.ipam.GetPool(ctx, poolID)
	if err != nil {
		return nil, &WrappedError{Msg: "pool updated but could not be retrieved", Err: err}
	}
	return ipamPoolToRESTResponse(updated), nil
}

// DeleteIPAMPool removes an IPAM pool.
func (s *gatewayRESTService) DeleteIPAMPool(ctx context.Context, poolID string) error {
	return s.mapIPAMError(s.ipam.DeletePool(ctx, poolID))
}

// ListIPAMPools returns all IPAM pools, optionally filtered by zone.
func (s *gatewayRESTService) ListIPAMPools(ctx context.Context, zone string) ([]rest.IPAMPoolResponse, error) {
	var pools []*ipam.Pool
	var err error
	if zone != "" {
		pools, err = s.ipam.ListPoolsByZone(ctx, zone)
	} else {
		pools, err = s.ipam.ListPools(ctx)
	}
	if err != nil {
		return nil, s.mapIPAMError(err)
	}

	resp := make([]rest.IPAMPoolResponse, 0, len(pools))
	for _, p := range pools {
		resp = append(resp, *ipamPoolToRESTResponse(p))
	}
	return resp, nil
}

// =============================================================================
// IPAM allocation operations
// =============================================================================

// AllocateIP allocates the next available IP from a pool.
func (s *gatewayRESTService) AllocateIP(ctx context.Context, poolID, deviceID, hostname string) (*rest.IPAllocationResponse, error) {
	req := &ipam.AllocationRequest{
		PoolID:   poolID,
		DeviceID: deviceID,
		Hostname: hostname,
	}
	alloc, err := s.ipam.Allocate(ctx, req)
	if err != nil {
		return nil, s.mapIPAMError(err)
	}
	return ipamAllocToRESTResponse(alloc), nil
}

// ReleaseIP releases an allocated IP address.
func (s *gatewayRESTService) ReleaseIP(ctx context.Context, ipStr string) error {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return &WrappedError{Msg: "invalid ip address", Err: err}
	}
	return s.mapIPAMError(s.ipam.Release(ctx, addr))
}

// ListAllocations returns all active IP allocations for a pool.
func (s *gatewayRESTService) ListAllocations(ctx context.Context, poolID string) ([]rest.IPAllocationResponse, error) {
	var allocs []*ipam.Allocation
	if poolID != "" {
		poolAllocs, err := s.ipam.GetAllocationsByPool(ctx, poolID)
		if err != nil {
			return nil, s.mapIPAMError(err)
		}
		allocs = poolAllocs
	} else {
		// pool_id is an optional filter: empty means all allocations,
		// aggregated across pools (mirrors the gRPC service semantics).
		pools, err := s.ipam.ListPools(ctx)
		if err != nil {
			return nil, s.mapIPAMError(err)
		}
		for _, pool := range pools {
			poolAllocs, err := s.ipam.GetAllocationsByPool(ctx, pool.ID)
			if err != nil {
				continue // Skip pools we cannot read.
			}
			allocs = append(allocs, poolAllocs...)
		}
	}
	resp := make([]rest.IPAllocationResponse, 0, len(allocs))
	for _, a := range allocs {
		resp = append(resp, *ipamAllocToRESTResponse(a))
	}
	return resp, nil
}

// =============================================================================
// Error mapping
// =============================================================================

// mapIPAMError converts ipam sentinel errors to typed REST errors.
func (s *gatewayRESTService) mapIPAMError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ipam.ErrPoolNotFound):
		return rest.ErrIPAMPoolNotFound{}
	case errors.Is(err, ipam.ErrPoolNameExists), errors.Is(err, ipam.ErrPoolAlreadyExists):
		return rest.ErrIPAMPoolAlreadyExists{}
	case errors.Is(err, ipam.ErrPoolHasAllocations):
		return rest.ErrIPAMPoolHasAllocations{}
	case errors.Is(err, ipam.ErrPoolExhausted):
		return rest.ErrIPAMPoolExhausted{}
	default:
		return err
	}
}

// =============================================================================
// Conversion helpers
// =============================================================================

// ipamPoolToRESTResponse converts an ipam.Pool to a rest.IPAMPoolResponse.
func ipamPoolToRESTResponse(p *ipam.Pool) *rest.IPAMPoolResponse {
	if p == nil {
		return nil
	}
	resp := &rest.IPAMPoolResponse{
		ID:                     p.ID,
		Name:                   p.Name,
		CIDR:                   p.CIDR.String(),
		Zone:                   p.Zone,
		Description:            p.Description,
		Total:                  p.TotalIPs,
		Allocated:              p.AllocatedIPs,
		Available:              p.AvailableIPs,
		DefaultLeaseDurationNs: int64(p.DefaultLeaseDuration),
		InactivityTimeoutNs:    int64(p.InactivityTimeout),
		CreatedAt:              p.CreatedAt,
		UpdatedAt:              p.UpdatedAt,
	}
	if p.Gateway.IsValid() {
		resp.Gateway = p.Gateway.String()
	}
	return resp
}

// ipamAllocToRESTResponse converts an ipam.Allocation to a rest.IPAllocationResponse.
func ipamAllocToRESTResponse(a *ipam.Allocation) *rest.IPAllocationResponse {
	if a == nil {
		return nil
	}
	return &rest.IPAllocationResponse{
		IP:          a.IP.String(),
		PoolID:      a.PoolID,
		DeviceID:    a.DeviceID,
		Hostname:    a.Hostname,
		AllocatedAt: a.AllocatedAt,
		ExpiresAt:   a.ExpiresAt,
	}
}
