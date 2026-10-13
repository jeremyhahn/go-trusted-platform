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
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// gatewayRESTService implements rest.GatewayServiceInterface using the
// daemon's ipam.Allocator directly. Gateway status and mode delegate to the
// gateway gRPC service, so they report not configured exactly when gRPC
// does (no in-process gateway). BGP methods return
// rest.ErrGatewayFeatureNotConfigured: platformd constructs no BGP speaker.
//
// This service is always registered so that IPAM pool CRUD and IP allocation
// endpoints work over REST even without an SDN controller.
type gatewayRESTService struct {
	ipam   ipam.Allocator
	status GatewayStatusController
	lb     GatewayLoadBalancerInterface
	nat64  GatewayNAT64Interface
	reader GatewaySnapshotReader
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
// Gateway status / mode — served by the gateway gRPC service (#65)
// =============================================================================

// SetGatewayStatusController wires the gateway gRPC service the status and
// mode routes answer from.
func (s *gatewayRESTService) SetGatewayStatusController(controller GatewayStatusController) {
	s.status = controller
}

// GetGatewayStatus returns the gateway status from the gateway gRPC service.
func (s *gatewayRESTService) GetGatewayStatus(ctx context.Context) (*rest.GatewayStatusResponse, error) {
	const feature = "gateway status"
	if s.status == nil {
		return nil, rest.ErrGatewayFeatureNotConfigured{Feature: feature}
	}
	resp, err := s.status.GetGatewayStatus(ctx, &platformv1.GetGatewayStatusRequest{})
	if err != nil {
		return nil, gatewayStatusRESTError(feature, 0, err)
	}
	return protoGatewayStatusToREST(resp.GetStatus()), nil
}

// SetGatewayMode sets the gateway's mode bitmask through the gateway gRPC
// service and returns its status after the change.
func (s *gatewayRESTService) SetGatewayMode(ctx context.Context, modes uint32) (*rest.SetGatewayModeResponse, error) {
	const feature = "gateway mode"
	if s.status == nil {
		return nil, rest.ErrGatewayFeatureNotConfigured{Feature: feature}
	}
	resp, err := s.status.SetGatewayMode(ctx, &platformv1.SetGatewayModeRequest{Modes: modes})
	if err != nil {
		return nil, gatewayStatusRESTError(feature, modes, err)
	}
	return &rest.SetGatewayModeResponse{
		Success:       true,
		GatewayStatus: protoGatewayStatusToREST(resp.GetGatewayStatus()),
	}, nil
}

// gatewayStatusRESTError maps a gateway gRPC status error to the typed REST
// error its handler turns into an HTTP status: Unavailable (no in-process
// gateway) is not configured, InvalidArgument is an invalid mode. Any other
// error passes through.
func gatewayStatusRESTError(feature string, modes uint32, err error) error {
	switch grpcstatus.Code(err) {
	case codes.Unavailable:
		return rest.ErrGatewayFeatureNotConfigured{Feature: feature}
	case codes.InvalidArgument:
		return rest.ErrInvalidGatewayMode{Mode: modes}
	default:
		return err
	}
}

// protoGatewayStatusToREST converts the gRPC gateway status to its REST
// shape; nil stays nil.
func protoGatewayStatusToREST(s *platformv1.GatewayStatus) *rest.GatewayStatusResponse {
	if s == nil {
		return nil
	}
	resp := &rest.GatewayStatusResponse{
		ID:            s.GetId(),
		NodeID:        s.GetNodeId(),
		Modes:         s.GetModes(),
		Tier:          s.GetTier(),
		Reputation:    s.GetReputation(),
		UptimeSeconds: s.GetUptimeSeconds(),
		Healthy:       s.GetHealthy(),
		Timestamp:     time.Now(),
	}
	if s.GetStartedAt() != nil {
		resp.StartedAt = s.GetStartedAt().AsTime()
	}
	return resp
}

// =============================================================================
// BGP operations — not available without a BGP speaker
// =============================================================================

// GetBGPStatus returns rest.ErrGatewayFeatureNotConfigured; no BGP speaker is wired.
func (s *gatewayRESTService) GetBGPStatus(_ context.Context) (*rest.BGPStatusResponse, error) {
	return nil, rest.ErrGatewayFeatureNotConfigured{Feature: "bgp"}
}

// ListBGPPeers returns rest.ErrGatewayFeatureNotConfigured; no BGP speaker is wired.
func (s *gatewayRESTService) ListBGPPeers(_ context.Context) ([]rest.BGPPeerResponse, error) {
	return nil, rest.ErrGatewayFeatureNotConfigured{Feature: "bgp"}
}

// AnnouncePrefix returns rest.ErrGatewayFeatureNotConfigured; no BGP speaker is wired.
func (s *gatewayRESTService) AnnouncePrefix(_ context.Context, _, _ string) error {
	return rest.ErrGatewayFeatureNotConfigured{Feature: "bgp"}
}

// WithdrawPrefix returns rest.ErrGatewayFeatureNotConfigured; no BGP speaker is wired.
func (s *gatewayRESTService) WithdrawPrefix(_ context.Context, _ string) error {
	return rest.ErrGatewayFeatureNotConfigured{Feature: "bgp"}
}

// ListAnnouncedPrefixes returns rest.ErrGatewayFeatureNotConfigured; no BGP speaker is wired.
func (s *gatewayRESTService) ListAnnouncedPrefixes(_ context.Context) ([]rest.AnnouncedPrefixResponse, error) {
	return nil, rest.ErrGatewayFeatureNotConfigured{Feature: "bgp"}
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
	reserved, rangeStart, rangeEnd, err := ipam.ParseWindow(req.Reserved, req.RangeStart, req.RangeEnd)
	if err != nil {
		return nil, s.mapIPAMError(err)
	}
	pool.Reserved = reserved
	pool.RangeStart = rangeStart
	pool.RangeEnd = rangeEnd

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
	if err := applyRESTWindowUpdate(pool, req); err != nil {
		return nil, s.mapIPAMError(err)
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
	allocs, err := activeAllocations(ctx, s.ipam, poolID)
	if err != nil {
		return nil, s.mapIPAMError(err)
	}
	resp := make([]rest.IPAllocationResponse, 0, len(allocs))
	for _, a := range allocs {
		resp = append(resp, *ipamAllocToRESTResponse(a))
	}
	return resp, nil
}

// GetAdmittedVTEP returns one VTEP the gateway reported as admitted.
func (s *gatewayRESTService) GetAdmittedVTEP(ctx context.Context, gatewayID, vtep string) (*rest.GatewayAdmittedVTEPResponse, error) {
	if s.reader == nil {
		return nil, rest.ErrGatewayFeatureNotConfigured{Feature: "gateway overlay admission"}
	}
	resp, err := s.reader.GetGatewayAdmittedVTEP(ctx, &platformv1.GetGatewayAdmittedVTEPRequest{GatewayId: gatewayID, Vtep: vtep})
	if err != nil {
		return nil, gatewayAdmissionErrToREST(vtep, err)
	}
	return admittedVTEPToREST(resp.GetVtep()), nil
}

// ListAdmittedVTEPs returns every VTEP the gateway reported as admitted.
func (s *gatewayRESTService) ListAdmittedVTEPs(ctx context.Context, gatewayID string) ([]rest.GatewayAdmittedVTEPResponse, error) {
	if s.reader == nil {
		return nil, rest.ErrGatewayFeatureNotConfigured{Feature: "gateway overlay admission"}
	}
	resp, err := s.reader.ListGatewayAdmittedVTEPs(ctx, &platformv1.ListGatewayAdmittedVTEPsRequest{GatewayId: gatewayID})
	if err != nil {
		return nil, gatewayAdmissionErrToREST("", err)
	}
	out := make([]rest.GatewayAdmittedVTEPResponse, 0, len(resp.GetVteps()))
	for _, vtep := range resp.GetVteps() {
		out = append(out, *admittedVTEPToREST(vtep))
	}
	return out, nil
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
	case isIPAMWindowError(err):
		return rest.ErrIPAMWindow{Reason: err.Error()}
	default:
		return err
	}
}

// applyRESTWindowUpdate applies the window fields present in an update
// request to pool: a present field replaces the pool's value, an omitted
// one keeps it.
func applyRESTWindowUpdate(pool *ipam.Pool, req *rest.UpdateIPAMPoolRequest) error {
	return pool.ApplyWindowUpdate(req.Reserved, req.RangeStart, req.RangeEnd)
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
		Reserved:               p.ReservedStrings(),
		RangeStart:             ipam.AddrString(p.RangeStart),
		RangeEnd:               ipam.AddrString(p.RangeEnd),
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
		Status:      string(a.Status),
		AllocatedAt: a.AllocatedAt,
		ExpiresAt:   a.ExpiresAt,
	}
}

func admittedVTEPToREST(vtep *platformv1.GatewayAdmittedVTEP) *rest.GatewayAdmittedVTEPResponse {
	if vtep == nil {
		return nil
	}
	out := &rest.GatewayAdmittedVTEPResponse{
		VTEP:           vtep.GetVtep(),
		DeviceID:       vtep.GetDeviceId(),
		HostID:         vtep.GetHostId(),
		Serial:         vtep.GetSerial(),
		Hostname:       vtep.GetHostname(),
		AllocationID:   vtep.GetAllocationId(),
		BaselineSource: vtep.GetBaselineSource(),
		ProfileID:      vtep.GetProfileId(),
	}
	if ts := vtep.GetVerdictAt(); ts != nil {
		verdictAt := ts.AsTime()
		out.VerdictAt = &verdictAt
	}
	return out
}

func gatewayAdmissionErrToREST(vtep string, err error) error {
	switch grpcstatus.Code(err) {
	case codes.NotFound:
		return rest.ErrGatewayAdmittedVTEPNotFound{VTEP: vtep}
	case codes.Unavailable:
		// A gateway with no overlay section is a disabled capability (503),
		// not a server fault.
		return rest.ErrGatewayFeatureNotConfigured{Feature: "gateway overlay admission"}
	}
	return err
}
