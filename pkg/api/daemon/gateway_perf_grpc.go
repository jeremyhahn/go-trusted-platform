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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GatewayPerfInterface abstracts the gateway performance verification
// operations for the API layers. *perf.Service implements it.
type GatewayPerfInterface interface {
	Flows(ctx context.Context, bridge string, count int, batch bool) (perf.FlowsResult, error)
	Datapath(ctx context.Context, bridge string) (perf.DatapathResult, error)
	Conntrack(ctx context.Context, zone int) (perf.ConntrackResult, error)
}

// Ensure perf.Service implements GatewayPerfInterface.
var _ GatewayPerfInterface = (*perf.Service)(nil)

// WithPerf sets the perf backend for the service.
func WithPerf(p GatewayPerfInterface) GatewayServiceOption {
	return func(s *GatewayService) {
		s.perf = p
	}
}

// Perf returns the perf backend for testing purposes.
func (s *GatewayService) Perf() GatewayPerfInterface {
	return s.perf
}

// SetPerf sets the perf backend (useful for testing).
func (s *GatewayService) SetPerf(p GatewayPerfInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.perf = p
}

// requirePerf returns an error when the perf backend is not configured
// (the daemon has no OVS access).
func (s *GatewayService) requirePerf() error {
	if s.perf == nil {
		return status.Error(codes.Unavailable, "gateway perf service not configured")
	}
	return nil
}

// perfErrToGRPC maps perf service errors to gRPC status codes.
func perfErrToGRPC(err error) error {
	if err == nil {
		return nil
	}
	var countErr *perf.ErrInvalidFlowCount
	var bridgeErr *perf.ErrBridgeUnavailable
	switch {
	case errors.As(err, &countErr):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &bridgeErr):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, perf.ErrNoBridgeAvailable):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, perf.ErrAppCtlUnavailable):
		return status.Error(codes.Unavailable, err.Error())
	default:
		return status.Errorf(codes.Internal, "perf operation failed: %v", err)
	}
}

// GetPerfFlows measures real flow-programming throughput by installing
// ephemeral flows into the dedicated perf table and timing the install.
//
// Permission: sdn:write — although the flows are ephemeral and confined
// to table 250 with the perf cookie, the operation MUTATES the bridge
// flow tables (install + cookie-scoped delete), so it is gated as a
// write, not a read.
func (s *GatewayService) GetPerfFlows(ctx context.Context, req *platformv1.GetPerfFlowsRequest) (*platformv1.GetPerfFlowsResponse, error) {
	count := int(req.GetCount())
	if count == 0 {
		count = perf.DefaultFlowCount
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requirePerf(); err != nil {
		return nil, err
	}
	result, err := s.perf.Flows(ctx, req.GetBridge(), count, req.GetBatch())
	if err != nil {
		return nil, perfErrToGRPC(err)
	}

	return &platformv1.GetPerfFlowsResponse{
		Installed:      uint32(result.Installed),
		DurationNs:     result.Duration.Nanoseconds(),
		FlowsPerSecond: result.FlowsPerSecond,
		Batched:        result.Batched,
		Bridge:         result.Bridge,
	}, nil
}

// GetPerfDatapath reports live datapath lookup counters, the offloaded
// flow count, and the hardware offload configuration state.
//
// Permission: sdn:read — read-only counters.
func (s *GatewayService) GetPerfDatapath(ctx context.Context, req *platformv1.GetPerfDatapathRequest) (*platformv1.GetPerfDatapathResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.requirePerf(); err != nil {
		return nil, err
	}
	result, err := s.perf.Datapath(ctx, req.GetBridge())
	if err != nil {
		return nil, perfErrToGRPC(err)
	}

	return &platformv1.GetPerfDatapathResponse{
		Hits:               result.Hits,
		Misses:             result.Missed,
		Lost:               result.Lost,
		OffloadedFlowCount: uint64(result.OffloadedFlowCount),
		HwOffloadEnabled:   result.HWOffloadEnabled,
		DatapathType:       result.DatapathType,
		Bridge:             result.Bridge,
	}, nil
}

// GetPerfConntrack summarizes the connection tracking table, optionally
// restricted to one zone.
//
// Permission: sdn:read — read-only counters.
func (s *GatewayService) GetPerfConntrack(ctx context.Context, req *platformv1.GetPerfConntrackRequest) (*platformv1.GetPerfConntrackResponse, error) {
	zone := -1
	if req.Zone != nil {
		zone = int(req.GetZone())
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.requirePerf(); err != nil {
		return nil, err
	}
	result, err := s.perf.Conntrack(ctx, zone)
	if err != nil {
		return nil, perfErrToGRPC(err)
	}

	perZone := make(map[uint32]uint64, len(result.PerZone))
	for z, n := range result.PerZone {
		perZone[uint32(z)] = uint64(n)
	}
	return &platformv1.GetPerfConntrackResponse{
		TotalEntries: uint64(result.TotalEntries),
		PerZone:      perZone,
	}, nil
}
