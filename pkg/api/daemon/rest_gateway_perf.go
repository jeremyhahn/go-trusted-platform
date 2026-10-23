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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
)

// gatewayPerfRESTService bridges the shared perf backend into the REST
// gateway perf handler interface.
type gatewayPerfRESTService struct {
	backends GatewayBackendSource
}

// newGatewayPerfRESTService creates the REST perf adapter.
func newGatewayPerfRESTService(backends GatewayBackendSource) *gatewayPerfRESTService {
	return &gatewayPerfRESTService{backends: backends}
}

// requirePerf returns the shared service's perf backend, or the typed
// not-configured error (503) when none is wired.
func (s *gatewayPerfRESTService) requirePerf() (GatewayPerfInterface, error) {
	if s.backends == nil || s.backends.Perf() == nil {
		return nil, rest.ErrPerfNotConfigured{}
	}
	return s.backends.Perf(), nil
}

// Ensure the adapter satisfies the REST perf interface.
var _ rest.GatewayPerfServiceInterface = (*gatewayPerfRESTService)(nil)

// mapPerfError converts perf service errors to typed REST errors.
func mapPerfError(err error) error {
	if err == nil {
		return nil
	}
	var countErr *perf.ErrInvalidFlowCount
	var bridgeErr *perf.ErrBridgeUnavailable
	var notActive *gateway.ErrServiceNotActive
	switch {
	case errors.As(err, &notActive):
		return rest.ErrPerfNotConfigured{}
	case errors.As(err, &countErr):
		return rest.ErrPerfInvalidRequest{Reason: err.Error()}
	case errors.As(err, &bridgeErr):
		return rest.ErrPerfBridgeNotFound{Bridge: bridgeErr.Bridge}
	case errors.Is(err, perf.ErrNoBridgeAvailable), errors.Is(err, perf.ErrAppCtlUnavailable):
		return rest.ErrPerfNotConfigured{}
	default:
		return err
	}
}

// GetPerfFlows measures a real flow install/teardown cycle.
func (s *gatewayPerfRESTService) GetPerfFlows(ctx context.Context, req *rest.PerfFlowsRequest) (*rest.PerfFlowsResponse, error) {
	if req == nil {
		return nil, rest.ErrPerfInvalidRequest{Reason: "request body is required"}
	}
	count := int(req.Count)
	if count == 0 {
		count = perf.DefaultFlowCount
	}

	backend, err := s.requirePerf()
	if err != nil {
		return nil, err
	}
	result, err := backend.Flows(ctx, req.Bridge, count, req.Batch)
	if err != nil {
		return nil, mapPerfError(err)
	}
	return &rest.PerfFlowsResponse{
		Installed:      uint32(result.Installed),
		DurationNs:     result.Duration.Nanoseconds(),
		FlowsPerSecond: result.FlowsPerSecond,
		Batched:        result.Batched,
		Bridge:         result.Bridge,
	}, nil
}

// GetPerfDatapath reads live datapath counters.
func (s *gatewayPerfRESTService) GetPerfDatapath(ctx context.Context, bridge string) (*rest.PerfDatapathResponse, error) {
	backend, err := s.requirePerf()
	if err != nil {
		return nil, err
	}
	result, err := backend.Datapath(ctx, bridge)
	if err != nil {
		return nil, mapPerfError(err)
	}
	return &rest.PerfDatapathResponse{
		Hits:               result.Hits,
		Misses:             result.Missed,
		Lost:               result.Lost,
		OffloadedFlowCount: uint64(result.OffloadedFlowCount),
		HWOffloadEnabled:   result.HWOffloadEnabled,
		DatapathType:       result.DatapathType,
		Bridge:             result.Bridge,
	}, nil
}

// GetPerfConntrack summarizes the conntrack table.
func (s *gatewayPerfRESTService) GetPerfConntrack(ctx context.Context, zone int) (*rest.PerfConntrackResponse, error) {
	backend, err := s.requirePerf()
	if err != nil {
		return nil, err
	}
	result, err := backend.Conntrack(ctx, zone)
	if err != nil {
		return nil, mapPerfError(err)
	}
	perZone := make(map[uint32]uint64, len(result.PerZone))
	for z, n := range result.PerZone {
		perZone[uint32(z)] = uint64(n)
	}
	return &rest.PerfConntrackResponse{
		TotalEntries: uint64(result.TotalEntries),
		PerZone:      perZone,
	}, nil
}
