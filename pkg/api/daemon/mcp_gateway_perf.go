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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
)

// requireGatewayPerf returns the perf backend or the typed
// service-unavailable error.
func (m *MCPServiceProvider) requireGatewayPerf() (GatewayPerfInterface, error) {
	if m.gatewayBackends == nil || m.gatewayBackends.Perf() == nil {
		return nil, ErrServiceNotAvailable{Service: "gateway-perf"}
	}
	return m.gatewayBackends.Perf(), nil
}

// GatewayPerfFlows measures a real flow install/teardown cycle.
func (m *MCPServiceProvider) GatewayPerfFlows(ctx context.Context, bridge string, count int, batch bool) (interface{}, error) {
	backend, err := m.requireGatewayPerf()
	if err != nil {
		return nil, err
	}
	return gatewayPerfFlows(ctx, backend, bridge, count, batch)
}

// gatewayPerfFlows implements the shared MCP perf flows path for every
// mcp.ServiceProvider implementation. It returns the REST response shape
// so the tool result JSON matches the proto JSON field names.
func gatewayPerfFlows(ctx context.Context, backend GatewayPerfInterface, bridge string, count int, batch bool) (interface{}, error) {
	if count == 0 {
		count = perf.DefaultFlowCount
	}
	result, err := backend.Flows(ctx, bridge, count, batch)
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

// GatewayPerfDatapath reads live datapath counters.
func (m *MCPServiceProvider) GatewayPerfDatapath(ctx context.Context, bridge string) (interface{}, error) {
	backend, err := m.requireGatewayPerf()
	if err != nil {
		return nil, err
	}
	return gatewayPerfDatapath(ctx, backend, bridge)
}

// gatewayPerfDatapath implements the shared MCP perf datapath path.
func gatewayPerfDatapath(ctx context.Context, backend GatewayPerfInterface, bridge string) (interface{}, error) {
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

// GatewayPerfConntrack summarizes the conntrack table.
func (m *MCPServiceProvider) GatewayPerfConntrack(ctx context.Context, zone int) (interface{}, error) {
	backend, err := m.requireGatewayPerf()
	if err != nil {
		return nil, err
	}
	return gatewayPerfConntrack(ctx, backend, zone)
}

// gatewayPerfConntrack implements the shared MCP perf conntrack path.
func gatewayPerfConntrack(ctx context.Context, backend GatewayPerfInterface, zone int) (interface{}, error) {
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
