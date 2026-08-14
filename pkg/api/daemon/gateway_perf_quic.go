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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
)

// gatewayPerfQUICAdapter bridges the shared perf backend into the QUIC
// gateway perf handler interface.
type gatewayPerfQUICAdapter struct {
	perf GatewayPerfInterface
}

// newGatewayPerfQUICAdapter creates the QUIC perf adapter.
func newGatewayPerfQUICAdapter(backend GatewayPerfInterface) *gatewayPerfQUICAdapter {
	return &gatewayPerfQUICAdapter{perf: backend}
}

// Ensure the adapter satisfies the QUIC perf interface.
var _ quic.GatewayPerfServiceInterface = (*gatewayPerfQUICAdapter)(nil)

// mapPerfToQUICError translates perf service errors to the sentinel
// errors recognized by quic.GatewayHandler.perfErrorResponse.
func mapPerfToQUICError(err error) error {
	if err == nil {
		return nil
	}
	var countErr *perf.ErrInvalidFlowCount
	var bridgeErr *perf.ErrBridgeUnavailable
	switch {
	case errors.As(err, &countErr):
		return quic.ErrGatewayPerfInvalidRequest
	case errors.As(err, &bridgeErr):
		return quic.ErrGatewayPerfBridgeNotFound
	case errors.Is(err, perf.ErrNoBridgeAvailable), errors.Is(err, perf.ErrAppCtlUnavailable):
		return quic.ErrGatewayPerfNotConfigured
	default:
		return err
	}
}

// PerfFlows measures a real flow install/teardown cycle.
func (a *gatewayPerfQUICAdapter) PerfFlows(ctx context.Context, bridge string, count uint32, batch bool) (*quic.PerfFlowsInfo, error) {
	flowCount := int(count)
	if flowCount == 0 {
		flowCount = perf.DefaultFlowCount
	}

	result, err := a.perf.Flows(ctx, bridge, flowCount, batch)
	if err != nil {
		return nil, mapPerfToQUICError(err)
	}
	return &quic.PerfFlowsInfo{
		Installed:      uint32(result.Installed),
		DurationNs:     result.Duration.Nanoseconds(),
		FlowsPerSecond: result.FlowsPerSecond,
		Batched:        result.Batched,
		Bridge:         result.Bridge,
	}, nil
}

// PerfDatapath reads live datapath counters.
func (a *gatewayPerfQUICAdapter) PerfDatapath(ctx context.Context, bridge string) (*quic.PerfDatapathInfo, error) {
	result, err := a.perf.Datapath(ctx, bridge)
	if err != nil {
		return nil, mapPerfToQUICError(err)
	}
	return &quic.PerfDatapathInfo{
		Hits:               result.Hits,
		Misses:             result.Missed,
		Lost:               result.Lost,
		OffloadedFlowCount: uint64(result.OffloadedFlowCount),
		HwOffloadEnabled:   result.HWOffloadEnabled,
		DatapathType:       result.DatapathType,
		Bridge:             result.Bridge,
	}, nil
}

// PerfConntrack summarizes the conntrack table.
func (a *gatewayPerfQUICAdapter) PerfConntrack(ctx context.Context, zone *uint32) (*quic.PerfConntrackInfo, error) {
	zoneFilter := -1
	if zone != nil {
		zoneFilter = int(*zone)
	}

	result, err := a.perf.Conntrack(ctx, zoneFilter)
	if err != nil {
		return nil, mapPerfToQUICError(err)
	}
	perZone := make(map[uint32]uint64, len(result.PerZone))
	for z, n := range result.PerZone {
		perZone[uint32(z)] = uint64(n)
	}
	return &quic.PerfConntrackInfo{
		TotalEntries: uint64(result.TotalEntries),
		PerZone:      perZone,
	}, nil
}
