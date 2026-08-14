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
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
)

// =============================================================================
// REST perf adapter
// =============================================================================

func TestRESTPerfGetPerfFlows(t *testing.T) {
	backend := &fakeGatewayPerf{flowsResult: perf.FlowsResult{
		Installed:      100,
		Duration:       time.Millisecond,
		FlowsPerSecond: 100000,
		Batched:        true,
		Bridge:         "br-int",
	}}
	svc := newGatewayPerfRESTService(backend)

	resp, err := svc.GetPerfFlows(context.Background(), &rest.PerfFlowsRequest{Count: 100, Batch: true})
	if err != nil {
		t.Fatalf("GetPerfFlows: %v", err)
	}
	if resp.Installed != 100 || !resp.Batched || resp.Bridge != "br-int" {
		t.Errorf("resp = %+v", resp)
	}
	if resp.DurationNs != time.Millisecond.Nanoseconds() {
		t.Errorf("DurationNs = %d", resp.DurationNs)
	}
}

func TestRESTPerfGetPerfFlowsDefaultsCount(t *testing.T) {
	backend := &fakeGatewayPerf{}
	svc := newGatewayPerfRESTService(backend)

	if _, err := svc.GetPerfFlows(context.Background(), &rest.PerfFlowsRequest{}); err != nil {
		t.Fatalf("GetPerfFlows: %v", err)
	}
	if backend.lastCount != perf.DefaultFlowCount {
		t.Errorf("count = %d, want default %d", backend.lastCount, perf.DefaultFlowCount)
	}
}

func TestRESTPerfGetPerfFlowsErrors(t *testing.T) {
	t.Run("nil request", func(t *testing.T) {
		svc := newGatewayPerfRESTService(&fakeGatewayPerf{})
		_, err := svc.GetPerfFlows(context.Background(), nil)
		var invalidErr rest.ErrPerfInvalidRequest
		if !errors.As(err, &invalidErr) {
			t.Fatalf("err = %v, want ErrPerfInvalidRequest", err)
		}
	})

	t.Run("invalid count maps to invalid request", func(t *testing.T) {
		backend := &fakeGatewayPerf{err: &perf.ErrInvalidFlowCount{Count: -1, Max: perf.MaxFlowCount}}
		svc := newGatewayPerfRESTService(backend)
		_, err := svc.GetPerfFlows(context.Background(), &rest.PerfFlowsRequest{Count: 5})
		var invalidErr rest.ErrPerfInvalidRequest
		if !errors.As(err, &invalidErr) {
			t.Fatalf("err = %v, want ErrPerfInvalidRequest", err)
		}
	})

	t.Run("bridge not found", func(t *testing.T) {
		backend := &fakeGatewayPerf{err: &perf.ErrBridgeUnavailable{Bridge: "br-x", Cause: errors.New("gone")}}
		svc := newGatewayPerfRESTService(backend)
		_, err := svc.GetPerfFlows(context.Background(), &rest.PerfFlowsRequest{Count: 5})
		var notFoundErr rest.ErrPerfBridgeNotFound
		if !errors.As(err, &notFoundErr) {
			t.Fatalf("err = %v, want ErrPerfBridgeNotFound", err)
		}
		if notFoundErr.Bridge != "br-x" {
			t.Errorf("Bridge = %q", notFoundErr.Bridge)
		}
	})
}

func TestRESTPerfGetPerfDatapath(t *testing.T) {
	backend := &fakeGatewayPerf{datapathResult: perf.DatapathResult{
		Hits: 10, Missed: 2, Lost: 1, OffloadedFlowCount: 4,
		HWOffloadEnabled: true, DatapathType: "netdev", Bridge: "br-a",
	}}
	svc := newGatewayPerfRESTService(backend)

	resp, err := svc.GetPerfDatapath(context.Background(), "br-a")
	if err != nil {
		t.Fatalf("GetPerfDatapath: %v", err)
	}
	if resp.Hits != 10 || resp.Misses != 2 || resp.Lost != 1 {
		t.Errorf("counters = %+v", resp)
	}
	if resp.OffloadedFlowCount != 4 || !resp.HWOffloadEnabled || resp.DatapathType != "netdev" {
		t.Errorf("offload = %+v", resp)
	}
}

func TestRESTPerfGetPerfDatapathAppCtlUnavailable(t *testing.T) {
	backend := &fakeGatewayPerf{err: perf.ErrAppCtlUnavailable}
	svc := newGatewayPerfRESTService(backend)

	_, err := svc.GetPerfDatapath(context.Background(), "")
	var notConfigured rest.ErrPerfNotConfigured
	if !errors.As(err, &notConfigured) {
		t.Fatalf("err = %v, want ErrPerfNotConfigured", err)
	}
}

func TestRESTPerfGetPerfConntrack(t *testing.T) {
	backend := &fakeGatewayPerf{conntrackResult: perf.ConntrackResult{
		TotalEntries: 3,
		PerZone:      map[int]int{7: 2, 0: 1},
	}}
	svc := newGatewayPerfRESTService(backend)

	resp, err := svc.GetPerfConntrack(context.Background(), 7)
	if err != nil {
		t.Fatalf("GetPerfConntrack: %v", err)
	}
	if resp.TotalEntries != 3 || resp.PerZone[7] != 2 || resp.PerZone[0] != 1 {
		t.Errorf("resp = %+v", resp)
	}
	if backend.lastZone != 7 {
		t.Errorf("zone = %d, want 7", backend.lastZone)
	}
}

func TestRESTPerfGetPerfConntrackError(t *testing.T) {
	backend := &fakeGatewayPerf{err: errors.New("boom")}
	svc := newGatewayPerfRESTService(backend)

	if _, err := svc.GetPerfConntrack(context.Background(), -1); err == nil {
		t.Fatal("expected error")
	}
}

// =============================================================================
// QUIC perf adapter
// =============================================================================

func TestQUICPerfFlows(t *testing.T) {
	backend := &fakeGatewayPerf{flowsResult: perf.FlowsResult{
		Installed:      250,
		Duration:       time.Millisecond,
		FlowsPerSecond: 250000,
		Batched:        false,
		Bridge:         "br-int",
	}}
	adapter := newGatewayPerfQUICAdapter(backend)

	info, err := adapter.PerfFlows(context.Background(), "br-int", 250, false)
	if err != nil {
		t.Fatalf("PerfFlows: %v", err)
	}
	if info.Installed != 250 || info.Batched || info.Bridge != "br-int" {
		t.Errorf("info = %+v", info)
	}
	if backend.lastCount != 250 {
		t.Errorf("count = %d", backend.lastCount)
	}
}

func TestQUICPerfFlowsDefaultsCount(t *testing.T) {
	backend := &fakeGatewayPerf{}
	adapter := newGatewayPerfQUICAdapter(backend)

	if _, err := adapter.PerfFlows(context.Background(), "", 0, true); err != nil {
		t.Fatalf("PerfFlows: %v", err)
	}
	if backend.lastCount != perf.DefaultFlowCount {
		t.Errorf("count = %d, want default %d", backend.lastCount, perf.DefaultFlowCount)
	}
}

func TestQUICPerfErrorMapping(t *testing.T) {
	cases := []struct {
		name    string
		backend error
		want    error
	}{
		{"invalid count", &perf.ErrInvalidFlowCount{Count: -1, Max: 1}, quic.ErrGatewayPerfInvalidRequest},
		{"bridge unavailable", &perf.ErrBridgeUnavailable{Bridge: "br-x", Cause: errors.New("gone")}, quic.ErrGatewayPerfBridgeNotFound},
		{"no bridges", perf.ErrNoBridgeAvailable, quic.ErrGatewayPerfNotConfigured},
		{"appctl unavailable", perf.ErrAppCtlUnavailable, quic.ErrGatewayPerfNotConfigured},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := newGatewayPerfQUICAdapter(&fakeGatewayPerf{err: tc.backend})
			_, err := adapter.PerfFlows(context.Background(), "", 5, true)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestQUICPerfDatapath(t *testing.T) {
	backend := &fakeGatewayPerf{datapathResult: perf.DatapathResult{
		Hits: 1, Missed: 2, Lost: 3, OffloadedFlowCount: 4,
		HWOffloadEnabled: true, DatapathType: "system", Bridge: "br-b",
	}}
	adapter := newGatewayPerfQUICAdapter(backend)

	info, err := adapter.PerfDatapath(context.Background(), "br-b")
	if err != nil {
		t.Fatalf("PerfDatapath: %v", err)
	}
	if info.Hits != 1 || info.Misses != 2 || info.Lost != 3 || info.OffloadedFlowCount != 4 {
		t.Errorf("info = %+v", info)
	}
	if !info.HwOffloadEnabled || info.DatapathType != "system" || info.Bridge != "br-b" {
		t.Errorf("info = %+v", info)
	}
}

func TestQUICPerfConntrack(t *testing.T) {
	backend := &fakeGatewayPerf{conntrackResult: perf.ConntrackResult{
		TotalEntries: 2,
		PerZone:      map[int]int{5: 2},
	}}
	adapter := newGatewayPerfQUICAdapter(backend)

	zone := uint32(5)
	info, err := adapter.PerfConntrack(context.Background(), &zone)
	if err != nil {
		t.Fatalf("PerfConntrack: %v", err)
	}
	if info.TotalEntries != 2 || info.PerZone[5] != 2 {
		t.Errorf("info = %+v", info)
	}
	if backend.lastZone != 5 {
		t.Errorf("zone = %d, want 5", backend.lastZone)
	}
}

func TestQUICPerfConntrackNilZone(t *testing.T) {
	backend := &fakeGatewayPerf{}
	adapter := newGatewayPerfQUICAdapter(backend)

	if _, err := adapter.PerfConntrack(context.Background(), nil); err != nil {
		t.Fatalf("PerfConntrack: %v", err)
	}
	if backend.lastZone != -1 {
		t.Errorf("zone = %d, want -1", backend.lastZone)
	}
}

// =============================================================================
// MCP perf providers
// =============================================================================

func TestMCPServiceProviderGatewayPerf(t *testing.T) {
	provider := &MCPServiceProvider{}
	provider.SetGatewayPerf(&fakeGatewayPerf{
		flowsResult:     perf.FlowsResult{Installed: 10, Duration: time.Millisecond, Batched: true, Bridge: "br-int"},
		conntrackResult: perf.ConntrackResult{TotalEntries: 1, PerZone: map[int]int{0: 1}},
	})

	if result, err := provider.GatewayPerfFlows(context.Background(), "br-int", 10, true); err != nil || result == nil {
		t.Fatalf("GatewayPerfFlows: result=%v err=%v", result, err)
	}
	if result, err := provider.GatewayPerfDatapath(context.Background(), ""); err != nil || result == nil {
		t.Fatalf("GatewayPerfDatapath: result=%v err=%v", result, err)
	}
	if result, err := provider.GatewayPerfConntrack(context.Background(), -1); err != nil || result == nil {
		t.Fatalf("GatewayPerfConntrack: result=%v err=%v", result, err)
	}
}

func TestMCPServiceProviderGatewayPerfUnavailable(t *testing.T) {
	provider := &MCPServiceProvider{}

	if _, err := provider.GatewayPerfFlows(context.Background(), "", 10, false); err == nil {
		t.Fatal("expected ErrServiceNotAvailable")
	}
	if _, err := provider.GatewayPerfDatapath(context.Background(), ""); err == nil {
		t.Fatal("expected ErrServiceNotAvailable")
	}
	if _, err := provider.GatewayPerfConntrack(context.Background(), -1); err == nil {
		t.Fatal("expected ErrServiceNotAvailable")
	}
}

func TestPlatformServiceProviderGatewayPerf(t *testing.T) {
	provider := &PlatformServiceProvider{}
	provider.SetGatewayPerf(&fakeGatewayPerf{})

	if _, err := provider.GatewayPerfFlows(context.Background(), "", 5, false); err != nil {
		t.Fatalf("GatewayPerfFlows: %v", err)
	}
	if _, err := provider.GatewayPerfDatapath(context.Background(), ""); err != nil {
		t.Fatalf("GatewayPerfDatapath: %v", err)
	}
	if _, err := provider.GatewayPerfConntrack(context.Background(), 3); err != nil {
		t.Fatalf("GatewayPerfConntrack: %v", err)
	}
}

func TestPlatformServiceProviderGatewayPerfUnavailable(t *testing.T) {
	provider := &PlatformServiceProvider{}

	if _, err := provider.GatewayPerfFlows(context.Background(), "", 5, false); err == nil {
		t.Fatal("expected ErrServiceNotAvailable")
	}
}
