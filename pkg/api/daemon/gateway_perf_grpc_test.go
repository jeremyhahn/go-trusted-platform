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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeGatewayPerf implements GatewayPerfInterface with programmable
// behavior.
type fakeGatewayPerf struct {
	flowsResult     perf.FlowsResult
	datapathResult  perf.DatapathResult
	conntrackResult perf.ConntrackResult
	err             error

	lastBridge string
	lastCount  int
	lastBatch  bool
	lastZone   int
}

func (f *fakeGatewayPerf) Flows(ctx context.Context, bridge string, count int, batch bool) (perf.FlowsResult, error) {
	f.lastBridge = bridge
	f.lastCount = count
	f.lastBatch = batch
	if f.err != nil {
		return perf.FlowsResult{}, f.err
	}
	return f.flowsResult, nil
}

func (f *fakeGatewayPerf) Datapath(ctx context.Context, bridge string) (perf.DatapathResult, error) {
	f.lastBridge = bridge
	if f.err != nil {
		return perf.DatapathResult{}, f.err
	}
	return f.datapathResult, nil
}

func (f *fakeGatewayPerf) Conntrack(ctx context.Context, zone int) (perf.ConntrackResult, error) {
	f.lastZone = zone
	if f.err != nil {
		return perf.ConntrackResult{}, f.err
	}
	return f.conntrackResult, nil
}

// newPerfTestService builds a GatewayService with a fake perf backend.
func newPerfTestService() (*GatewayService, *fakeGatewayPerf) {
	backend := &fakeGatewayPerf{}
	return NewGatewayService(WithPerf(backend)), backend
}

func TestGetPerfFlows(t *testing.T) {
	svc, backend := newPerfTestService()
	backend.flowsResult = perf.FlowsResult{
		Installed:      500,
		Duration:       2 * time.Millisecond,
		FlowsPerSecond: 250000,
		Batched:        true,
		Bridge:         "br-int",
	}

	resp, err := svc.GetPerfFlows(context.Background(), &platformv1.GetPerfFlowsRequest{
		Count:  500,
		Batch:  true,
		Bridge: "br-int",
	})
	if err != nil {
		t.Fatalf("GetPerfFlows: %v", err)
	}
	if resp.GetInstalled() != 500 || !resp.GetBatched() || resp.GetBridge() != "br-int" {
		t.Errorf("resp = %+v", resp)
	}
	if resp.GetDurationNs() != (2 * time.Millisecond).Nanoseconds() {
		t.Errorf("DurationNs = %d", resp.GetDurationNs())
	}
	if resp.GetFlowsPerSecond() != 250000 {
		t.Errorf("FlowsPerSecond = %v", resp.GetFlowsPerSecond())
	}
	if backend.lastCount != 500 || !backend.lastBatch || backend.lastBridge != "br-int" {
		t.Errorf("backend received count=%d batch=%v bridge=%q",
			backend.lastCount, backend.lastBatch, backend.lastBridge)
	}
}

func TestGetPerfFlowsDefaultCount(t *testing.T) {
	svc, backend := newPerfTestService()

	if _, err := svc.GetPerfFlows(context.Background(), &platformv1.GetPerfFlowsRequest{}); err != nil {
		t.Fatalf("GetPerfFlows: %v", err)
	}
	if backend.lastCount != perf.DefaultFlowCount {
		t.Errorf("default count = %d, want %d", backend.lastCount, perf.DefaultFlowCount)
	}
}

func TestGetPerfFlowsErrors(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		svc := NewGatewayService()
		_, err := svc.GetPerfFlows(context.Background(), &platformv1.GetPerfFlowsRequest{Count: 10})
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
	})

	t.Run("invalid count", func(t *testing.T) {
		svc, backend := newPerfTestService()
		backend.err = &perf.ErrInvalidFlowCount{Count: -1, Max: perf.MaxFlowCount}
		_, err := svc.GetPerfFlows(context.Background(), &platformv1.GetPerfFlowsRequest{Count: 10})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
		}
	})

	t.Run("bridge not found", func(t *testing.T) {
		svc, backend := newPerfTestService()
		backend.err = &perf.ErrBridgeUnavailable{Bridge: "br-x", Cause: errors.New("no row")}
		_, err := svc.GetPerfFlows(context.Background(), &platformv1.GetPerfFlowsRequest{Count: 10})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("code = %v, want NotFound", status.Code(err))
		}
	})

	t.Run("no bridges", func(t *testing.T) {
		svc, backend := newPerfTestService()
		backend.err = perf.ErrNoBridgeAvailable
		_, err := svc.GetPerfFlows(context.Background(), &platformv1.GetPerfFlowsRequest{Count: 10})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
		}
	})

	t.Run("internal", func(t *testing.T) {
		svc, backend := newPerfTestService()
		backend.err = errors.New("boom")
		_, err := svc.GetPerfFlows(context.Background(), &platformv1.GetPerfFlowsRequest{Count: 10})
		if status.Code(err) != codes.Internal {
			t.Fatalf("code = %v, want Internal", status.Code(err))
		}
	})
}

func TestGetPerfDatapath(t *testing.T) {
	svc, backend := newPerfTestService()
	backend.datapathResult = perf.DatapathResult{
		Hits:               5000,
		Missed:             20,
		Lost:               1,
		OffloadedFlowCount: 3,
		HWOffloadEnabled:   true,
		DatapathType:       "system",
		Bridge:             "br-int",
	}

	resp, err := svc.GetPerfDatapath(context.Background(), &platformv1.GetPerfDatapathRequest{Bridge: "br-int"})
	if err != nil {
		t.Fatalf("GetPerfDatapath: %v", err)
	}
	if resp.GetHits() != 5000 || resp.GetMisses() != 20 || resp.GetLost() != 1 {
		t.Errorf("counters = %+v", resp)
	}
	if resp.GetOffloadedFlowCount() != 3 || !resp.GetHwOffloadEnabled() {
		t.Errorf("offload = %+v", resp)
	}
	if resp.GetDatapathType() != "system" || resp.GetBridge() != "br-int" {
		t.Errorf("bridge info = %+v", resp)
	}
}

func TestGetPerfDatapathErrors(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		svc := NewGatewayService()
		_, err := svc.GetPerfDatapath(context.Background(), &platformv1.GetPerfDatapathRequest{})
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
	})

	t.Run("appctl unavailable", func(t *testing.T) {
		svc, backend := newPerfTestService()
		backend.err = perf.ErrAppCtlUnavailable
		_, err := svc.GetPerfDatapath(context.Background(), &platformv1.GetPerfDatapathRequest{})
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
	})
}

func TestGetPerfConntrack(t *testing.T) {
	svc, backend := newPerfTestService()
	backend.conntrackResult = perf.ConntrackResult{
		TotalEntries: 4,
		PerZone:      map[int]int{12: 2, 7: 1, 0: 1},
	}

	zone := uint32(12)
	resp, err := svc.GetPerfConntrack(context.Background(), &platformv1.GetPerfConntrackRequest{Zone: &zone})
	if err != nil {
		t.Fatalf("GetPerfConntrack: %v", err)
	}
	if resp.GetTotalEntries() != 4 {
		t.Errorf("TotalEntries = %d", resp.GetTotalEntries())
	}
	if resp.GetPerZone()[12] != 2 || resp.GetPerZone()[7] != 1 || resp.GetPerZone()[0] != 1 {
		t.Errorf("PerZone = %v", resp.GetPerZone())
	}
	if backend.lastZone != 12 {
		t.Errorf("backend zone = %d, want 12", backend.lastZone)
	}
}

func TestGetPerfConntrackAllZones(t *testing.T) {
	svc, backend := newPerfTestService()
	backend.lastZone = 99

	if _, err := svc.GetPerfConntrack(context.Background(), &platformv1.GetPerfConntrackRequest{}); err != nil {
		t.Fatalf("GetPerfConntrack: %v", err)
	}
	if backend.lastZone != -1 {
		t.Errorf("backend zone = %d, want -1 (all zones)", backend.lastZone)
	}
}

func TestGetPerfConntrackErrors(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		svc := NewGatewayService()
		_, err := svc.GetPerfConntrack(context.Background(), &platformv1.GetPerfConntrackRequest{})
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
	})

	t.Run("internal", func(t *testing.T) {
		svc, backend := newPerfTestService()
		backend.err = errors.New("boom")
		_, err := svc.GetPerfConntrack(context.Background(), &platformv1.GetPerfConntrackRequest{})
		if status.Code(err) != codes.Internal {
			t.Fatalf("code = %v, want Internal", status.Code(err))
		}
	})
}
