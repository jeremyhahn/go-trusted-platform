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

package perf

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// errBoom is the sentinel failure injected by the fakes.
var errBoom = errors.New("boom")

// TestFlowTableAboveThePipeline pins that the perf table stays clear of the
// gateway pipeline: a pipeline that grows into it would let a measurement
// run program flows production traffic reaches.
func TestFlowTableAboveThePipeline(t *testing.T) {
	if FlowTable <= int(modes.TableLocalDelivery) {
		t.Fatalf("FlowTable %d is inside the gateway pipeline (last table %d)", FlowTable, modes.TableLocalDelivery)
	}
}

// fakeFlowClient implements FlowClient with programmable behavior.
type fakeFlowClient struct {
	bridges        []*ovs.Bridge
	otherConfig    map[string]string
	addFlowErr     error
	addFlowsErr    error
	deleteErr      error
	listErr        error
	getErr         error
	getBridgeCalls int
	getErrOnCall   int
	configErr      error
	addFlowCalls   int
	addFlowsSize   int
	deleted        []struct{ cookie, mask uint64 }
	added          []*ovs.FlowMod
}

func (f *fakeFlowClient) AddFlow(ctx context.Context, bridge string, flow *ovs.FlowMod) error {
	if f.addFlowErr != nil && f.addFlowCalls > 0 {
		return f.addFlowErr
	}
	f.addFlowCalls++
	f.added = append(f.added, flow)
	return nil
}

func (f *fakeFlowClient) AddFlows(ctx context.Context, bridge string, flows []*ovs.FlowMod) error {
	if f.addFlowsErr != nil {
		return f.addFlowsErr
	}
	f.addFlowsSize = len(flows)
	f.added = append(f.added, flows...)
	return nil
}

func (f *fakeFlowClient) DeleteFlowsByCookie(ctx context.Context, bridge string, cookie, mask uint64) error {
	f.deleted = append(f.deleted, struct{ cookie, mask uint64 }{cookie, mask})
	return f.deleteErr
}

func (f *fakeFlowClient) ListBridges(ctx context.Context) ([]*ovs.Bridge, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.bridges, nil
}

func (f *fakeFlowClient) GetBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	f.getBridgeCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getErrOnCall != 0 && f.getBridgeCalls >= f.getErrOnCall {
		return nil, errBoom
	}
	for _, b := range f.bridges {
		if b.Name == name {
			return b, nil
		}
	}
	return nil, ovs.ErrBridgeNotFound
}

func (f *fakeFlowClient) GetOVSOtherConfig(ctx context.Context) (map[string]string, error) {
	if f.configErr != nil {
		return nil, f.configErr
	}
	return f.otherConfig, nil
}

// fakeAppCtl implements ovs.AppCtlRunner with canned replies.
type fakeAppCtl struct {
	datapathStats string
	offloadedDump string
	conntrackDump string
	err           error
	dumpErr       error
	conntrackZone int
}

func (f *fakeAppCtl) AppCtl(ctx context.Context, method string, args ...string) (string, error) {
	return "", f.err
}

func (f *fakeAppCtl) DumpDatapathFlows(ctx context.Context, filter string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if f.dumpErr != nil {
		return "", f.dumpErr
	}
	return f.offloadedDump, nil
}

func (f *fakeAppCtl) DumpConntrack(ctx context.Context, zone int) (string, error) {
	f.conntrackZone = zone
	if f.err != nil {
		return "", f.err
	}
	return f.conntrackDump, nil
}

func (f *fakeAppCtl) CoverageShow(ctx context.Context) (string, error) { return "", f.err }
func (f *fakeAppCtl) PMDStats(ctx context.Context) (string, error)     { return "", f.err }

func (f *fakeAppCtl) DatapathStats(ctx context.Context) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.datapathStats, nil
}

func testBridges() []*ovs.Bridge {
	return []*ovs.Bridge{
		{Name: "br-zeta", DatapathType: ""},
		{Name: "br-alpha", DatapathType: "netdev"},
	}
}

func TestNewRequiresOVS(t *testing.T) {
	if _, err := New(Deps{}); !errors.Is(err, ErrOVSRequired) {
		t.Fatalf("expected ErrOVSRequired, got %v", err)
	}
}

func TestFlowsBatchMeasuresAndTearsDown(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	svc, err := New(Deps{OVS: fc})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := svc.Flows(context.Background(), "br-zeta", 50, true)
	if err != nil {
		t.Fatalf("Flows: %v", err)
	}
	if result.Installed != 50 || !result.Batched || result.Bridge != "br-zeta" {
		t.Errorf("result = %+v", result)
	}
	if result.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", result.Duration)
	}
	if result.FlowsPerSecond <= 0 {
		t.Errorf("FlowsPerSecond = %v, want > 0", result.FlowsPerSecond)
	}
	if fc.addFlowsSize != 50 {
		t.Errorf("AddFlows batch size = %d, want 50", fc.addFlowsSize)
	}
	if len(fc.deleted) != 1 || fc.deleted[0].cookie != FlowCookie || fc.deleted[0].mask != ^uint64(0) {
		t.Errorf("teardown deletes = %+v", fc.deleted)
	}
	// Every flow lands in the dedicated perf table with the perf cookie
	// and a unique match.
	seen := make(map[string]struct{}, len(fc.added))
	for _, flow := range fc.added {
		if flow.Table != FlowTable || flow.Priority != FlowPriority {
			t.Fatalf("flow placement = %+v", flow)
		}
		if _, dup := seen[flow.Match]; dup {
			t.Fatalf("duplicate match %q", flow.Match)
		}
		seen[flow.Match] = struct{}{}
	}
}

func TestFlowsNonBatchInstallsIndividually(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	svc, err := New(Deps{OVS: fc, Bridge: "br-zeta"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := svc.Flows(context.Background(), "", 10, false)
	if err != nil {
		t.Fatalf("Flows: %v", err)
	}
	if result.Batched {
		t.Error("Batched = true, want false")
	}
	if fc.addFlowCalls != 10 {
		t.Errorf("AddFlow calls = %d, want 10", fc.addFlowCalls)
	}
	if len(fc.deleted) != 1 {
		t.Errorf("teardown deletes = %d, want 1", len(fc.deleted))
	}
}

func TestFlowsInvalidCount(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	svc, _ := New(Deps{OVS: fc})

	for _, count := range []int{0, -1, MaxFlowCount + 1} {
		_, err := svc.Flows(context.Background(), "br-zeta", count, true)
		var countErr *ErrInvalidFlowCount
		if !errors.As(err, &countErr) {
			t.Fatalf("count %d: expected ErrInvalidFlowCount, got %v", count, err)
		}
	}
	if len(fc.deleted) != 0 {
		t.Errorf("teardown ran for rejected counts: %+v", fc.deleted)
	}
}

func TestFlowsInstallFailureStillTearsDown(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges(), addFlowErr: errBoom}
	svc, _ := New(Deps{OVS: fc})

	// Non-batch: first AddFlow succeeds, second fails — partial install.
	_, err := svc.Flows(context.Background(), "br-zeta", 5, false)
	var installErr *ErrFlowInstallFailed
	if !errors.As(err, &installErr) {
		t.Fatalf("expected ErrFlowInstallFailed, got %v", err)
	}
	if len(fc.deleted) != 1 {
		t.Fatalf("teardown deletes = %d, want 1 (must clean partial installs)", len(fc.deleted))
	}
}

func TestFlowsBatchInstallFailure(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges(), addFlowsErr: errBoom}
	svc, _ := New(Deps{OVS: fc})

	_, err := svc.Flows(context.Background(), "br-zeta", 5, true)
	var installErr *ErrFlowInstallFailed
	if !errors.As(err, &installErr) {
		t.Fatalf("expected ErrFlowInstallFailed, got %v", err)
	}
	if len(fc.deleted) != 1 {
		t.Fatalf("teardown deletes = %d, want 1", len(fc.deleted))
	}
}

func TestFlowsTeardownFailureSurfaces(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges(), deleteErr: errBoom}
	svc, _ := New(Deps{OVS: fc})

	_, err := svc.Flows(context.Background(), "br-zeta", 5, true)
	var teardownErr *ErrFlowTeardownFailed
	if !errors.As(err, &teardownErr) {
		t.Fatalf("expected ErrFlowTeardownFailed, got %v", err)
	}
}

func TestFlowsUnknownBridge(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	svc, _ := New(Deps{OVS: fc})

	_, err := svc.Flows(context.Background(), "br-missing", 5, true)
	var bridgeErr *ErrBridgeUnavailable
	if !errors.As(err, &bridgeErr) {
		t.Fatalf("expected ErrBridgeUnavailable, got %v", err)
	}
	if !errors.Is(err, ovs.ErrBridgeNotFound) {
		t.Errorf("cause should be ErrBridgeNotFound, got %v", err)
	}
}

func TestResolveBridgeFirstSorted(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	svc, _ := New(Deps{OVS: fc})

	result, err := svc.Flows(context.Background(), "", 1, true)
	if err != nil {
		t.Fatalf("Flows: %v", err)
	}
	if result.Bridge != "br-alpha" {
		t.Errorf("Bridge = %q, want br-alpha (sorted first)", result.Bridge)
	}
}

func TestResolveBridgeNoneAvailable(t *testing.T) {
	fc := &fakeFlowClient{}
	svc, _ := New(Deps{OVS: fc})

	if _, err := svc.Flows(context.Background(), "", 1, true); !errors.Is(err, ErrNoBridgeAvailable) {
		t.Fatalf("expected ErrNoBridgeAvailable, got %v", err)
	}
}

func TestResolveBridgeListFailure(t *testing.T) {
	fc := &fakeFlowClient{listErr: errBoom}
	svc, _ := New(Deps{OVS: fc})

	_, err := svc.Flows(context.Background(), "", 1, true)
	var bridgeErr *ErrBridgeUnavailable
	if !errors.As(err, &bridgeErr) {
		t.Fatalf("expected ErrBridgeUnavailable, got %v", err)
	}
}

const testDatapathStats = `system@ovs-system:
  lookups: hit:5000 missed:20 lost:1
  flows: 12`

const testOffloadedDump = `recirc_id(0),in_port(2),eth_type(0x0800),ipv4(frag=no), packets:10, bytes:800, used:0.1s, offloaded:yes, dp:tc, actions:3
recirc_id(0),in_port(3),eth_type(0x0800),ipv4(frag=no), packets:11, bytes:900, used:0.1s, offloaded:yes, dp:tc, actions:2
recirc_id(0),in_port(4),eth_type(0x0800),ipv4(frag=no), packets:12, bytes:950, used:0.1s, offloaded:yes, dp:tc, actions:5`

const testConntrackDump = `tcp,orig=(src=10.0.1.5,dst=10.100.0.10,sport=1,dport=443),reply=(src=10.0.2.7,dst=10.0.1.5,sport=8443,dport=1),zone=12,protoinfo=(state=ESTABLISHED)
tcp,orig=(src=10.0.1.6,dst=10.100.0.10,sport=2,dport=443),reply=(src=10.0.2.8,dst=10.0.1.6,sport=8443,dport=2),zone=12,protoinfo=(state=ESTABLISHED)
udp,orig=(src=10.0.1.5,dst=10.0.3.9,sport=5353,dport=53),reply=(src=10.0.3.9,dst=10.0.1.5,sport=53,dport=5353),zone=7`

func TestDatapath(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges(), otherConfig: map[string]string{"hw-offload": "true"}}
	ac := &fakeAppCtl{datapathStats: testDatapathStats, offloadedDump: testOffloadedDump}
	svc, _ := New(Deps{OVS: fc, AppCtl: ac})

	result, err := svc.Datapath(context.Background(), "br-zeta")
	if err != nil {
		t.Fatalf("Datapath: %v", err)
	}
	if result.Hits != 5000 || result.Missed != 20 || result.Lost != 1 {
		t.Errorf("counters = %+v", result)
	}
	if result.OffloadedFlowCount != 3 {
		t.Errorf("OffloadedFlowCount = %d, want 3", result.OffloadedFlowCount)
	}
	if !result.HWOffloadEnabled {
		t.Error("HWOffloadEnabled = false, want true")
	}
	// br-zeta has empty datapath_type, which normalizes to "system".
	if result.DatapathType != "system" {
		t.Errorf("DatapathType = %q, want system", result.DatapathType)
	}
}

func TestDatapathNetdevType(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges(), otherConfig: map[string]string{}}
	ac := &fakeAppCtl{datapathStats: testDatapathStats, offloadedDump: ""}
	svc, _ := New(Deps{OVS: fc, AppCtl: ac})

	result, err := svc.Datapath(context.Background(), "br-alpha")
	if err != nil {
		t.Fatalf("Datapath: %v", err)
	}
	if result.DatapathType != "netdev" {
		t.Errorf("DatapathType = %q, want netdev", result.DatapathType)
	}
	if result.HWOffloadEnabled {
		t.Error("HWOffloadEnabled = true, want false")
	}
	if result.OffloadedFlowCount != 0 {
		t.Errorf("OffloadedFlowCount = %d, want 0", result.OffloadedFlowCount)
	}
}

func TestDatapathWithoutAppCtl(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	svc, _ := New(Deps{OVS: fc})

	if _, err := svc.Datapath(context.Background(), "br-zeta"); !errors.Is(err, ErrAppCtlUnavailable) {
		t.Fatalf("expected ErrAppCtlUnavailable, got %v", err)
	}
}

func TestDatapathAppCtlFailure(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	ac := &fakeAppCtl{err: errBoom}
	svc, _ := New(Deps{OVS: fc, AppCtl: ac})

	if _, err := svc.Datapath(context.Background(), "br-zeta"); !errors.Is(err, errBoom) {
		t.Fatalf("expected boom, got %v", err)
	}
}

func TestDatapathOtherConfigFailure(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges(), configErr: errBoom}
	ac := &fakeAppCtl{datapathStats: testDatapathStats, offloadedDump: ""}
	svc, _ := New(Deps{OVS: fc, AppCtl: ac})

	if _, err := svc.Datapath(context.Background(), "br-zeta"); !errors.Is(err, errBoom) {
		t.Fatalf("expected boom, got %v", err)
	}
}

func TestConntrackAllZones(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	ac := &fakeAppCtl{conntrackDump: testConntrackDump}
	svc, _ := New(Deps{OVS: fc, AppCtl: ac})

	result, err := svc.Conntrack(context.Background(), -1)
	if err != nil {
		t.Fatalf("Conntrack: %v", err)
	}
	if result.TotalEntries != 3 {
		t.Errorf("TotalEntries = %d, want 3", result.TotalEntries)
	}
	if result.PerZone[12] != 2 || result.PerZone[7] != 1 {
		t.Errorf("PerZone = %+v", result.PerZone)
	}
	if ac.conntrackZone != -1 {
		t.Errorf("zone passed to appctl = %d, want -1", ac.conntrackZone)
	}
}

func TestConntrackSpecificZone(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	ac := &fakeAppCtl{conntrackDump: testConntrackDump}
	svc, _ := New(Deps{OVS: fc, AppCtl: ac})

	if _, err := svc.Conntrack(context.Background(), 12); err != nil {
		t.Fatalf("Conntrack: %v", err)
	}
	if ac.conntrackZone != 12 {
		t.Errorf("zone passed to appctl = %d, want 12", ac.conntrackZone)
	}
}

func TestConntrackWithoutAppCtl(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	svc, _ := New(Deps{OVS: fc})

	if _, err := svc.Conntrack(context.Background(), -1); !errors.Is(err, ErrAppCtlUnavailable) {
		t.Fatalf("expected ErrAppCtlUnavailable, got %v", err)
	}
}

func TestConntrackDumpFailure(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	ac := &fakeAppCtl{err: errBoom}
	svc, _ := New(Deps{OVS: fc, AppCtl: ac})

	if _, err := svc.Conntrack(context.Background(), -1); !errors.Is(err, errBoom) {
		t.Fatalf("expected boom, got %v", err)
	}
}

func TestDatapathOffloadedDumpFailure(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	ac := &fakeAppCtl{datapathStats: testDatapathStats, dumpErr: errBoom}
	svc, _ := New(Deps{OVS: fc, AppCtl: ac})

	if _, err := svc.Datapath(context.Background(), "br-zeta"); !errors.Is(err, errBoom) {
		t.Fatalf("expected boom from offloaded dump, got %v", err)
	}
}

func TestDatapathBridgeRowFailure(t *testing.T) {
	// The bridge resolves on the first GetBridge call, then the second
	// call (reading datapath_type) fails.
	fc := &fakeFlowClient{bridges: testBridges(), otherConfig: map[string]string{}, getErrOnCall: 2}
	ac := &fakeAppCtl{datapathStats: testDatapathStats}
	svc, _ := New(Deps{OVS: fc, AppCtl: ac})

	if _, err := svc.Datapath(context.Background(), "br-zeta"); !errors.Is(err, errBoom) {
		t.Fatalf("expected boom from bridge row read, got %v", err)
	}
}

func TestDatapathStatsParseFailure(t *testing.T) {
	fc := &fakeFlowClient{bridges: testBridges()}
	ac := &fakeAppCtl{datapathStats: "garbage with no counters"}
	svc, _ := New(Deps{OVS: fc, AppCtl: ac})

	var parseErr *ovs.ErrDatapathStatsUnparseable
	if _, err := svc.Datapath(context.Background(), "br-zeta"); !errors.As(err, &parseErr) {
		t.Fatalf("expected ErrDatapathStatsUnparseable, got %v", err)
	}
}

func TestTypedErrorMessages(t *testing.T) {
	countErr := &ErrInvalidFlowCount{Count: -3, Max: MaxFlowCount}
	if !strings.Contains(countErr.Error(), "-3") {
		t.Errorf("count error message = %q", countErr.Error())
	}

	bridgeErr := &ErrBridgeUnavailable{Bridge: "br-x", Cause: errBoom}
	if !strings.Contains(bridgeErr.Error(), "br-x") || !errors.Is(bridgeErr, errBoom) {
		t.Errorf("bridge error = %q", bridgeErr.Error())
	}
	discoveryErr := &ErrBridgeUnavailable{Cause: errBoom}
	if !strings.Contains(discoveryErr.Error(), "discovery") {
		t.Errorf("discovery error = %q", discoveryErr.Error())
	}

	installErr := &ErrFlowInstallFailed{Bridge: "br-y", Cause: errBoom}
	if !strings.Contains(installErr.Error(), "br-y") || !errors.Is(installErr, errBoom) {
		t.Errorf("install error = %q", installErr.Error())
	}

	teardownErr := &ErrFlowTeardownFailed{Bridge: "br-z", Cause: errBoom}
	if !strings.Contains(teardownErr.Error(), "br-z") || !errors.Is(teardownErr, errBoom) {
		t.Errorf("teardown error = %q", teardownErr.Error())
	}
}
