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

package loadbalancer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ct"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// fakeController records installed flow batches and injects failures.
type fakeController struct {
	mu         sync.Mutex
	batches    [][]zoneflows.FlowRule
	installErr error
	// failOnCall fails only the n-th InstallFlows call (1-based) with
	// installErr; zero fails every call while installErr is set.
	failOnCall int
	calls      int
}

func (f *fakeController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	return f.InstallFlows(bridgeName, []zoneflows.FlowRule{{Priority: priority, Match: match, Actions: actions}})
}

func (f *fakeController) InstallFlows(bridgeName string, rules []zoneflows.FlowRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.installErr != nil && (f.failOnCall == 0 || f.failOnCall == f.calls) {
		return f.installErr
	}
	f.batches = append(f.batches, rules)
	return nil
}

func (f *fakeController) DeleteFlow(bridgeName string, match string) error         { return nil }
func (f *fakeController) DeleteFlowsByPort(bridgeName string, portID string) error { return nil }
func (f *fakeController) ListFlows(bridgeName string) ([]string, error)            { return nil, nil }

// allRules flattens the recorded batches.
func (f *fakeController) allRules() []zoneflows.FlowRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []zoneflows.FlowRule
	for _, batch := range f.batches {
		out = append(out, batch...)
	}
	return out
}

// fakeOVS overrides only the client methods the service uses; any other
// call panics via the embedded nil interface, flagging an unexpected
// dependency.
type fakeOVS struct {
	ovs.ClientInterface

	mu            sync.Mutex
	strictDeletes []*ovs.FlowMod
	cookieDeletes []uint64
	strictErr     error
	cookieErr     error
}

func (f *fakeOVS) DeleteFlowStrict(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.strictErr != nil {
		return f.strictErr
	}
	f.strictDeletes = append(f.strictDeletes, flow)
	return nil
}

func (f *fakeOVS) DeleteFlowsByCookie(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cookieErr != nil {
		return f.cookieErr
	}
	f.cookieDeletes = append(f.cookieDeletes, cookie)
	return nil
}

// fakeGroups records group table programming and injects failures.
type fakeGroups struct {
	mu        sync.Mutex
	groups    map[uint32]*openflow.GroupMod
	descs     []openflow.GroupDesc
	addErr    error
	failAddOn int // fail only the n-th AddGroup (1-based); zero fails every one
	addCalls  int
	failDelOn int // fail only the n-th DeleteGroup (1-based); zero fails every one
	delCalls  int
	modErr    error
	delErr    error
	descErr   error
	deleted   []uint32
	modifies  int
	additions int
}

func newFakeGroups() *fakeGroups {
	return &fakeGroups{groups: make(map[uint32]*openflow.GroupMod)}
}

func (f *fakeGroups) AddGroup(ctx context.Context, bridgeName string, group *openflow.GroupMod) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCalls++
	if f.addErr != nil && (f.failAddOn == 0 || f.failAddOn == f.addCalls) {
		return f.addErr
	}
	f.groups[group.GroupID] = group
	f.additions++
	return nil
}

func (f *fakeGroups) ModifyGroup(ctx context.Context, bridgeName string, group *openflow.GroupMod) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.modErr != nil {
		return f.modErr
	}
	f.groups[group.GroupID] = group
	f.modifies++
	return nil
}

func (f *fakeGroups) DeleteGroup(ctx context.Context, bridgeName string, groupID uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delCalls++
	if f.delErr != nil && (f.failDelOn == 0 || f.failDelOn == f.delCalls) {
		return f.delErr
	}
	delete(f.groups, groupID)
	f.deleted = append(f.deleted, groupID)
	return nil
}

func (f *fakeGroups) GetGroupDesc(ctx context.Context, bridgeName string) ([]openflow.GroupDesc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.descErr != nil {
		return nil, f.descErr
	}
	return f.descs, nil
}

// bucketCount returns the bucket count of a programmed group.
func (f *fakeGroups) bucketCount(groupID uint32) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.groups[groupID]
	if !ok {
		return -1
	}
	return len(g.Buckets)
}

// testVIP builds a two-backend TCP VIP.
func testVIP() VIP {
	return VIP{
		Address:  netip.MustParseAddr("10.100.0.10"),
		Port:     443,
		Protocol: ProtocolTCP,
		Backends: []Backend{
			{Address: netip.MustParseAddr("10.0.1.5"), Port: 8443, Weight: 2},
			{Address: netip.MustParseAddr("10.0.1.6"), Port: 8443},
		},
	}
}

// testDeps builds a full fake dependency set with one configured VIP.
func testDeps(vips ...VIP) (Deps, *fakeController, *fakeOVS, *fakeGroups) {
	controller := &fakeController{}
	ovsClient := &fakeOVS{}
	groups := newFakeGroups()
	deps := Deps{
		Controller: controller,
		OVS:        ovsClient,
		Groups:     groups,
		Allocator:  ct.NewZoneAllocator(nil),
		Config: Config{
			Bridge:              "br-test",
			Algorithm:           AlgorithmHash,
			HealthCheckInterval: time.Hour,
			HealthCheckTimeout:  time.Second,
			MaxBackends:         8,
			VIPs:                vips,
		},
	}
	return deps, controller, ovsClient, groups
}

// startService builds and starts a service, failing the test on error.
func startService(t *testing.T, deps Deps) *Service {
	t.Helper()
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if svc.Active() {
			if err := svc.Stop(context.Background()); err != nil {
				t.Fatalf("Stop: %v", err)
			}
		}
	})
	return svc
}

func TestNewValidatesDeps(t *testing.T) {
	base, _, _, _ := testDeps()

	tests := []struct {
		name    string
		mutate  func(*Deps)
		wantErr error
	}{
		{"nil controller", func(d *Deps) { d.Controller = nil }, ErrNilController},
		{"nil ovs", func(d *Deps) { d.OVS = nil }, ErrNilOVSClient},
		{"nil groups", func(d *Deps) { d.Groups = nil }, ErrNilGroupClient},
		{"nil allocator", func(d *Deps) { d.Allocator = nil }, ErrNilAllocator},
		{"empty bridge", func(d *Deps) { d.Config.Bridge = "" }, ErrEmptyBridge},
		{"bad algorithm", func(d *Deps) { d.Config.Algorithm = "least-conn" }, ErrAlgorithmUnsupported},
		{"bad health check", func(d *Deps) { d.Config.HealthCheckTimeout = 0 }, ErrInvalidHealthCheck},
		{"inverted health check", func(d *Deps) {
			d.Config.HealthCheckInterval = time.Second
			d.Config.HealthCheckTimeout = time.Second
		}, ErrInvalidHealthCheck},
		{"negative rise", func(d *Deps) { d.Config.Rise = -1 }, ErrInvalidHealthCheck},
		{"bad max backends", func(d *Deps) { d.Config.MaxBackends = -1 }, ErrInvalidMaxBackends},
		{"invalid vip", func(d *Deps) { d.Config.VIPs = []VIP{{}} }, ErrInvalidVIPAddress},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := base
			tt.mutate(&deps)
			if _, err := New(deps); !errors.Is(err, tt.wantErr) {
				t.Fatalf("New error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	deps, _, _, _ := testDeps()
	deps.Config.Algorithm = ""
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc.cfg.Algorithm != AlgorithmHash {
		t.Errorf("Algorithm = %q, want %q", svc.cfg.Algorithm, AlgorithmHash)
	}
	if svc.cfg.Rise != DefaultRise || svc.cfg.Fall != DefaultFall {
		t.Errorf("Rise/Fall = %d/%d, want %d/%d", svc.cfg.Rise, svc.cfg.Fall, DefaultRise, DefaultFall)
	}
}

func TestStartInstallsPipeline(t *testing.T) {
	deps, controller, _, groups := testDeps(testVIP())
	svc := startService(t, deps)

	rules := controller.allRules()

	// Gate: table 10 priority 3 -> table 20, installed last.
	last := rules[len(rules)-1]
	if last.Table != 10 || last.Priority != lbGatePriority || last.Actions != "goto_table:20" {
		t.Errorf("gate rule = %+v", last)
	}

	var haveDivert, haveDispatch, haveMissT26 bool
	for _, r := range rules {
		if r.Table == 20 && r.Priority == prioLBDivert &&
			strings.Contains(r.Match, "nw_dst=10.100.0.10") && strings.Contains(r.Match, "tp_dst=443") {
			haveDivert = true
			if !strings.Contains(r.Actions, "ct(table=26,zone=") || !strings.HasSuffix(r.Actions, ",nat)") {
				t.Errorf("divert actions = %q", r.Actions)
			}
		}
		if r.Table == 26 && r.Priority == prioLBDispatch && strings.HasPrefix(r.Match, "ct_state=+new+trk,") {
			haveDispatch = true
			if !strings.HasPrefix(r.Actions, "group:") {
				t.Errorf("dispatch actions = %q", r.Actions)
			}
		}
		// The table-20 miss is the gateway pipeline's; a load balancer
		// copy is the same OpenFlow flow, which its Stop would delete
		// from under every other service gating into table 20 (#614).
		if r.Table == 20 && r.Match == "" {
			t.Errorf("load balancer installs an empty-match table-20 flow %+v; the miss belongs to the pipeline", r)
		}
		if r.Table == 26 && r.Priority == prioLBMissT26 && r.Actions == "drop" {
			haveMissT26 = true
		}
		if r.Cookie != fmt.Sprintf("0x%x", CookieLoadBalancer) {
			t.Errorf("rule %+v missing LB cookie", r)
		}
	}
	if !haveDivert || !haveDispatch || !haveMissT26 {
		t.Errorf("missing pipeline flows: divert=%v dispatch=%v missT26=%v",
			haveDivert, haveDispatch, haveMissT26)
	}
	assertReplyPath(t, svc, rules, testVIP())

	// One select group with one bucket per backend.
	status, err := svc.GetVIP(ProtocolTCP, netip.MustParseAddrPort("10.100.0.10:443"))
	if err != nil {
		t.Fatalf("GetVIP: %v", err)
	}
	if status.GroupID&GroupIDMask != GroupIDBase {
		t.Errorf("group ID 0x%x outside LB range", status.GroupID)
	}
	if got := groups.bucketCount(status.GroupID); got != 2 {
		t.Errorf("bucket count = %d, want 2", got)
	}
	if status.CTZone == 0 {
		t.Error("CT zone not allocated")
	}
}

func TestStartErrors(t *testing.T) {
	t.Run("already started", func(t *testing.T) {
		deps, _, _, _ := testDeps()
		svc := startService(t, deps)
		if err := svc.Start(context.Background()); !errors.Is(err, ErrAlreadyStarted) {
			t.Fatalf("Start = %v, want ErrAlreadyStarted", err)
		}
	})

	t.Run("group desc failure", func(t *testing.T) {
		deps, _, _, groups := testDeps()
		groups.descErr = errors.New("of down")
		svc, err := New(deps)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		var opErr *OpError
		if err := svc.Start(context.Background()); !errors.As(err, &opErr) || opErr.Op != "group-desc" {
			t.Fatalf("Start = %v, want group-desc OpError", err)
		}
	})

	t.Run("group add failure", func(t *testing.T) {
		deps, _, _, groups := testDeps(testVIP())
		groups.addErr = errors.New("group rejected")
		svc, err := New(deps)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		var opErr *OpError
		if err := svc.Start(context.Background()); !errors.As(err, &opErr) || opErr.Op != "group-add" {
			t.Fatalf("Start = %v, want group-add OpError", err)
		}
	})

	t.Run("flow install failure", func(t *testing.T) {
		deps, controller, _, _ := testDeps(testVIP())
		controller.installErr = errors.New("switch rejected")
		svc, err := New(deps)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		var opErr *OpError
		if err := svc.Start(context.Background()); !errors.As(err, &opErr) || opErr.Op != "install" {
			t.Fatalf("Start = %v, want install OpError", err)
		}
	})
}

func TestStartRecoversExistingGroupsAndPrunesStale(t *testing.T) {
	deps, _, _, groups := testDeps(testVIP())

	// Compute the deterministic ID the VIP will claim so the fake can
	// pre-populate it (simulating a daemon restart) plus one stale group.
	probe, err := New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	claimedID, err := probe.groupIDFor(testVIP().key())
	if err != nil {
		t.Fatalf("groupIDFor: %v", err)
	}
	staleID := GroupIDBase | 0xBEEF
	if staleID == claimedID {
		staleID = GroupIDBase | 0xBEE0
	}
	foreignID := uint32(7) // outside the LB range: must never be touched
	groups.descs = []openflow.GroupDesc{
		{GroupID: claimedID}, {GroupID: staleID}, {GroupID: foreignID},
	}
	groups.groups[claimedID] = openflow.NewGroupMod(openflow.OFPGCAdd, openflow.OFPGTSelect, claimedID)
	groups.groups[staleID] = openflow.NewGroupMod(openflow.OFPGCAdd, openflow.OFPGTSelect, staleID)
	groups.groups[foreignID] = openflow.NewGroupMod(openflow.OFPGCAdd, openflow.OFPGTAll, foreignID)

	startService(t, deps)

	groups.mu.Lock()
	defer groups.mu.Unlock()
	if groups.additions != 0 {
		t.Errorf("additions = %d, want 0 (existing group must be modified)", groups.additions)
	}
	if groups.modifies == 0 {
		t.Error("existing group was not modified")
	}
	if len(groups.deleted) != 1 || groups.deleted[0] != staleID {
		t.Errorf("deleted = %v, want [0x%x]", groups.deleted, staleID)
	}
	if _, ok := groups.groups[foreignID]; !ok {
		t.Error("foreign group outside LB range was deleted")
	}
}

func TestStopTearsDownPipeline(t *testing.T) {
	deps, _, ovsClient, groups := testDeps(testVIP())
	svc := startService(t, deps)

	status, err := svc.GetVIP(ProtocolTCP, netip.MustParseAddrPort("10.100.0.10:443"))
	if err != nil {
		t.Fatalf("GetVIP: %v", err)
	}

	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	ovsClient.mu.Lock()
	if len(ovsClient.strictDeletes) != 1 || ovsClient.strictDeletes[0].Table != 10 {
		t.Errorf("strict deletes = %+v, want single table 10 gate delete", ovsClient.strictDeletes)
	}
	if len(ovsClient.cookieDeletes) != 1 || ovsClient.cookieDeletes[0] != CookieLoadBalancer {
		t.Errorf("cookie deletes = %v", ovsClient.cookieDeletes)
	}
	ovsClient.mu.Unlock()

	if got := groups.bucketCount(status.GroupID); got != -1 {
		t.Errorf("group 0x%x still installed after Stop", status.GroupID)
	}
	if svc.Active() {
		t.Error("service still active after Stop")
	}
}

func TestStopErrors(t *testing.T) {
	t.Run("not started", func(t *testing.T) {
		deps, _, _, _ := testDeps()
		svc, err := New(deps)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := svc.Stop(context.Background()); !errors.Is(err, ErrNotStarted) {
			t.Fatalf("Stop = %v, want ErrNotStarted", err)
		}
	})

	t.Run("gate delete failure", func(t *testing.T) {
		deps, _, ovsClient, _ := testDeps()
		svc := startService(t, deps)
		ovsClient.strictErr = errors.New("of down")
		var opErr *OpError
		if err := svc.Stop(context.Background()); !errors.As(err, &opErr) || opErr.Op != "delete" {
			t.Fatalf("Stop = %v, want delete OpError", err)
		}
		ovsClient.strictErr = nil
	})
}

func TestAddAndRemoveVIP(t *testing.T) {
	deps, _, ovsClient, groups := testDeps()
	svc := startService(t, deps)

	vip := testVIP()
	if err := svc.AddVIP(context.Background(), vip); err != nil {
		t.Fatalf("AddVIP: %v", err)
	}
	if err := svc.AddVIP(context.Background(), vip); !errors.Is(err, ErrVIPExists) {
		t.Fatalf("duplicate AddVIP = %v, want ErrVIPExists", err)
	}

	vips, err := svc.ListVIPs(), error(nil)
	if err != nil || len(vips) != 1 {
		t.Fatalf("ListVIPs = %v (%v)", vips, err)
	}
	if vips[0].VIP.Algorithm != AlgorithmHash {
		t.Errorf("effective algorithm = %q", vips[0].VIP.Algorithm)
	}

	addr := netip.MustParseAddrPort("10.100.0.10:443")
	if err := svc.RemoveVIP(context.Background(), ProtocolTCP, addr); err != nil {
		t.Fatalf("RemoveVIP: %v", err)
	}
	if err := svc.RemoveVIP(context.Background(), ProtocolTCP, addr); !errors.Is(err, ErrVIPNotFound) {
		t.Fatalf("second RemoveVIP = %v, want ErrVIPNotFound", err)
	}

	// Removal strict-deletes every VIP flow — the divert and dispatch, and
	// both reply flows of each of the two backends — and the group.
	ovsClient.mu.Lock()
	strictCount := len(ovsClient.strictDeletes)
	ovsClient.mu.Unlock()
	if strictCount != 6 {
		t.Errorf("strict deletes = %d, want 6", strictCount)
	}
	groups.mu.Lock()
	deletions := len(groups.deleted)
	groups.mu.Unlock()
	if deletions != 1 {
		t.Errorf("group deletions = %d, want 1", deletions)
	}

	if len(svc.ListVIPs()) != 0 {
		t.Error("VIP list not empty after removal")
	}
}

func TestAddVIPValidation(t *testing.T) {
	deps, _, _, _ := testDeps()
	svc := startService(t, deps)

	bad := testVIP()
	bad.Protocol = "sctp"
	if err := svc.AddVIP(context.Background(), bad); !errors.Is(err, ErrInvalidProtocol) {
		t.Fatalf("AddVIP = %v, want ErrInvalidProtocol", err)
	}

	leastConn := testVIP()
	leastConn.Algorithm = "least-conn"
	if err := svc.AddVIP(context.Background(), leastConn); !errors.Is(err, ErrAlgorithmUnsupported) {
		t.Fatalf("AddVIP = %v, want ErrAlgorithmUnsupported", err)
	}

	tooMany := testVIP()
	for i := 0; i < 20; i++ {
		tooMany.Backends = append(tooMany.Backends, Backend{
			Address: netip.MustParseAddr(fmt.Sprintf("10.9.0.%d", i+1)), Port: 80,
		})
	}
	if err := svc.AddVIP(context.Background(), tooMany); !errors.Is(err, ErrTooManyBackends) {
		t.Fatalf("AddVIP = %v, want ErrTooManyBackends", err)
	}
}

func TestVIPOperationsRequireStart(t *testing.T) {
	deps, _, _, _ := testDeps()
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	addr := netip.MustParseAddrPort("10.100.0.10:443")

	if err := svc.AddVIP(ctx, testVIP()); !errors.Is(err, ErrNotStarted) {
		t.Errorf("AddVIP = %v", err)
	}
	if err := svc.RemoveVIP(ctx, ProtocolTCP, addr); !errors.Is(err, ErrNotStarted) {
		t.Errorf("RemoveVIP = %v", err)
	}
	if err := svc.SetBackends(ctx, ProtocolTCP, addr, testVIP().Backends); !errors.Is(err, ErrNotStarted) {
		t.Errorf("SetBackends = %v", err)
	}
	if err := svc.SetBackendHealth(ctx, ProtocolTCP, addr, netip.MustParseAddrPort("10.0.1.5:8443"), false); !errors.Is(err, ErrNotStarted) {
		t.Errorf("SetBackendHealth = %v", err)
	}
	if err := svc.Reconcile(ctx); !errors.Is(err, ErrNotStarted) {
		t.Errorf("Reconcile = %v", err)
	}
}

func TestSetBackendHealthRebuildsGroup(t *testing.T) {
	deps, _, _, groups := testDeps(testVIP())
	svc := startService(t, deps)

	addr := netip.MustParseAddrPort("10.100.0.10:443")
	status, err := svc.GetVIP(ProtocolTCP, addr)
	if err != nil {
		t.Fatalf("GetVIP: %v", err)
	}
	ctx := context.Background()

	// Demote one backend: one bucket remains.
	b1 := netip.MustParseAddrPort("10.0.1.5:8443")
	if err := svc.SetBackendHealth(ctx, ProtocolTCP, addr, b1, false); err != nil {
		t.Fatalf("SetBackendHealth: %v", err)
	}
	if got := groups.bucketCount(status.GroupID); got != 1 {
		t.Errorf("bucket count = %d, want 1", got)
	}

	// Demote the second: zero buckets — fail closed for new connections.
	b2 := netip.MustParseAddrPort("10.0.1.6:8443")
	if err := svc.SetBackendHealth(ctx, ProtocolTCP, addr, b2, false); err != nil {
		t.Fatalf("SetBackendHealth: %v", err)
	}
	if got := groups.bucketCount(status.GroupID); got != 0 {
		t.Errorf("bucket count = %d, want 0 (fail closed)", got)
	}

	// The zero-bucket group mod must encode.
	groups.mu.Lock()
	empty := groups.groups[status.GroupID]
	groups.mu.Unlock()
	data, err := empty.MarshalBinary()
	if err != nil {
		t.Fatalf("zero-bucket MarshalBinary: %v", err)
	}
	if len(data) != 16 {
		t.Errorf("zero-bucket group mod length = %d, want 16 (header+body only)", len(data))
	}

	// Promote back: buckets restored.
	if err := svc.SetBackendHealth(ctx, ProtocolTCP, addr, b1, true); err != nil {
		t.Fatalf("SetBackendHealth: %v", err)
	}
	if got := groups.bucketCount(status.GroupID); got != 1 {
		t.Errorf("bucket count after promote = %d, want 1", got)
	}

	// Idempotent transition performs no group mod.
	groups.mu.Lock()
	before := groups.modifies
	groups.mu.Unlock()
	if err := svc.SetBackendHealth(ctx, ProtocolTCP, addr, b1, true); err != nil {
		t.Fatalf("SetBackendHealth idempotent: %v", err)
	}
	groups.mu.Lock()
	after := groups.modifies
	groups.mu.Unlock()
	if after != before {
		t.Errorf("idempotent health set programmed the group (%d -> %d)", before, after)
	}
}

func TestSetBackendHealthErrors(t *testing.T) {
	deps, _, _, groups := testDeps(testVIP())
	svc := startService(t, deps)

	ctx := context.Background()
	addr := netip.MustParseAddrPort("10.100.0.10:443")

	if err := svc.SetBackendHealth(ctx, ProtocolTCP, netip.MustParseAddrPort("10.9.9.9:1"), netip.MustParseAddrPort("10.0.1.5:8443"), false); !errors.Is(err, ErrVIPNotFound) {
		t.Errorf("unknown VIP = %v, want ErrVIPNotFound", err)
	}
	if err := svc.SetBackendHealth(ctx, ProtocolTCP, addr, netip.MustParseAddrPort("10.9.9.9:1"), false); !errors.Is(err, ErrBackendNotFound) {
		t.Errorf("unknown backend = %v, want ErrBackendNotFound", err)
	}

	// Group modify failure rolls the health flip back.
	groups.modErr = errors.New("of down")
	b1 := netip.MustParseAddrPort("10.0.1.5:8443")
	var opErr *OpError
	if err := svc.SetBackendHealth(ctx, ProtocolTCP, addr, b1, false); !errors.As(err, &opErr) || opErr.Op != "group-modify" {
		t.Fatalf("SetBackendHealth = %v, want group-modify OpError", err)
	}
	groups.modErr = nil
	status, err := svc.GetVIP(ProtocolTCP, addr)
	if err != nil {
		t.Fatalf("GetVIP: %v", err)
	}
	for _, b := range status.Backends {
		if !b.Healthy {
			t.Errorf("backend %v unhealthy after rolled-back transition", b.Backend)
		}
	}
}

func TestSetBackends(t *testing.T) {
	deps, _, _, groups := testDeps(testVIP())
	svc := startService(t, deps)

	ctx := context.Background()
	addr := netip.MustParseAddrPort("10.100.0.10:443")

	// Mark an existing backend unhealthy so we can verify health survives
	// the backend-set replacement.
	b1 := netip.MustParseAddrPort("10.0.1.5:8443")
	if err := svc.SetBackendHealth(ctx, ProtocolTCP, addr, b1, false); err != nil {
		t.Fatalf("SetBackendHealth: %v", err)
	}

	replacement := []Backend{
		{Address: netip.MustParseAddr("10.0.1.5"), Port: 8443},
		{Address: netip.MustParseAddr("10.0.1.7"), Port: 9000, Weight: 3},
	}
	if err := svc.SetBackends(ctx, ProtocolTCP, addr, replacement); err != nil {
		t.Fatalf("SetBackends: %v", err)
	}

	status, err := svc.GetVIP(ProtocolTCP, addr)
	if err != nil {
		t.Fatalf("GetVIP: %v", err)
	}
	if len(status.Backends) != 2 {
		t.Fatalf("backends = %d, want 2", len(status.Backends))
	}
	for _, b := range status.Backends {
		switch b.Backend.addrPort() {
		case b1:
			if b.Healthy {
				t.Error("retained backend lost its unhealthy state")
			}
		default:
			if !b.Healthy {
				t.Error("new backend must start healthy")
			}
		}
	}
	// Only the healthy new backend contributes a bucket.
	if got := groups.bucketCount(status.GroupID); got != 1 {
		t.Errorf("bucket count = %d, want 1", got)
	}

	// Validation errors surface.
	if err := svc.SetBackends(ctx, ProtocolTCP, addr, nil); !errors.Is(err, ErrNoBackends) {
		t.Errorf("SetBackends(nil) = %v, want ErrNoBackends", err)
	}
	if err := svc.SetBackends(ctx, ProtocolTCP, netip.MustParseAddrPort("10.9.9.9:1"), replacement); !errors.Is(err, ErrVIPNotFound) {
		t.Errorf("SetBackends unknown VIP = %v, want ErrVIPNotFound", err)
	}

	// Group failures roll the replacement back.
	groups.modErr = errors.New("of down")
	var opErr *OpError
	if err := svc.SetBackends(ctx, ProtocolTCP, addr, testVIP().Backends); !errors.As(err, &opErr) || opErr.Op != "group-modify" {
		t.Fatalf("SetBackends = %v, want group-modify OpError", err)
	}
	groups.modErr = nil
	status, err = svc.GetVIP(ProtocolTCP, addr)
	if err != nil {
		t.Fatalf("GetVIP: %v", err)
	}
	if len(status.Backends) != 2 || status.Backends[1].Backend.Port != 9000 {
		t.Errorf("backend set changed after rolled-back SetBackends: %+v", status.Backends)
	}
}

func TestReconcileReinstallsFlowsAndGroups(t *testing.T) {
	deps, controller, _, groups := testDeps(testVIP())
	svc := startService(t, deps)

	controller.mu.Lock()
	controller.batches = nil
	controller.mu.Unlock()
	groups.mu.Lock()
	groups.modifies = 0
	groups.mu.Unlock()

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	rules := controller.allRules()
	if len(rules) == 0 {
		t.Fatal("Reconcile installed no flows")
	}
	groups.mu.Lock()
	modifies := groups.modifies
	groups.mu.Unlock()
	if modifies != 1 {
		t.Errorf("group modifies = %d, want 1", modifies)
	}

	controller.installErr = errors.New("switch rejected")
	var opErr *OpError
	if err := svc.Reconcile(context.Background()); !errors.As(err, &opErr) || opErr.Op != "reconcile" {
		t.Fatalf("Reconcile = %v, want reconcile OpError", err)
	}
}

func TestHealthSnapshot(t *testing.T) {
	deps, _, _, _ := testDeps(testVIP())
	svc := startService(t, deps)

	h := svc.Health()
	if !h.Active || h.VIPCount != 1 || h.TotalBackends != 2 || h.HealthyBackends != 2 {
		t.Errorf("Health = %+v", h)
	}

	addr := netip.MustParseAddrPort("10.100.0.10:443")
	if err := svc.SetBackendHealth(context.Background(), ProtocolTCP, addr, netip.MustParseAddrPort("10.0.1.5:8443"), false); err != nil {
		t.Fatalf("SetBackendHealth: %v", err)
	}
	h = svc.Health()
	if h.HealthyBackends != 1 {
		t.Errorf("HealthyBackends = %d, want 1", h.HealthyBackends)
	}
	if h.LastReconcile.IsZero() {
		t.Error("LastReconcile is zero")
	}
}

func TestGroupIDDeterminismAndCollisionProbing(t *testing.T) {
	deps, _, _, _ := testDeps()
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key := testVIP().key()
	id1, err := svc.groupIDFor(key)
	if err != nil {
		t.Fatalf("groupIDFor: %v", err)
	}
	id2, err := svc.groupIDFor(key)
	if err != nil {
		t.Fatalf("groupIDFor: %v", err)
	}
	if id1 != id2 {
		t.Errorf("group ID not deterministic: 0x%x vs 0x%x", id1, id2)
	}

	// Occupy the deterministic slot with another VIP: probing yields the
	// next free ID.
	svc.vips[vipKey{proto: "tcp", addr: netip.MustParseAddr("10.0.0.99"), port: 1}] = &vipState{groupID: id1}
	id3, err := svc.groupIDFor(key)
	if err != nil {
		t.Fatalf("groupIDFor: %v", err)
	}
	if id3 == id1 {
		t.Error("collision probing did not advance")
	}
	if id3&GroupIDMask != GroupIDBase {
		t.Errorf("probed ID 0x%x escaped the LB range", id3)
	}
}

// TestBucketActionEncoding is the golden proof of the bucket action bytes.
// The encoded ct(commit,zone=42,nat(dst=10.0.1.5:8080),table=30) action was
// verified against Open vSwitch 3.3.4:
//
//	$ echo <hex> | ovs-ofctl parse-actions OpenFlow13
//	actions=ct(commit,table=30,zone=42,nat(dst=10.0.1.5:8080))
//
// Layout (struct nx_action_conntrack, 48 bytes total):
//
//	ffff 0030 00002320 0023   experimenter header, len 48, Nicira, NXAST_CT
//	0001                      flags = NX_CT_F_COMMIT
//	00000000                  zone_src = 0 (immediate zone)
//	002a                      zone_imm = 42
//	1e                        recirc_table = 30
//	000000                    pad
//	0000                      alg = 0
//	ffff 0018 00002320 0024   nested NXAST_NAT header, len 24
//	0000                      pad
//	0002                      flags = NX_NAT_F_DST
//	0011                      range_present = IPv4_MIN | PROTO_MIN
//	0a000105                  10.0.1.5
//	1f90                      port 8080
//	0000                      pad to 8
func TestBucketActionEncoding(t *testing.T) {
	svc, err := New(func() Deps { d, _, _, _ := testDeps(); return d }())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state := &vipState{
		vip: VIP{
			Address:  netip.MustParseAddr("10.100.0.10"),
			Port:     443,
			Protocol: ProtocolTCP,
			Backends: []Backend{{Address: netip.MustParseAddr("10.0.1.5"), Port: 8080}},
		},
		zone:    42,
		groupID: GroupIDBase,
		healthy: map[netip.AddrPort]bool{netip.MustParseAddrPort("10.0.1.5:8080"): true},
	}

	mod := svc.groupMod(state)
	if mod.Type != openflow.OFPGTSelect {
		t.Errorf("group type = %d, want OFPGT_SELECT", mod.Type)
	}
	if len(mod.Buckets) != 1 {
		t.Fatalf("buckets = %d, want 1", len(mod.Buckets))
	}
	if mod.Buckets[0].Weight != 1 {
		t.Errorf("default weight = %d, want 1", mod.Buckets[0].Weight)
	}
	if len(mod.Buckets[0].Actions) != 1 {
		t.Fatalf("bucket actions = %d, want 1", len(mod.Buckets[0].Actions))
	}

	data, err := mod.Buckets[0].Actions[0].MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	// ct(commit,zone=42,nat(dst=10.0.1.5:8080),table=28): the bucket
	// recirculates into the hairpin stage, not straight to table 30.
	const golden = "ffff0030000023200023000100000000002a1c0000000000" +
		"ffff00180000232000240000000200110a0001051f900000"
	if got := hex.EncodeToString(data); got != golden {
		t.Errorf("bucket action bytes:\n got  %s\n want %s", got, golden)
	}
}

// rulesIn returns the rules in table at priority.
func rulesIn(rules []zoneflows.FlowRule, table, priority int) []zoneflows.FlowRule {
	var out []zoneflows.FlowRule
	for _, r := range rules {
		if r.Table == table && r.Priority == priority {
			out = append(out, r)
		}
	}
	return out
}

// assertReplyPath checks the #718 half of a VIP's pipeline. Without the
// reply divert a backend's reply never meets the VIP's conntrack zone and
// reaches the client from the backend's address, which the client drops.
func assertReplyPath(t *testing.T, svc *Service, rules []zoneflows.FlowRule, vip VIP) {
	t.Helper()
	status, err := svc.GetVIP(vip.Protocol, netip.AddrPortFrom(vip.Address, vip.Port))
	if err != nil {
		t.Fatalf("GetVIP: %v", err)
	}
	if svc.hairpinZone == 0 || svc.hairpinZone == status.CTZone {
		t.Fatalf("hairpin zone %d must be allocated and distinct from the VIP zone %d", svc.hairpinZone, status.CTZone)
	}

	diverts := rulesIn(rules, int(modes.TableCTGate), prioLBReplyDivert)
	undnat := rulesIn(rules, int(modes.TableLBReply), prioLBReplyUnDNAT)
	if prioLBReplyUnDNAT <= prioLBReplyEst {
		t.Error("the per-backend un-DNAT must be tried before the reply verdict")
	}
	if len(diverts) != len(vip.Backends) || len(undnat) != len(vip.Backends) {
		t.Fatalf("reply flows = %d diverts, %d un-DNAT; want one each per backend (%d)",
			len(diverts), len(undnat), len(vip.Backends))
	}
	for i, b := range vip.Backends {
		source := fmt.Sprintf("dl_type=0x0800,nw_proto=6,nw_src=%s,tp_src=%d", b.Address, b.Port)
		if want := "reg1=0/0x1," + source; diverts[i].Match != want {
			t.Errorf("reply divert match = %q, want %q", diverts[i].Match, want)
		}
		if want := fmt.Sprintf("load:1->NXM_NX_REG1[0],ct(table=29,zone=%d,nat)", svc.hairpinZone); diverts[i].Actions != want {
			t.Errorf("reply divert actions = %q, want %q (hairpin zone first)", diverts[i].Actions, want)
		}
		if want := fmt.Sprintf("ct_zone=%d,%s", svc.hairpinZone, source); undnat[i].Match != want {
			t.Errorf("un-DNAT match = %q, want %q (only a packet back from the hairpin zone)", undnat[i].Match, want)
		}
		if want := fmt.Sprintf("ct(table=29,zone=%d,nat)", status.CTZone); undnat[i].Actions != want {
			t.Errorf("un-DNAT actions = %q, want %q (the VIP's own zone)", undnat[i].Actions, want)
		}
	}

	for _, check := range []struct {
		table, priority int
		match, actions  string
		purpose         string
	}{
		{26, prioLBEstRel, "ct_state=+est+trk", "goto_table:28", "established requests pass the hairpin stage"},
		{28, prioLBMissHairpin, "", "goto_table:30", "non-hairpin connections continue"},
		{29, prioLBReplyEst, "ct_state=+est+rpl+trk", "goto_table:30", "a VIP reply continues un-NATed"},
		{29, prioLBReplyMiss, "", "resubmit(,20)", "a backend's own traffic returns to the gate"},
	} {
		got := rulesIn(rules, check.table, check.priority)
		found := false
		for _, r := range got {
			if r.Match == check.match && r.Actions == check.actions {
				found = true
			}
		}
		if !found {
			t.Errorf("table %d priority %d: no %q -> %q (%s); have %+v",
				check.table, check.priority, check.match, check.actions, check.purpose, got)
		}
	}
}

// TestHairpinPrefixesSourceNATToTheVIP pins the hairpin half of #718: a
// connection from a hairpin prefix is source-NATed to the VIP in the shared
// hairpin zone, committed on its first packet and applied to the rest.
func TestHairpinPrefixesSourceNATToTheVIP(t *testing.T) {
	deps, controller, _, _ := testDeps(testVIP())
	deps.Config.HairpinPrefixes = []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("192.168.7.9/16"), // installed masked
	}
	svc := startService(t, deps)
	status, err := svc.GetVIP(ProtocolTCP, netip.MustParseAddrPort("10.100.0.10:443"))
	if err != nil {
		t.Fatalf("GetVIP: %v", err)
	}

	hairpin := rulesIn(controller.allRules(), int(modes.TableLBHairpin), prioLBHairpin)
	if len(hairpin) != 4 {
		t.Fatalf("hairpin flows = %d, want a commit and an established flow per prefix", len(hairpin))
	}
	for i, src := range []string{"10.0.1.0/24", "192.168.0.0/16"} {
		source := fmt.Sprintf("ct_zone=%d,dl_type=0x0800,nw_src=%s", status.CTZone, src)
		commit, est := hairpin[2*i], hairpin[2*i+1]
		if commit.Match != "ct_state=+new+trk,"+source {
			t.Errorf("hairpin commit match = %q", commit.Match)
		}
		if want := fmt.Sprintf("ct(commit,zone=%d,nat(src=10.100.0.10),table=30)", svc.hairpinZone); commit.Actions != want {
			t.Errorf("hairpin commit actions = %q, want %q", commit.Actions, want)
		}
		if est.Match != "ct_state=+est+trk,"+source {
			t.Errorf("hairpin established match = %q", est.Match)
		}
		if want := fmt.Sprintf("ct(zone=%d,nat,table=30)", svc.hairpinZone); est.Actions != want {
			t.Errorf("hairpin established actions = %q, want %q", est.Actions, want)
		}
	}
}

func TestNoHairpinPrefixesNoSourceNAT(t *testing.T) {
	deps, controller, _, _ := testDeps(testVIP())
	startService(t, deps)
	if got := rulesIn(controller.allRules(), int(modes.TableLBHairpin), prioLBHairpin); len(got) != 0 {
		t.Errorf("hairpin flows without hairpin prefixes: %+v", got)
	}
}

func TestHairpinZoneLifecycle(t *testing.T) {
	deps, _, _, _ := testDeps(testVIP())
	svc := startService(t, deps)
	zone := svc.hairpinZone
	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Released: the allocator hands the same key a zone again, and the
	// service starts cleanly a second time.
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if svc.hairpinZone == 0 {
		t.Errorf("hairpin zone not re-allocated (was %d)", zone)
	}
}

// refusingPersister fails every save, so every new zone allocation fails.
type refusingPersister struct{}

func (refusingPersister) Save(context.Context, map[string]uint16) error {
	return errors.New("persist refused")
}

func (refusingPersister) Load(context.Context) (map[string]uint16, error) { return nil, nil }

func TestStartFailsWhenTheHairpinZoneCannotBeAllocated(t *testing.T) {
	deps, controller, _, groups := testDeps(testVIP())
	deps.Allocator = ct.NewZoneAllocator(refusingPersister{})
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var opErr *OpError
	if err := svc.Start(context.Background()); !errors.As(err, &opErr) || opErr.Op != "allocate" {
		t.Fatalf("Start = %v, want an allocate OpError", err)
	}
	if len(controller.allRules()) != 0 || groups.additions != 0 {
		t.Error("nothing may be programmed before the hairpin zone exists")
	}
}

// TestBackendServesOneVIPPerProtocol pins the constraint the reply divert
// imposes: a backend endpoint's replies go to exactly one VIP zone.
func TestBackendServesOneVIPPerProtocol(t *testing.T) {
	deps, _, _, _ := testDeps(testVIP())
	svc := startService(t, deps)
	ctx := context.Background()

	shared := testVIP()
	shared.Address = netip.MustParseAddr("10.100.0.11")
	if err := svc.AddVIP(ctx, shared); !errors.Is(err, ErrBackendInUse) {
		t.Errorf("AddVIP sharing a backend = %v, want ErrBackendInUse", err)
	}

	udp := shared
	udp.Protocol = ProtocolUDP
	if err := svc.AddVIP(ctx, udp); err != nil {
		t.Errorf("the same endpoint under another protocol is a different tuple: %v", err)
	}

	other := VIP{
		Address: netip.MustParseAddr("10.100.0.12"), Port: 80, Protocol: ProtocolTCP,
		Backends: []Backend{{Address: netip.MustParseAddr("10.0.2.1"), Port: 80}},
	}
	if err := svc.AddVIP(ctx, other); err != nil {
		t.Fatalf("AddVIP: %v", err)
	}
	if err := svc.SetBackends(ctx, ProtocolTCP, netip.AddrPortFrom(other.Address, other.Port), testVIP().Backends); !errors.Is(err, ErrBackendInUse) {
		t.Errorf("SetBackends onto another VIP's backend = %v, want ErrBackendInUse", err)
	}
	// A VIP may of course keep its own backends.
	if err := svc.SetBackends(ctx, ProtocolTCP, netip.MustParseAddrPort("10.100.0.10:443"), testVIP().Backends); err != nil {
		t.Errorf("SetBackends to its own set: %v", err)
	}
}

// TestSetBackendsMovesTheReplyDiverts pins that the reply path follows the
// backend set: a new backend's divert is installed, a removed backend's is
// strict-deleted, and a failed group update takes the new divert back out.
func TestSetBackendsMovesTheReplyDiverts(t *testing.T) {
	deps, controller, ovsClient, groups := testDeps(testVIP())
	svc := startService(t, deps)
	ctx := context.Background()
	addr := netip.MustParseAddrPort("10.100.0.10:443")

	replacement := []Backend{
		{Address: netip.MustParseAddr("10.0.1.5"), Port: 8443},
		{Address: netip.MustParseAddr("10.0.1.7"), Port: 9000},
	}
	if err := svc.SetBackends(ctx, ProtocolTCP, addr, replacement); err != nil {
		t.Fatalf("SetBackends: %v", err)
	}
	last := controller.batches[len(controller.batches)-1]
	if got := rulesIn(last, int(modes.TableCTGate), prioLBReplyDivert); len(got) != 2 ||
		!strings.Contains(got[1].Match, "nw_src=10.0.1.7,tp_src=9000") {
		t.Errorf("installed reply diverts = %+v", got)
	}
	if len(ovsClient.strictDeletes) != 2 {
		t.Fatalf("strict deletes = %+v, want the removed backend's two reply flows", ovsClient.strictDeletes)
	}
	for _, d := range ovsClient.strictDeletes {
		if !strings.Contains(d.Match, "nw_src=10.0.1.6,tp_src=8443") {
			t.Errorf("deleted %+v, which is not the removed backend's", d)
		}
	}

	groups.modErr = errors.New("of down")
	before := len(ovsClient.strictDeletes)
	if err := svc.SetBackends(ctx, ProtocolTCP, addr, append(replacement, Backend{Address: netip.MustParseAddr("10.0.1.8"), Port: 1})); err == nil {
		t.Fatal("SetBackends must fail when the group cannot be modified")
	}
	added := ovsClient.strictDeletes[before:]
	if len(added) != 2 {
		t.Fatalf("rollback deletes = %+v, want the never-selectable backend's two reply flows", added)
	}
	for _, d := range added {
		if !strings.Contains(d.Match, "nw_src=10.0.1.8,tp_src=1") {
			t.Errorf("rollback deleted %+v", d)
		}
	}

	groups.modErr = nil
	ovsClient.strictErr = errors.New("delete refused")
	var opErr *OpError
	if err := svc.SetBackends(ctx, ProtocolTCP, addr, testVIP().Backends); !errors.As(err, &opErr) || opErr.Op != "delete" {
		t.Errorf("SetBackends with a failing stale delete = %v, want a delete OpError", err)
	}
	ovsClient.strictErr = nil
}

func TestSetBackendsInstallFailure(t *testing.T) {
	deps, controller, _, _ := testDeps(testVIP())
	svc := startService(t, deps)
	controller.installErr = errors.New("controller down")
	var opErr *OpError
	err := svc.SetBackends(context.Background(), ProtocolTCP, netip.MustParseAddrPort("10.100.0.10:443"), testVIP().Backends)
	if !errors.As(err, &opErr) || opErr.Op != "install" {
		t.Errorf("SetBackends = %v, want an install OpError", err)
	}
	controller.installErr = nil
}

func TestStaleFlows(t *testing.T) {
	a := zoneflows.FlowRule{Table: 20, Priority: 260, Match: "a"}
	b := zoneflows.FlowRule{Table: 20, Priority: 260, Match: "b"}
	bOtherAction := zoneflows.FlowRule{Table: 20, Priority: 260, Match: "b", Actions: "changed"}
	c := zoneflows.FlowRule{Table: 27, Priority: 100, Match: "a"}

	got := staleFlows([]zoneflows.FlowRule{a, b, c}, []zoneflows.FlowRule{bOtherAction})
	if len(got) != 2 || got[0].Match != "a" || got[1].Table != 27 {
		t.Errorf("staleFlows = %+v; identity is table+priority+match, not actions", got)
	}
	if got := staleFlows(nil, []zoneflows.FlowRule{a}); len(got) != 0 {
		t.Errorf("nothing installed, nothing stale: %+v", got)
	}
}

// secondVIP is a TCP VIP with backends of its own, so it can sit beside
// testVIP.
func secondVIP() VIP {
	v := testVIP()
	v.Address = netip.MustParseAddr("10.100.0.11")
	v.Backends = []Backend{{Address: netip.MustParseAddr("10.0.2.5"), Port: 8443}}
	return v
}

// TestStartRollsBackEveryFailure is the second review finding on #728: the
// gateway registers the service only after Start succeeds, so a Start that
// fails part-way must take back what it programmed and allocated itself.
func TestStartRollsBackEveryFailure(t *testing.T) {
	tests := []struct {
		name   string
		inject func(*fakeController, *fakeGroups)
		wantOp string
	}{
		{"the second VIP's group", func(_ *fakeController, g *fakeGroups) {
			g.failAddOn = 2
			g.addErr = errors.New("group table full")
		}, "group-add"},
		{"the second VIP's flows", func(c *fakeController, _ *fakeGroups) {
			c.failOnCall = 2
			c.installErr = errors.New("switch rejected")
		}, "install"},
		{"a stale group", func(_ *fakeController, g *fakeGroups) {
			g.descs = []openflow.GroupDesc{{GroupID: GroupIDBase | 0xfffe}}
			g.failDelOn = 1
			g.delErr = errors.New("stale group busy")
		}, "group-delete"},
		{"the scaffolding", func(c *fakeController, _ *fakeGroups) {
			c.failOnCall = 3
			c.installErr = errors.New("switch rejected")
		}, "install"},
		{"the gate", func(c *fakeController, _ *fakeGroups) {
			c.failOnCall = 4
			c.installErr = errors.New("switch rejected")
		}, "install"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, controller, ovsClient, groups := testDeps(testVIP(), secondVIP())
			tt.inject(controller, groups)
			svc, err := New(deps)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			err = svc.Start(context.Background())
			var opErr *OpError
			if !errors.As(err, &opErr) || opErr.Op != tt.wantOp {
				t.Fatalf("Start = %v, want a %s OpError", err, tt.wantOp)
			}
			if svc.Active() {
				t.Fatal("a failed Start must not leave the service active")
			}
			ovsClient.mu.Lock()
			cookieDeletes := len(ovsClient.cookieDeletes)
			ovsClient.mu.Unlock()
			if cookieDeletes != 1 {
				t.Errorf("cookie deletes = %d, want one sweep of every LB flow", cookieDeletes)
			}

			// The stale group from a previous run is not Start's to keep
			// or remove on failure; everything Start installed is gone.
			groups.mu.Lock()
			for id := range groups.groups {
				if id != GroupIDBase|0xfffe {
					t.Errorf("group 0x%x left on the switch", id)
				}
			}
			groups.mu.Unlock()
			if held := deps.Allocator.Snapshot(); len(held) != 0 {
				t.Errorf("conntrack zones still held: %v", held)
			}

			// And the service starts cleanly once the fault is gone.
			controller.installErr, groups.addErr, groups.delErr = nil, nil, nil
			if err := svc.Start(context.Background()); err != nil {
				t.Fatalf("restart after rollback: %v", err)
			}
			if err := svc.Stop(context.Background()); err != nil {
				t.Fatalf("Stop: %v", err)
			}
		})
	}
}

// TestStartReportsAFailedRollback keeps the original error and adds the
// rollback's, so neither is lost.
func TestStartReportsAFailedRollback(t *testing.T) {
	deps, controller, ovsClient, _ := testDeps(testVIP())
	controller.failOnCall = 2
	controller.installErr = errors.New("switch rejected")
	ovsClient.cookieErr = errors.New("switch gone")
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = svc.Start(context.Background())
	if !errors.Is(err, controller.installErr) || !errors.Is(err, ovsClient.cookieErr) {
		t.Fatalf("Start = %v, want both the install and the rollback failure", err)
	}
}

// TestAddVIPLeavesNothingWhenItFails covers the per-VIP half: a VIP whose
// flows the switch refuses leaves no group and holds no zone.
func TestAddVIPLeavesNothingWhenItFails(t *testing.T) {
	deps, controller, ovsClient, groups := testDeps()
	svc := startService(t, deps)
	before := len(deps.Allocator.Snapshot())

	controller.installErr = errors.New("switch rejected")
	var opErr *OpError
	if err := svc.AddVIP(context.Background(), testVIP()); !errors.As(err, &opErr) || opErr.Op != "install" {
		t.Fatalf("AddVIP = %v, want an install OpError", err)
	}
	controller.installErr = nil

	groups.mu.Lock()
	left := len(groups.groups)
	groups.mu.Unlock()
	if left != 0 {
		t.Errorf("%d groups left after a refused VIP", left)
	}
	if held := len(deps.Allocator.Snapshot()); held != before {
		t.Errorf("zones held = %d, want %d (the hairpin zone only)", held, before)
	}
	ovsClient.mu.Lock()
	deleted := len(ovsClient.strictDeletes)
	ovsClient.mu.Unlock()
	if deleted == 0 {
		t.Error("the refused batch's flows must be strict-deleted in case some went in")
	}
	if _, err := svc.GetVIP(ProtocolTCP, netip.MustParseAddrPort("10.100.0.10:443")); !errors.Is(err, ErrVIPNotFound) {
		t.Errorf("GetVIP = %v, want ErrVIPNotFound", err)
	}
	if err := svc.AddVIP(context.Background(), testVIP()); err != nil {
		t.Errorf("the VIP installs once the switch accepts it: %v", err)
	}
}

// TestAddVIPReportsAFailedUndo keeps the install error and adds the undo's.
func TestAddVIPReportsAFailedUndo(t *testing.T) {
	deps, controller, _, groups := testDeps()
	svc := startService(t, deps)
	installErr, delErr := errors.New("switch rejected"), errors.New("group busy")
	controller.installErr, groups.delErr = installErr, delErr
	err := svc.AddVIP(context.Background(), testVIP())
	controller.installErr, groups.delErr = nil, nil
	if !errors.Is(err, installErr) || !errors.Is(err, delErr) {
		t.Fatalf("AddVIP = %v, want both the install and the undo failure", err)
	}
	var opErr *OpError
	if !errors.As(err, &opErr) || opErr.Op != "install" {
		t.Errorf("the first OpError is the cause: %v", err)
	}
}
