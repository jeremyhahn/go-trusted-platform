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
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// fakeController records installed flow batches and injects failures.
type fakeController struct {
	mu         sync.Mutex
	batches    [][]zoneflows.FlowRule
	installErr error
}

func (f *fakeController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	return f.InstallFlows(bridgeName, []zoneflows.FlowRule{{Priority: priority, Match: match, Actions: actions}})
}

func (f *fakeController) InstallFlows(bridgeName string, rules []zoneflows.FlowRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.installErr != nil {
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
	if f.addErr != nil {
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
	if f.delErr != nil {
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

	var haveDivert, haveDispatch, haveMissT20, haveMissT26 bool
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
		if r.Table == 20 && r.Priority == prioLBMissT20 && r.Actions == "goto_table:30" {
			haveMissT20 = true
		}
		if r.Table == 26 && r.Priority == prioLBMissT26 && r.Actions == "drop" {
			haveMissT26 = true
		}
		if r.Cookie != fmt.Sprintf("0x%x", CookieLoadBalancer) {
			t.Errorf("rule %+v missing LB cookie", r)
		}
	}
	if !haveDivert || !haveDispatch || !haveMissT20 || !haveMissT26 {
		t.Errorf("missing pipeline flows: divert=%v dispatch=%v missT20=%v missT26=%v",
			haveDivert, haveDispatch, haveMissT20, haveMissT26)
	}

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

	// Removal strict-deletes the two VIP flows and the group.
	ovsClient.mu.Lock()
	strictCount := len(ovsClient.strictDeletes)
	ovsClient.mu.Unlock()
	if strictCount != 2 {
		t.Errorf("strict deletes = %d, want 2", strictCount)
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
	const golden = "ffff0030000023200023000100000000002a1e0000000000" +
		"ffff00180000232000240000000200110a0001051f900000"
	if got := hex.EncodeToString(data); got != golden {
		t.Errorf("bucket action bytes:\n got  %s\n want %s", got, golden)
	}
}
