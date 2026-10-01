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

package nat64

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// fakeDriver records what the service asked of the kernel and answers from
// a scripted state.
type fakeDriver struct {
	mu        sync.Mutex
	applied   []Instance
	removed   []string
	stats     Stats
	applyErr  error
	removeErr error
	statsErr  error

	// adopted makes Apply report an instance it found rather than made.
	adopted bool
	// statsCalls, when set, receives one value per Stats call, so a test
	// can wait on the reconcile loop without sleeping.
	statsCalls chan struct{}
}

func (d *fakeDriver) Apply(_ context.Context, inst Instance) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.applyErr != nil {
		return false, d.applyErr
	}
	d.applied = append(d.applied, inst)
	return !d.adopted, nil
}

func (d *fakeDriver) Remove(_ context.Context, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.removeErr != nil {
		return d.removeErr
	}
	d.removed = append(d.removed, name)
	return nil
}

func (d *fakeDriver) Stats(_ context.Context, _ string) (Stats, error) {
	d.mu.Lock()
	stats, err, calls := d.stats, d.statsErr, d.statsCalls
	d.mu.Unlock()
	if calls != nil {
		select {
		case calls <- struct{}{}:
		default:
		}
	}
	if err != nil {
		return Stats{}, err
	}
	return stats, nil
}

func (d *fakeDriver) set(mutate func(*fakeDriver)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	mutate(d)
}

func (d *fakeDriver) applyCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.applied)
}

func (d *fakeDriver) removedNames() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.removed...)
}

// fakeController records installed flow batches and injects failures.
type fakeController struct {
	mu         sync.Mutex
	batches    [][]zoneflows.FlowRule
	installErr error
}

func (f *fakeController) InstallFlow(bridge string, priority int, match, actions string) error {
	return f.InstallFlows(bridge, []zoneflows.FlowRule{{Priority: priority, Match: match, Actions: actions}})
}

func (f *fakeController) InstallFlows(_ string, rules []zoneflows.FlowRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.installErr != nil {
		return f.installErr
	}
	f.batches = append(f.batches, rules)
	return nil
}

func (f *fakeController) DeleteFlow(string, string) error        { return nil }
func (f *fakeController) DeleteFlowsByPort(string, string) error { return nil }
func (f *fakeController) ListFlows(string) ([]string, error)     { return nil, nil }

func (f *fakeController) allRules() []zoneflows.FlowRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []zoneflows.FlowRule
	for _, batch := range f.batches {
		out = append(out, batch...)
	}
	return out
}

// fakeOVS overrides only the methods the service uses; anything else panics
// through the embedded nil interface, flagging an unexpected dependency.
type fakeOVS struct {
	ovs.ClientInterface

	mu            sync.Mutex
	ofPort        int32
	mac           string
	ifaceErr      error
	cookieDeletes []uint64
	cookieMasks   []uint64
	cookieErr     error

	// flows is what a cookie-filtered stats query returns: the flows a
	// previous process left under the NAT64 owner.
	flows    []*ovs.Flow
	statsErr error
}

func (f *fakeOVS) GetFlowStats(_ context.Context, _ string, match string) ([]*ovs.Flow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statsErr != nil {
		return nil, f.statsErr
	}
	if !strings.HasPrefix(match, "cookie=") {
		return nil, errors.New("the sweep must query by cookie, got " + match)
	}
	return append([]*ovs.Flow(nil), f.flows...), nil
}

func (f *fakeOVS) masks() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.cookieMasks...)
}

func (f *fakeOVS) GetInterface(_ context.Context, name string) (*ovs.Interface, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ifaceErr != nil {
		return nil, f.ifaceErr
	}
	return &ovs.Interface{Name: name, OFPort: f.ofPort, MAC: f.mac}, nil
}

func (f *fakeOVS) set(mutate func(*fakeOVS)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mutate(f)
}

func (f *fakeOVS) DeleteFlowsByCookie(_ context.Context, _ string, cookie, mask uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cookieErr != nil {
		return f.cookieErr
	}
	f.cookieDeletes = append(f.cookieDeletes, cookie)
	f.cookieMasks = append(f.cookieMasks, mask)
	return nil
}

func (f *fakeOVS) deletedCookies() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.cookieDeletes...)
}

// testMAC and testPort are the translator port every test resolves.
const testMAC = "02:00:00:00:00:07"

var testPort = TranslatorPort{OFPort: 7, MAC: testMAC}

// newTestService builds a service over fakes, returning them for assertions.
func newTestService(t *testing.T, mutate func(*Deps)) (*Service, *fakeDriver, *fakeController, *fakeOVS) {
	t.Helper()
	driver := &fakeDriver{stats: Stats{Present: true}}
	ctrl := &fakeController{}
	client := &fakeOVS{ofPort: 7, mac: testMAC}
	deps := Deps{
		Driver:     driver,
		Controller: ctrl,
		OVS:        client,
		Config:     validConfig(),
		Now:        func() time.Time { return time.Unix(1700000000, 0) },
	}
	if mutate != nil {
		mutate(&deps)
	}
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	return svc, driver, ctrl, client
}

func TestNew_RefusesAServiceThatCouldNotProgramAnything(t *testing.T) {
	base := Deps{
		Driver:     &fakeDriver{},
		Controller: &fakeController{},
		OVS:        &fakeOVS{},
		Config:     validConfig(),
	}
	tests := []struct {
		name    string
		mutate  func(*Deps)
		wantErr error
	}{
		{"no driver", func(d *Deps) { d.Driver = nil }, ErrNilDriver},
		{"no controller", func(d *Deps) { d.Controller = nil }, ErrNilController},
		{"no ovs client", func(d *Deps) { d.OVS = nil }, ErrNilOVSClient},
		{"an invalid config", func(d *Deps) { d.Config.Pool4 = nil }, ErrNoPool4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := base
			tc.mutate(&deps)
			_, err := New(deps)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("New() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestFlowRules_EveryGotoTargetIsRoutedInto is the keystone invariant: a
// service that emits `goto_table:N` and never routes traffic into N
// programs nothing while reporting success (#567). Table 27 exists only
// because tables 10 and 20 send frames there.
func TestFlowRules_EveryGotoTargetIsRoutedInto(t *testing.T) {
	svc, _, _, _ := newTestService(t, nil)
	rules := svc.FlowRules(testPort)

	targets := map[int]bool{}
	tables := map[int]bool{}
	for _, r := range rules {
		tables[r.Table] = true
		if target, ok := gotoTarget(r.Actions); ok {
			targets[target] = true
		}
	}
	if !targets[int(modes.TableNAT64)] {
		t.Fatal("no rule routes traffic into table 27; the hand-off would be dead flows")
	}
	if !tables[int(modes.TableNAT64)] {
		t.Fatal("nothing is installed in table 27; the divert would be a black hole")
	}
	if !tables[gateTable] {
		t.Fatal("no table 10 gate; the divert is unreachable without the firewall or NAT running")
	}
	if !tables[int(modes.TableCTGate)] {
		t.Fatal("no table 20 divert; nothing would ever reach table 27")
	}
}

func TestFlowRules_TableTwentySevenIsNeverABlackHole(t *testing.T) {
	svc, _, _, _ := newTestService(t, nil)
	rules := svc.FlowRules(testPort)
	var miss *zoneflows.FlowRule
	for i := range rules {
		if rules[i].Table == int(modes.TableNAT64) && rules[i].Priority == prioNAT64Miss {
			miss = &rules[i]
		}
	}
	if miss == nil {
		t.Fatal("table 27 has no miss rule; a frame that reaches it and matches nothing is dropped")
	}
	if target, ok := gotoTarget(miss.Actions); !ok || target != int(modes.TableMACLearning) {
		t.Fatalf("table 27 miss = %q, want a continuation to table %d", miss.Actions, modes.TableMACLearning)
	}
}

func TestFlowRules_DivertOutranksTheZoneGateAndTheIPv6Pass(t *testing.T) {
	// The firewall's per-zone conntrack gate is priority 100 and NAT's IPv6
	// pass is 80. A divert below either never fires, and the translator
	// would sit idle while the section reported healthy.
	svc, _, _, _ := newTestService(t, nil)
	for _, r := range svc.FlowRules(testPort) {
		if r.Table == int(modes.TableCTGate) && strings.Contains(r.Actions, strconv.Itoa(int(modes.TableNAT64))) {
			if r.Priority <= 100 {
				t.Fatalf("divert priority %d does not outrank the firewall zone gate (100)", r.Priority)
			}
			return
		}
	}
	t.Fatal("no table 20 divert found")
}

func TestFlowRules_TheGateCarriesItsOwnPriority(t *testing.T) {
	// Identical match and priority would make one service's OFPFC_ADD
	// replace another's and break per-service teardown; the firewall holds
	// 2 and NAT holds 1.
	svc, _, _, _ := newTestService(t, nil)
	for _, r := range svc.FlowRules(testPort) {
		if r.Table == gateTable {
			if r.Priority == 1 || r.Priority == 2 {
				t.Fatalf("table 10 gate priority %d collides with the firewall or NAT gate", r.Priority)
			}
			return
		}
	}
	t.Fatal("no table 10 gate found")
}

func TestFlowRules_NamedClientZonesRestrictTheDivert(t *testing.T) {
	svc, _, _, _ := newTestService(t, func(d *Deps) {
		d.Config.ClientZones = []ClientZone{{Name: "iot", VLAN: 300}, {Name: "guest", VLAN: 400}}
	})
	var diverts []zoneflows.FlowRule
	for _, r := range svc.FlowRules(testPort) {
		if r.Table == int(modes.TableCTGate) {
			diverts = append(diverts, r)
		}
	}
	if len(diverts) != 2 {
		t.Fatalf("got %d diverts for 2 client zones, want one each", len(diverts))
	}
	for _, want := range []string{"dl_vlan=300", "dl_vlan=400"} {
		var found bool
		for _, r := range diverts {
			if strings.Contains(r.Match, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("no divert matches %s; that zone would get no translation", want)
		}
	}
}

func TestFlowRules_NoClientZonesDivertsEveryFrameAddressedToThePrefix(t *testing.T) {
	svc, _, _, _ := newTestService(t, nil)
	var diverts int
	for _, r := range svc.FlowRules(testPort) {
		if r.Table == int(modes.TableCTGate) {
			diverts++
			if strings.Contains(r.Match, "dl_vlan") {
				t.Fatalf("divert matches a VLAN with no client zones configured: %q", r.Match)
			}
			if !strings.Contains(r.Match, "ipv6_dst=64:ff9b::/96") {
				t.Fatalf("divert does not match the translation prefix: %q", r.Match)
			}
		}
	}
	if diverts != 1 {
		t.Fatalf("got %d diverts, want exactly 1", diverts)
	}
}

func TestFlowRules_EveryRuleCarriesTheServiceCookie(t *testing.T) {
	// Stop deletes by cookie; a rule without one outlives the service.
	svc, _, _, _ := newTestService(t, nil)
	want := fmt.Sprintf("0x%x", CookieNAT64)
	for _, r := range svc.FlowRules(testPort) {
		if r.Cookie != want {
			t.Fatalf("rule in table %d priority %d has cookie %q, want %q", r.Table, r.Priority, r.Cookie, want)
		}
	}
}

func TestFlowRules_HandOffReaddressesTheFrameToTheTranslator(t *testing.T) {
	// The frame arrives addressed to the zone's router MAC. Output
	// unchanged, the translator interface sees PACKET_OTHERHOST and the
	// kernel drops it before Jool's netfilter hook; tagged, it is not an
	// IPv6 packet to the host at all.
	svc, _, _, _ := newTestService(t, nil)
	port := TranslatorPort{OFPort: 42, MAC: "02:aa:bb:cc:dd:ee"}
	var untagged, tagged *zoneflows.FlowRule
	rules := svc.FlowRules(port)
	for i := range rules {
		switch {
		case rules[i].Table == int(modes.TableNAT64) && rules[i].Priority == prioNAT64Handoff:
			untagged = &rules[i]
		case rules[i].Table == int(modes.TableNAT64) && rules[i].Priority == prioNAT64HandoffTagged:
			tagged = &rules[i]
		}
	}
	if untagged == nil || tagged == nil {
		t.Fatalf("want a tagged and an untagged hand-off: %+v", rules)
	}
	if untagged.Actions != "mod_dl_dst:02:aa:bb:cc:dd:ee,output:42" {
		t.Fatalf("untagged hand-off = %q", untagged.Actions)
	}
	if tagged.Actions != "strip_vlan,mod_dl_dst:02:aa:bb:cc:dd:ee,output:42" {
		t.Fatalf("tagged hand-off = %q", tagged.Actions)
	}
	if !strings.Contains(tagged.Match, "vlan_vid=0x1000/0x1000") || !strings.Contains(tagged.Match, "ipv6_dst=64:ff9b::/96") {
		t.Fatalf("tagged hand-off match = %q, want every tagged frame to the prefix", tagged.Match)
	}
	if tagged.Priority <= untagged.Priority {
		t.Fatal("the tagged hand-off must outrank the untagged one, which also matches a tagged frame")
	}
}

func TestFlowRules_InstallsNoTableTwentyMiss(t *testing.T) {
	// The table-20 miss is the pipeline's; a NAT64 copy would be the same
	// OpenFlow flow as the pipeline's, deleted from under every other
	// service by NAT64's Stop (#614).
	svc, _, _, _ := newTestService(t, nil)
	for _, r := range svc.FlowRules(testPort) {
		if r.Table == int(modes.TableCTGate) && r.Match == "" {
			t.Fatalf("nat64 installs an empty-match table-20 flow: %+v", r)
		}
	}
}

func TestStart_ProgramsTheTranslatorThenThePipeline(t *testing.T) {
	svc, driver, ctrl, _ := newTestService(t, nil)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	if !svc.Active() {
		t.Fatal("Start() left the service inactive")
	}
	if driver.applyCount() != 1 {
		t.Fatalf("driver applied %d times, want 1", driver.applyCount())
	}
	if len(ctrl.allRules()) == 0 {
		t.Fatal("Start() installed no flows")
	}
	if driver.applied[0].Pool6 != "64:ff9b::/96" {
		t.Fatalf("instance pool6 = %q", driver.applied[0].Pool6)
	}
	if !svc.Health().InstancePresent {
		t.Fatal("Health() after Start() does not carry the kernel's answer")
	}
}

func TestStart_SweepsFlowsAPreviousProcessLeftBehind(t *testing.T) {
	// A control process that exited without Stop leaves its cookie-owned
	// flows in place. The new set goes in first under a fresh generation;
	// only then is every flow still carrying another generation deleted,
	// each by its exact cookie. A flow of another owner is never touched.
	svc, _, ctrl, client := newTestService(t, nil)
	client.set(func(f *fakeOVS) {
		f.flows = []*ovs.Flow{
			{Cookie: "0xf1be000400000007"},
			{Cookie: "0xf1be000400000007"},
			{Cookie: "0xF1BE000400000009"},
			{Cookie: "0xf1be000100000000"},
		}
	})
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })

	if len(ctrl.allRules()) == 0 {
		t.Fatal("nothing was installed")
	}
	got, masks := client.deletedCookies(), client.masks()
	if len(got) != 2 {
		t.Fatalf("swept %x, want generations 7 and 9 once each", got)
	}
	want := map[uint64]bool{0xf1be000400000007: true, 0xf1be000400000009: true}
	for i, c := range got {
		if !want[c] || masks[i] != ^uint64(0) {
			t.Fatalf("delete %d = cookie %x mask %x, want an exact stale NAT64 cookie", i, c, masks[i])
		}
	}
	if svc.cookie()&CookieMask != CookieNAT64 || svc.cookie() == CookieNAT64 {
		t.Fatalf("this start's cookie %x carries no generation under the NAT64 owner", svc.cookie())
	}
	for _, r := range ctrl.allRules() {
		if r.Cookie != fmt.Sprintf("0x%x", svc.cookie()) {
			t.Fatalf("rule %+v does not carry this start's cookie %x", r, svc.cookie())
		}
	}
}

func TestStart_NeverSweepsBeforeTheNewSetIsInstalled(t *testing.T) {
	// Sweeping first would leave an adopted translator's sessions
	// unreachable through any later failure (#614 review).
	svc, driver, ctrl, client := newTestService(t, nil)
	driver.set(func(d *fakeDriver) { d.adopted = true })
	client.set(func(f *fakeOVS) { f.flows = []*ovs.Flow{{Cookie: "0xf1be000400000007"}} })
	ctrl.installErr = errors.New("ovs is unreachable")
	if err := svc.Start(context.Background()); err == nil {
		t.Fatal("Start() succeeded with no flows installed")
	}
	if got := client.deletedCookies(); len(got) != 0 {
		t.Fatalf("a failed start deleted %x", got)
	}
}

func TestStart_ASweepThatFailsIsReportedNotFatal(t *testing.T) {
	// The new set is in and translating; stale flows beside it are a
	// health finding the reconcile loop retries, not a reason to tear the
	// working set down.
	svc, _, _, client := newTestService(t, nil)
	client.set(func(f *fakeOVS) { f.statsErr = errors.New("ovs is unreachable") })
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v, want a running service", err)
	}
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	var op *OpError
	if h := svc.Health(); !h.Active || !errors.As(h.LastError, &op) || op.Op != "sweep" {
		t.Fatalf("Health() = %+v, want active with the sweep failure in LastError", h)
	}

	client.set(func(f *fakeOVS) { f.statsErr = nil })
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() = %v, want the sweep retried and the service healthy", err)
	}
	if svc.Health().LastError != nil {
		t.Fatal("a successful retry left the failure in health")
	}
}

func TestReconcile_RefusesWhileTheSweepCannotRun(t *testing.T) {
	svc, _, _, client := newTestService(t, nil)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	client.set(func(f *fakeOVS) {
		f.flows = []*ovs.Flow{{Cookie: "0xf1be000400000007"}}
		f.cookieErr = errors.New("ovs is unreachable")
	})
	var op *OpError
	if err := svc.Reconcile(context.Background()); !errors.As(err, &op) || op.Op != "sweep" {
		t.Fatalf("Reconcile() = %v, want *OpError{Op: sweep}", err)
	}
	if !errors.As(svc.Health().LastError, &op) {
		t.Fatal("the failed sweep is not in health")
	}
}

func TestStart_RefusesToRunTwice(t *testing.T) {
	svc, _, _, _ := newTestService(t, nil)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	if err := svc.Start(context.Background()); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start() = %v, want %v", err, ErrAlreadyStarted)
	}
}

func TestStart_RefusesATranslatorPortThatDoesNotResolve(t *testing.T) {
	// Outputting to a port that is not there is a black hole that reports
	// success, so the port is resolved before anything is programmed.
	svc, driver, _, client := newTestService(t, nil)
	client.set(func(f *fakeOVS) { f.ifaceErr = errors.New("no such port") })

	err := svc.Start(context.Background())
	var typed *OpError
	if !errors.As(err, &typed) || typed.Op != "resolve-port" {
		t.Fatalf("Start() = %v, want an OpError naming resolve-port", err)
	}
	if driver.applyCount() != 0 {
		t.Fatal("Start() programmed the kernel before knowing where to send frames")
	}
}

func TestStart_RefusesAPortWithNoOpenFlowNumber(t *testing.T) {
	svc, _, _, client := newTestService(t, nil)
	client.set(func(f *fakeOVS) { f.ofPort = 0 })
	if err := svc.Start(context.Background()); !errors.Is(err, ErrNoTranslatorOFPort) {
		t.Fatalf("Start() = %v, want %v", err, ErrNoTranslatorOFPort)
	}
}

func TestStart_RefusesAPortWithNoMAC(t *testing.T) {
	// The hand-off rewrites every frame to the port's MAC; without one the
	// kernel would drop each frame as addressed to another host.
	svc, _, _, client := newTestService(t, nil)
	client.set(func(f *fakeOVS) { f.mac = "" })
	err := svc.Start(context.Background())
	var typed *ErrTranslatorPortMAC
	if !errors.As(err, &typed) || typed.Port != "nat640" {
		t.Fatalf("Start() = %v, want *ErrTranslatorPortMAC naming nat640", err)
	}
	if !strings.Contains(typed.Error(), "nat640") {
		t.Fatalf("error text %q does not name the port", typed.Error())
	}
}

func TestStart_RollsBackACreatedTranslatorAndPartialFlows(t *testing.T) {
	// A translator with no flows translates nothing; leaving it behind
	// would be a kernel instance no configuration accounts for, and any
	// flow the failed batch did install is swept with it.
	svc, driver, ctrl, client := newTestService(t, nil)
	ctrl.installErr = errors.New("ovs is unreachable")

	err := svc.Start(context.Background())
	var op *OpError
	if !errors.As(err, &op) || op.Op != "install" {
		t.Fatalf("Start() = %v, want *OpError{Op: install}", err)
	}
	if got := driver.removedNames(); len(got) != 1 || got[0] != "tp-nat64" {
		t.Fatalf("removed = %v, want the instance rolled back", got)
	}
	if got, masks := client.deletedCookies(), client.masks(); len(got) != 1 || got[0] != CookieNAT64 || masks[0] != CookieMask {
		t.Fatalf("cookie deletes = %x, want every flow under the NAT64 owner", got)
	}
	if svc.Active() {
		t.Fatal("a failed Start() left the service active")
	}
}

func TestStart_LeavesAnAdoptedDatapathAloneWhenTheStartFails(t *testing.T) {
	// The instance was already there, carrying the previous process's
	// sessions, and so were the flows that reach it. A failed start is no
	// reason to drop either (#614 review).
	for name, breakIt := range map[string]func(*fakeDriver, *fakeController){
		"stats":   func(d *fakeDriver, _ *fakeController) { d.statsErr = errors.New("netlink: busy") },
		"absent":  func(d *fakeDriver, _ *fakeController) { d.stats = Stats{Present: false} },
		"install": func(_ *fakeDriver, c *fakeController) { c.installErr = errors.New("ovs is unreachable") },
	} {
		t.Run(name, func(t *testing.T) {
			svc, driver, ctrl, client := newTestService(t, nil)
			client.set(func(f *fakeOVS) { f.flows = []*ovs.Flow{{Cookie: "0xf1be000400000007"}} })
			driver.set(func(d *fakeDriver) {
				d.adopted = true
				breakIt(d, ctrl)
			})
			if err := svc.Start(context.Background()); err == nil {
				t.Fatal("Start() succeeded")
			}
			if got := driver.removedNames(); len(got) != 0 {
				t.Fatalf("a failed start removed an adopted instance: %v", got)
			}
			if got := client.deletedCookies(); len(got) != 0 {
				t.Fatalf("a failed start deleted flows reaching an adopted instance: %x", got)
			}
			if svc.Active() {
				t.Fatal("a failed Start() left the service active")
			}
		})
	}
}

func TestStart_ReportsARollbackThatAlsoFails(t *testing.T) {
	svc, driver, ctrl, _ := newTestService(t, nil)
	ctrl.installErr = errors.New("ovs is unreachable")
	driver.set(func(d *fakeDriver) { d.removeErr = errors.New("permission denied") })

	err := svc.Start(context.Background())
	var typed *ErrRollbackIncomplete
	if !errors.As(err, &typed) {
		t.Fatalf("Start() = %v, want *ErrRollbackIncomplete", err)
	}
	if !errors.Is(err, ctrl.installErr) {
		t.Fatal("the rollback failure hid the cause")
	}
	if !strings.Contains(err.Error(), "permission denied") || !strings.Contains(err.Error(), "ovs is unreachable") {
		t.Fatalf("error text %q drops one of the two failures", err.Error())
	}
	if svc.Active() {
		t.Fatal("a failed Start() left the service active")
	}
}

func TestStart_RefusesAnInstanceTheKernelDoesNotHold(t *testing.T) {
	// Health starts from the kernel, not from Apply's word: a driver that
	// converged and then reports no instance is a failed start.
	svc, driver, ctrl, _ := newTestService(t, nil)
	driver.set(func(d *fakeDriver) { d.stats = Stats{Present: false} })
	if err := svc.Start(context.Background()); !errors.Is(err, ErrInstanceVanished) {
		t.Fatalf("Start() = %v, want %v", err, ErrInstanceVanished)
	}
	if len(ctrl.allRules()) != 0 {
		t.Fatal("Start() diverted traffic to a translator the kernel does not hold")
	}
}

func TestStart_RefusesStatsItCannotRead(t *testing.T) {
	svc, driver, _, _ := newTestService(t, nil)
	driver.set(func(d *fakeDriver) { d.statsErr = errors.New("netlink: permission denied") })
	if err := svc.Start(context.Background()); err == nil || svc.Active() {
		t.Fatalf("Start() = %v with active=%v, want a refused start", err, svc.Active())
	}
	if got := driver.removedNames(); len(got) != 1 {
		t.Fatalf("removed = %v, want the created instance rolled back", got)
	}
}

func TestStart_RefusesWhenTheKernelCannotCarryTheTranslator(t *testing.T) {
	svc, driver, ctrl, _ := newTestService(t, nil)
	driver.set(func(d *fakeDriver) {
		d.applyErr = &ErrNAT64ModuleUnavailable{Instance: "tp-nat64", Err: errors.New("module not found")}
	})

	err := svc.Start(context.Background())
	var typed *ErrNAT64ModuleUnavailable
	if !errors.As(err, &typed) {
		t.Fatalf("Start() = %v, want *ErrNAT64ModuleUnavailable", err)
	}
	if len(ctrl.allRules()) != 0 {
		t.Fatal("Start() installed flows pointing at a translator that does not exist")
	}
}

func TestStop_RemovesTheFlowsBeforeTheTranslator(t *testing.T) {
	svc, driver, _, client := newTestService(t, nil)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() = %v", err)
	}
	if got, masks := client.deletedCookies(), client.masks(); len(got) != 1 || got[0] != CookieNAT64 || masks[0] != CookieMask {
		t.Fatalf("deleted cookies = %x, want every generation under the NAT64 owner, once", got)
	}
	if got := driver.removedNames(); len(got) != 1 {
		t.Fatalf("removed = %v, want the instance deleted once", got)
	}
	if svc.Active() {
		t.Fatal("Stop() left the service active")
	}
}

func TestStop_RefusesWhenNotStarted(t *testing.T) {
	svc, _, _, _ := newTestService(t, nil)
	if err := svc.Stop(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("Stop() = %v, want %v", err, ErrNotStarted)
	}
}

func TestStop_LeavesTheTranslatorAloneWhenTheFlowsWillNotGo(t *testing.T) {
	// Deleting the instance while frames are still diverted to it would
	// black-hole them; the flows go first or nothing goes.
	svc, driver, _, client := newTestService(t, nil)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	client.set(func(f *fakeOVS) { f.cookieErr = errors.New("ovs is unreachable") })

	if err := svc.Stop(context.Background()); err == nil {
		t.Fatal("Stop() reported success with the flows still installed")
	}
	if len(driver.removedNames()) != 0 {
		t.Fatal("Stop() deleted the translator while frames were still diverted to it")
	}
	if !svc.Active() {
		t.Fatal("a failed Stop() reported the service as stopped")
	}

	// The retry succeeds once the bridge answers.
	client.set(func(f *fakeOVS) { f.cookieErr = nil })
	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("retried Stop() = %v", err)
	}
}

func TestStop_StaysActiveWhenTheTranslatorWillNotGo(t *testing.T) {
	// The flows are gone, so nothing is diverted at the translator any
	// more and no traffic is harmed, but the kernel instance is still
	// there. Reporting the service as stopped would leak it silently, so
	// Stop stays active and the operator can retry. Reconcile must not put
	// the flows back meanwhile.
	svc, driver, ctrl, _ := newTestService(t, nil)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	driver.set(func(d *fakeDriver) { d.removeErr = errors.New("permission denied") })

	if err := svc.Stop(context.Background()); err == nil {
		t.Fatal("Stop() reported success with the instance still in the kernel")
	}
	if !svc.Active() {
		t.Fatal("Stop() reported the service stopped while its instance is still there")
	}
	installed := len(ctrl.allRules())
	if err := svc.Reconcile(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("Reconcile() during a half-done stop = %v, want %v", err, ErrNotStarted)
	}
	if len(ctrl.allRules()) != installed {
		t.Fatal("Reconcile() re-diverted traffic to a translator being torn down")
	}
}

func TestReconcileLoop_RunsUntilStop(t *testing.T) {
	// The loop is what makes health the kernel's answer after Start: it
	// re-reads Stats on its own. It must also be gone once Stop returns,
	// or a late pass would reinstall the flows Stop just deleted.
	calls := make(chan struct{}, 16)
	svc, driver, ctrl, _ := newTestService(t, func(d *Deps) {
		d.ReconcileInterval = time.Millisecond
	})
	driver.set(func(d *fakeDriver) {
		d.statsCalls = calls
		d.stats = Stats{Present: true, Sessions: 5}
	})
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	<-calls // Start's own read
	<-calls // the loop's first pass
	<-calls // and a second, so it is a loop

	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() = %v", err)
	}
	applied, installed := driver.applyCount(), len(ctrl.allRules())
	select {
	case <-calls:
		// A pass that was already reading when Stop began may land here;
		// it must not have converged anything after Stop returned.
	default:
	}
	if driver.applyCount() != applied || len(ctrl.allRules()) != installed {
		t.Fatal("the reconcile loop ran after Stop returned")
	}
}

func TestReconcile_ConvergesWithoutFlushing(t *testing.T) {
	svc, driver, ctrl, _ := newTestService(t, nil)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	driver.set(func(d *fakeDriver) {
		d.stats = Stats{Present: true, Sessions: 11, Pool4Used: 4, ModuleVersion: "4.1.14"}
	})

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}
	if len(driver.removedNames()) != 0 {
		t.Fatal("Reconcile() tore the instance down instead of converging it")
	}
	if driver.applyCount() != 2 {
		t.Fatalf("driver applied %d times, want the instance re-converged", driver.applyCount())
	}
	if len(ctrl.allRules()) == 0 {
		t.Fatal("Reconcile() installed no flows")
	}
	h := svc.Health()
	if h.Sessions != 11 || h.Pool4Used != 4 || h.ModuleVersion != "4.1.14" {
		t.Fatalf("Health() did not take the kernel's numbers: %+v", h)
	}
}

func TestReconcile_RefusesWhenNotStarted(t *testing.T) {
	svc, _, _, _ := newTestService(t, nil)
	if err := svc.Reconcile(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("Reconcile() = %v, want %v", err, ErrNotStarted)
	}
}

func TestReconcile_ReinstallsAgainstAMovedTranslatorPort(t *testing.T) {
	svc, _, ctrl, client := newTestService(t, nil)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	client.set(func(f *fakeOVS) { f.ofPort = 99 })

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}
	var found bool
	for _, r := range ctrl.allRules() {
		if strings.HasSuffix(r.Actions, "output:99") {
			found = true
		}
	}
	if !found {
		t.Fatal("Reconcile() kept pointing at the old OpenFlow port")
	}
}

func TestReconcile_RecordsEveryFailureInHealth(t *testing.T) {
	tests := []struct {
		name   string
		break_ func(*fakeDriver, *fakeController, *fakeOVS)
	}{
		{"an unresolvable port", func(_ *fakeDriver, _ *fakeController, o *fakeOVS) {
			o.set(func(f *fakeOVS) { f.ifaceErr = errors.New("no such port") })
		}},
		{"a port with no OpenFlow number", func(_ *fakeDriver, _ *fakeController, o *fakeOVS) {
			o.set(func(f *fakeOVS) { f.ofPort = 0 })
		}},
		{"a translator that will not converge", func(d *fakeDriver, _ *fakeController, _ *fakeOVS) {
			d.set(func(d *fakeDriver) { d.applyErr = errors.New("module unloaded") })
		}},
		{"flows that will not install", func(_ *fakeDriver, c *fakeController, _ *fakeOVS) {
			c.mu.Lock()
			c.installErr = errors.New("ovs is unreachable")
			c.mu.Unlock()
		}},
		{"stats that cannot be read", func(d *fakeDriver, _ *fakeController, _ *fakeOVS) {
			d.set(func(d *fakeDriver) { d.statsErr = errors.New("netlink: permission denied") })
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, driver, ctrl, client := newTestService(t, nil)
			if err := svc.Start(context.Background()); err != nil {
				t.Fatalf("Start() = %v", err)
			}
			t.Cleanup(func() {
				driver.set(func(d *fakeDriver) { d.applyErr, d.statsErr = nil, nil })
				_ = svc.Stop(context.Background())
			})
			tc.break_(driver, ctrl, client)

			if err := svc.Reconcile(context.Background()); err == nil {
				t.Fatal("Reconcile() reported success")
			}
			if svc.Health().LastError == nil {
				t.Fatal("Health() hides the failure the operator has to act on")
			}
		})
	}
}

func TestHealth_ReportsAnInstanceThatHasGone(t *testing.T) {
	// A started service whose kernel instance disappeared must say so; a
	// bool that reports the configuration back is the #568 defect.
	svc, driver, _, _ := newTestService(t, nil)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	driver.set(func(d *fakeDriver) { d.stats = Stats{Present: false} })
	if err := svc.Reconcile(context.Background()); !errors.Is(err, ErrInstanceVanished) {
		t.Fatalf("Reconcile() = %v, want %v", err, ErrInstanceVanished)
	}
	h := svc.Health()
	if !h.Active {
		t.Fatal("Health() reports the service as stopped; it is started")
	}
	if h.InstancePresent {
		t.Fatal("Health() reports an instance that is gone as present")
	}
	if !errors.Is(h.LastError, ErrInstanceVanished) {
		t.Fatalf("Health().LastError = %v, want %v", h.LastError, ErrInstanceVanished)
	}
}

func TestHealth_CarriesTheIdentityAnOperatorNeeds(t *testing.T) {
	svc, _, _, _ := newTestService(t, nil)
	h := svc.Health()
	if h.Prefix != "64:ff9b::/96" || h.Instance != "tp-nat64" {
		t.Fatalf("Health() = %+v, want the prefix and instance named", h)
	}
	if h.Active {
		t.Fatal("Health() reports an unstarted service as active")
	}
}

// gotoTarget extracts N from a "goto_table:N" action.
func gotoTarget(actions string) (int, bool) {
	const prefix = "goto_table:"
	idx := strings.Index(actions, prefix)
	if idx < 0 {
		return 0, false
	}
	rest := actions[idx+len(prefix):]
	end := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
	if end >= 0 {
		rest = rest[:end]
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}
	return n, true
}
