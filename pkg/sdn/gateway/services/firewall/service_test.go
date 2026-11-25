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

package firewall

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ct"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// fakeController records installed flow batches and injects failures.
type fakeController struct {
	mu         sync.Mutex
	batches    [][]zoneflows.FlowRule
	installErr error
	// failAt, when set, limits installErr to the install call with that
	// 1-based number; attempts counts the calls.
	failAt   int
	attempts int
	// bridge, when set, receives every installed batch.
	bridge *fakeOVS
}

func (f *fakeController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	return f.InstallFlows(bridgeName, []zoneflows.FlowRule{{Priority: priority, Match: match, Actions: actions}})
}

func (f *fakeController) InstallFlows(bridgeName string, rules []zoneflows.FlowRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.installErr != nil && (f.failAt == 0 || f.failAt == f.attempts) {
		return f.installErr
	}
	f.batches = append(f.batches, rules)
	if f.bridge != nil {
		f.bridge.install(rules)
	}
	return nil
}

func (f *fakeController) DeleteFlow(bridgeName string, match string) error { return nil }

func (f *fakeController) DeleteFlowsByPort(bridgeName string, portID string) error { return nil }

func (f *fakeController) ListFlows(bridgeName string) ([]string, error) { return nil, nil }

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

// batchCount returns the number of InstallFlows transactions.
func (f *fakeController) batchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.batches)
}

// fakeOVS overrides only the client methods the services use; any other
// call panics via the embedded nil interface, flagging an unexpected
// dependency.
type fakeOVS struct {
	ovs.ClientInterface

	mu sync.Mutex
	// flows is the bridge's flow table: the controller's installs land in
	// it with OFPFC_ADD semantics, deletes remove from it and GetFlowStats
	// reads it, so a Start's generation sweep runs against real state.
	flows         []*ovs.Flow
	statsErr      error
	strictDeletes []*ovs.FlowMod
	cookieDeletes []uint64
	strictErr     error
	cookieErr     error
	// sweepErr fails only exact-cookie deletes, the generation sweep's, so
	// an owner-wide delete still runs.
	sweepErr  error
	ofPortErr error
	ofPort    int32
	// ofPorts maps port names to OpenFlow ports for multi-uplink tests;
	// a name not present falls back to ofPort (or 7).
	ofPorts map[string]int32
}

// cookieOf parses a "0x%x" flow cookie; anything else reads as zero.
func cookieOf(cookie string) uint64 {
	var c uint64
	if _, err := fmt.Sscanf(cookie, "0x%x", &c); err != nil {
		return 0
	}
	return c
}

// install applies OFPFC_ADD: a rule replaces the flow of identical
// (table, priority, match), cookie included, and is appended otherwise.
func (f *fakeOVS) install(rules []zoneflows.FlowRule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rule := range rules {
		flow := &ovs.Flow{Table: rule.Table, Priority: rule.Priority, Match: rule.Match, Actions: rule.Actions, Cookie: rule.Cookie}
		replaced := false
		for i, existing := range f.flows {
			if existing.Table == rule.Table && existing.Priority == rule.Priority && existing.Match == rule.Match {
				f.flows[i] = flow
				replaced = true
				break
			}
		}
		if !replaced {
			f.flows = append(f.flows, flow)
		}
	}
}

// seed puts a flow on the bridge as another process would have.
func (f *fakeOVS) seed(flow *ovs.Flow) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flows = append(f.flows, flow)
}

// flowsUnder returns the flows on the bridge whose cookie carries owner.
func (f *fakeOVS) flowsUnder(owner uint64) []*ovs.Flow {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*ovs.Flow
	for _, flow := range f.flows {
		if cookieOf(flow.Cookie)&CookieMask == owner {
			out = append(out, flow)
		}
	}
	return out
}

func (f *fakeOVS) GetFlowStats(ctx context.Context, bridgeName string, match string) ([]*ovs.Flow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statsErr != nil {
		return nil, f.statsErr
	}
	var cookie, mask uint64
	if _, err := fmt.Sscanf(match, "cookie=0x%x/0x%x", &cookie, &mask); err != nil {
		return nil, err
	}
	var out []*ovs.Flow
	for _, flow := range f.flows {
		if cookieOf(flow.Cookie)&mask == cookie&mask {
			copied := *flow
			out = append(out, &copied)
		}
	}
	return out, nil
}

func (f *fakeOVS) DeleteFlowStrict(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.strictErr != nil {
		return f.strictErr
	}
	f.strictDeletes = append(f.strictDeletes, flow)
	kept := f.flows[:0]
	for _, existing := range f.flows {
		if existing.Table != flow.Table || existing.Priority != flow.Priority || existing.Match != flow.Match {
			kept = append(kept, existing)
		}
	}
	f.flows = kept
	return nil
}

func (f *fakeOVS) DeleteFlowsByCookie(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cookieErr != nil {
		return f.cookieErr
	}
	if f.sweepErr != nil && cookieMask == ^uint64(0) {
		return f.sweepErr
	}
	f.cookieDeletes = append(f.cookieDeletes, cookie)
	kept := f.flows[:0]
	for _, flow := range f.flows {
		if cookieOf(flow.Cookie)&cookieMask != cookie&cookieMask {
			kept = append(kept, flow)
		}
	}
	f.flows = kept
	return nil
}

func (f *fakeOVS) GetOFPort(ctx context.Context, portName string) (int32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ofPortErr != nil {
		return 0, f.ofPortErr
	}
	if port, ok := f.ofPorts[portName]; ok {
		return port, nil
	}
	if f.ofPort == 0 {
		return 7, nil
	}
	return f.ofPort, nil
}

// zoneProvider is a mutable two-zone topology for reconcile tests.
type zoneProvider struct {
	mu       sync.Mutex
	zones    []zone.ZoneConfig
	networks map[zone.Zone]zoneflows.NetworkSummary
}

func newZoneProvider() *zoneProvider {
	return &zoneProvider{
		zones: []zone.ZoneConfig{
			{Name: zone.ZoneControlPlane, AllowTo: []zone.ZonePath{{Zone: zone.ZoneBackup}}},
			{Name: zone.ZoneBackup, IsolateFrom: []zone.Zone{zone.ZoneControlPlane}},
		},
		networks: map[zone.Zone]zoneflows.NetworkSummary{
			zone.ZoneControlPlane: {VLAN: 100, Subnet: "10.0.100.0/24"},
			zone.ZoneBackup:       {VLAN: 200, Subnet: "10.0.200.0/24"},
		},
	}
}

func (p *zoneProvider) Zones() []zone.ZoneConfig {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]zone.ZoneConfig, len(p.zones))
	copy(out, p.zones)
	return out
}

func (p *zoneProvider) Networks() map[zone.Zone]zoneflows.NetworkSummary {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[zone.Zone]zoneflows.NetworkSummary, len(p.networks))
	for k, v := range p.networks {
		out[k] = v
	}
	return out
}

func (p *zoneProvider) addZone(cfg zone.ZoneConfig, net zoneflows.NetworkSummary) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.zones = append(p.zones, cfg)
	p.networks[cfg.Name] = net
}

func (p *zoneProvider) removeZone(name zone.Zone) {
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.zones[:0]
	for _, z := range p.zones {
		if z.Name != name {
			kept = append(kept, z)
		}
	}
	p.zones = kept
	delete(p.networks, name)
}

// testDeps builds a valid Deps with fresh fakes.
func testDeps() (Deps, *fakeController, *fakeOVS, *zoneProvider) {
	ovsClient := &fakeOVS{}
	controller := &fakeController{bridge: ovsClient}
	provider := newZoneProvider()
	deps := Deps{
		Controller: controller,
		OVS:        ovsClient,
		Config:     Config{DefaultPolicy: PolicyDeny, Bridge: "br-test"},
		Zones:      provider.Zones,
		Networks:   provider.Networks,
		Allocator:  ct.NewZoneAllocator(nil),
	}
	return deps, controller, ovsClient, provider
}

func TestNew(t *testing.T) {
	deps, _, _, _ := testDeps()
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if svc.Active() {
		t.Error("new service must not be active")
	}
}

func TestNew_Validation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(d *Deps)
		wantErr error
	}{
		{name: "nil controller", mutate: func(d *Deps) { d.Controller = nil }, wantErr: ErrNilController},
		{name: "nil ovs", mutate: func(d *Deps) { d.OVS = nil }, wantErr: ErrNilOVSClient},
		{name: "nil allocator", mutate: func(d *Deps) { d.Allocator = nil }, wantErr: ErrNilAllocator},
		{name: "nil zones", mutate: func(d *Deps) { d.Zones = nil }, wantErr: ErrNilZones},
		{name: "nil networks", mutate: func(d *Deps) { d.Networks = nil }, wantErr: ErrNilNetworks},
		{name: "empty bridge", mutate: func(d *Deps) { d.Config.Bridge = "" }, wantErr: ErrEmptyBridge},
		{name: "bad policy", mutate: func(d *Deps) { d.Config.DefaultPolicy = "maybe" }, wantErr: ErrInvalidDefaultPolicy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _, _, _ := testDeps()
			tt.mutate(&deps)
			if _, err := New(deps); !errors.Is(err, tt.wantErr) {
				t.Errorf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestService_Start(t *testing.T) {
	deps, controller, _, _ := testDeps()
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !svc.Active() {
		t.Fatal("service should be active")
	}

	// Two batches: the pipeline, then the gate.
	if got := controller.batchCount(); got != 2 {
		t.Fatalf("expected 2 install batches, got %d", got)
	}

	rules := controller.allRules()
	gate := rules[len(rules)-1]
	if gate.Table != gateTable || gate.Priority != firewallGatePriority || gate.Actions != "goto_table:20" {
		t.Errorf("unexpected gate rule: %+v", gate)
	}

	// Every rule carries the firewall owner and this start's generation.
	wantCookie := gate.Cookie
	if c := cookieOf(wantCookie); c&CookieMask != CookieFirewall || c == CookieFirewall {
		t.Fatalf("gate cookie %q is not the firewall owner with a generation", wantCookie)
	}
	for i, rule := range rules {
		if rule.Cookie != wantCookie {
			t.Errorf("rule %d cookie = %q, want %q", i, rule.Cookie, wantCookie)
		}
	}

	health := svc.Health()
	if !health.Active || health.FlowCount == 0 || len(health.CTZones) != 2 {
		t.Errorf("unexpected health: %+v", health)
	}
	if health.LastReconcile.IsZero() {
		t.Error("LastReconcile must be set after start")
	}
}

func TestService_StartTwice(t *testing.T) {
	deps, _, _, _ := testDeps()
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := svc.Start(ctx); !errors.Is(err, ErrAlreadyStarted) {
		t.Errorf("expected ErrAlreadyStarted, got %v", err)
	}
}

func TestService_StartInstallError(t *testing.T) {
	deps, controller, _, _ := testDeps()
	controller.installErr = errors.New("switch down")

	svc, err := New(deps)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	err = svc.Start(context.Background())
	if err == nil {
		t.Fatal("expected install error")
	}
	var opErr *OpError
	if !errors.As(err, &opErr) || opErr.Op != "install" {
		t.Errorf("expected install OpError, got %v", err)
	}
	if svc.Active() {
		t.Error("service must not be active after failed start")
	}
}

// A process that exits without Stop leaves its flows on the bridge (#557).
// The next Start installs the current set under a fresh generation, then
// sweeps what the previous generation had that the zone matrix no longer
// has, and leaves every other owner's flows alone.
func TestService_StartSweepsAPreviousProcessFlows(t *testing.T) {
	deps, _, ovsClient, provider := testDeps()
	ctx := context.Background()

	// The previous process ran with a third zone the next one drops.
	provider.addZone(
		zone.ZoneConfig{Name: zone.ZoneStorage, AllowTo: []zone.ZonePath{{Zone: zone.ZoneControlPlane}}},
		zoneflows.NetworkSummary{VLAN: 300, Subnet: "10.0.30.0/24"},
	)
	previous, err := New(deps)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := previous.Start(ctx); err != nil {
		t.Fatalf("previous start: %v", err)
	}
	previousFlows := len(ovsClient.flowsUnder(CookieFirewall))
	previousCookie := previous.gateRule().Cookie

	natFlow := &ovs.Flow{
		Table:    gateTable,
		Priority: natGatePriority,
		Actions:  "goto_table:20",
		Cookie:   fmt.Sprintf("0x%x", CookieNAT|0x1),
	}
	ovsClient.seed(natFlow)

	provider.removeZone(zone.ZoneStorage)
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	gate := svc.gateRule()
	if gate.Cookie == previousCookie {
		t.Fatalf("the restart reused generation %s", previousCookie)
	}
	current := ovsClient.flowsUnder(CookieFirewall)
	if want := svc.Health().FlowCount + 1; len(current) != want {
		t.Errorf("bridge holds %d firewall flows, want the %d rules and the gate", len(current), want-1)
	}
	if len(current) >= previousFlows {
		t.Errorf("the dropped zone's flows survived: %d flows now, %d before", len(current), previousFlows)
	}
	gateFound := false
	for _, flow := range current {
		if flow.Cookie != gate.Cookie {
			t.Errorf("flow %+v kept cookie %s, want the current generation %s", flow, flow.Cookie, gate.Cookie)
		}
		if flow.Table == gate.Table && flow.Priority == gate.Priority {
			gateFound = true
		}
	}
	if !gateFound {
		t.Error("the gate the new matrix still has must survive the sweep")
	}

	// The sweep deletes the previous generation exactly, nothing broader.
	ovsClient.mu.Lock()
	deletes := append([]uint64(nil), ovsClient.cookieDeletes...)
	ovsClient.mu.Unlock()
	if len(deletes) != 1 || deletes[0] != cookieOf(previousCookie) {
		t.Errorf("cookie deletes = %#x, want only the previous generation %s", deletes, previousCookie)
	}
	if nat := ovsClient.flowsUnder(CookieNAT); len(nat) != 1 || nat[0].Cookie != natFlow.Cookie {
		t.Errorf("another owner's flow was touched: %+v", nat)
	}
}

func TestService_StartSweepError(t *testing.T) {
	deps, _, ovsClient, _ := testDeps()
	ovsClient.statsErr = errors.New("dump-flows failed")

	svc, err := New(deps)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	err = svc.Start(context.Background())
	var opErr *OpError
	if !errors.As(err, &opErr) || opErr.Op != "sweep" {
		t.Fatalf("expected sweep OpError, got %v", err)
	}
	if !errors.Is(err, ovsClient.statsErr) {
		t.Errorf("the sweep error must wrap the cause, got %v", err)
	}
	if svc.Active() {
		t.Error("service must not be active after a failed sweep")
	}
}

// staleFlow is a flow a previous process left under owner: an older
// generation the current matrix does not replace.
func staleFlow(owner uint64) *ovs.Flow {
	return &ovs.Flow{
		Table:    gateTable,
		Priority: 50,
		Match:    "in_port=9",
		Actions:  "goto_table:20",
		Cookie:   fmt.Sprintf("0x%x", owner|0x1),
	}
}

// clearFaults removes every injected fault, so the next call succeeds.
func clearFaults(controller *fakeController, ovsClient *fakeOVS) {
	controller.installErr = nil
	ovsClient.statsErr = nil
	ovsClient.sweepErr = nil
	ovsClient.cookieErr = nil
}

// A failed Start leaves the bridge as Stop would (#557): no firewall gate,
// no firewall flow of any generation, the previous process's the failed
// sweep left included, and no conntrack zone. Another owner's flows stay,
// and the service can be started again.
func TestService_StartRollsBack(t *testing.T) {
	cases := []struct {
		name   string
		op     string
		inject func(cause error, controller *fakeController, ovsClient *fakeOVS)
	}{
		{
			name: "sweep stats query fails",
			op:   "sweep",
			inject: func(cause error, _ *fakeController, ovsClient *fakeOVS) {
				ovsClient.statsErr = cause
			},
		},
		{
			name: "sweep delete fails",
			op:   "sweep",
			inject: func(cause error, _ *fakeController, ovsClient *fakeOVS) {
				ovsClient.sweepErr = cause
			},
		},
		{
			name: "gate install fails after the pipeline",
			op:   "install",
			inject: func(cause error, controller *fakeController, _ *fakeOVS) {
				controller.installErr = cause
				controller.failAt = 2
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps, controller, ovsClient, _ := testDeps()
			allocator := deps.Allocator
			ctx := context.Background()
			ovsClient.seed(staleFlow(CookieFirewall))
			natFlow := staleFlow(CookieNAT)
			natFlow.Match = "in_port=8"
			ovsClient.seed(natFlow)
			cause := errors.New("injected fault")
			tc.inject(cause, controller, ovsClient)

			svc, err := New(deps)
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			err = svc.Start(ctx)
			var opErr *OpError
			if !errors.As(err, &opErr) || opErr.Op != tc.op {
				t.Fatalf("expected %s OpError, got %v", tc.op, err)
			}
			if !errors.Is(err, cause) {
				t.Errorf("the error must wrap the cause, got %v", err)
			}
			if svc.Active() {
				t.Error("service must not be active after a failed start")
			}
			if left := ovsClient.flowsUnder(CookieFirewall); len(left) != 0 {
				t.Errorf("a failed start left %d firewall flows live: %+v", len(left), left)
			}
			if zones := allocator.Snapshot(); len(zones) != 0 {
				t.Errorf("a failed start kept conntrack zones: %v", zones)
			}
			if nat := ovsClient.flowsUnder(CookieNAT); len(nat) != 1 || nat[0] != natFlow {
				t.Errorf("the rollback touched another owner's flow: %+v", nat)
			}

			clearFaults(controller, ovsClient)
			if err := svc.Start(ctx); err != nil {
				t.Fatalf("start after a rolled-back start: %v", err)
			}
			if !svc.Active() || len(svc.Health().CTZones) != 2 {
				t.Errorf("unexpected health after the second start: %+v", svc.Health())
			}
		})
	}
}

// A rollback that fails is joined to the Start error, never dropped, and
// the gate still goes first: with the owner-wide delete failing, no packet
// enters the pipeline left behind.
func TestService_StartRollbackError(t *testing.T) {
	deps, controller, ovsClient, _ := testDeps()
	allocator := deps.Allocator
	ctx := context.Background()
	ovsClient.statsErr = errors.New("dump-flows failed")
	ovsClient.cookieErr = errors.New("del-flows failed")

	svc, err := New(deps)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	err = svc.Start(ctx)
	if !errors.Is(err, ovsClient.statsErr) || !errors.Is(err, ovsClient.cookieErr) {
		t.Fatalf("both the sweep and the rollback cause must be reachable, got %v", err)
	}
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) || len(joined.Unwrap()) != 2 {
		t.Fatalf("expected the start and rollback errors joined, got %v", err)
	}
	var startErr, rollbackErr *OpError
	if parts := joined.Unwrap(); !errors.As(parts[0], &startErr) || !errors.As(parts[1], &rollbackErr) {
		t.Fatalf("both joined errors must be OpErrors, got %v", err)
	}
	if startErr.Op != "sweep" || rollbackErr.Op != "rollback" {
		t.Errorf("ops = %q, %q, want sweep, rollback", startErr.Op, rollbackErr.Op)
	}

	gate := svc.gateRule()
	for _, flow := range ovsClient.flowsUnder(CookieFirewall) {
		if flow.Table == gate.Table && flow.Priority == gate.Priority {
			t.Errorf("the gate outlived a failed rollback: %+v", flow)
		}
	}
	if zones := allocator.Snapshot(); len(zones) != 0 {
		t.Errorf("the zones must be released even when a delete fails: %v", zones)
	}

	clearFaults(controller, ovsClient)
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start after a failed rollback: %v", err)
	}
}

func TestService_Stop(t *testing.T) {
	deps, _, ovsClient, _ := testDeps()
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := svc.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if svc.Active() {
		t.Error("service should be inactive after stop")
	}

	ovsClient.mu.Lock()
	defer ovsClient.mu.Unlock()

	// The gate is strict-deleted before the cookie sweep.
	if len(ovsClient.strictDeletes) != 1 {
		t.Fatalf("expected 1 strict delete (gate), got %d", len(ovsClient.strictDeletes))
	}
	gate := ovsClient.strictDeletes[0]
	if gate.Table != gateTable || gate.Priority != firewallGatePriority {
		t.Errorf("unexpected gate delete: %+v", gate)
	}
	if len(ovsClient.cookieDeletes) != 1 || ovsClient.cookieDeletes[0] != CookieFirewall {
		t.Errorf("expected cookie sweep for CookieFirewall, got %v", ovsClient.cookieDeletes)
	}

	// Conntrack zones were released.
	if _, ok := deps.Allocator.Lookup(AllocatorOwnerFirewall, string(zone.ZoneControlPlane)); ok {
		t.Error("ct zone not released on stop")
	}
}

func TestService_StopErrors(t *testing.T) {
	t.Run("not started", func(t *testing.T) {
		deps, _, _, _ := testDeps()
		svc, err := New(deps)
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		if err := svc.Stop(context.Background()); !errors.Is(err, ErrNotStarted) {
			t.Errorf("expected ErrNotStarted, got %v", err)
		}
	})

	t.Run("gate delete failure", func(t *testing.T) {
		deps, _, ovsClient, _ := testDeps()
		svc, err := New(deps)
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		ctx := context.Background()
		if err := svc.Start(ctx); err != nil {
			t.Fatalf("start: %v", err)
		}

		ovsClient.mu.Lock()
		ovsClient.strictErr = errors.New("switch down")
		ovsClient.mu.Unlock()

		if err := svc.Stop(ctx); err == nil {
			t.Fatal("expected stop error")
		}
		if !svc.Active() {
			t.Error("service must stay active when gate removal fails")
		}
	})
}

func TestService_Reconcile(t *testing.T) {
	deps, controller, ovsClient, provider := testDeps()
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	baseline := svc.Health().FlowCount

	// No changes: nothing new installed, nothing deleted.
	batchesBefore := controller.batchCount()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	noopBatch := controller.allRules()[len(controller.allRules()):]
	if len(noopBatch) != 0 {
		t.Errorf("no-op reconcile must not install rules: %v", noopBatch)
	}
	if got := controller.batchCount(); got != batchesBefore+1 {
		t.Errorf("expected exactly one (empty) install batch, got %d new", got-batchesBefore)
	}

	// Add a zone: new gate/verdict flows appear.
	provider.addZone(
		zone.ZoneConfig{Name: zone.ZoneStorage, AllowTo: []zone.ZonePath{{Zone: zone.ZoneControlPlane}}},
		zoneflows.NetworkSummary{VLAN: 300, Subnet: "10.0.30.0/24"},
	)
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile after add: %v", err)
	}
	if got := svc.Health().FlowCount; got <= baseline {
		t.Errorf("flow count should grow after adding a zone: %d <= %d", got, baseline)
	}
	if len(svc.Health().CTZones) != 3 {
		t.Errorf("expected 3 ct zones, got %d", len(svc.Health().CTZones))
	}

	// Remove the zone again: stale flows are strict-deleted.
	provider.removeZone(zone.ZoneStorage)
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile after remove: %v", err)
	}
	if got := svc.Health().FlowCount; got != baseline {
		t.Errorf("flow count should return to baseline %d, got %d", baseline, got)
	}

	ovsClient.mu.Lock()
	staleDeletes := len(ovsClient.strictDeletes)
	ovsClient.mu.Unlock()
	if staleDeletes == 0 {
		t.Error("expected strict deletes for stale flows")
	}
}

func TestService_ReconcileErrors(t *testing.T) {
	t.Run("not started", func(t *testing.T) {
		deps, _, _, _ := testDeps()
		svc, err := New(deps)
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		if err := svc.Reconcile(context.Background()); !errors.Is(err, ErrNotStarted) {
			t.Errorf("expected ErrNotStarted, got %v", err)
		}
	})

	t.Run("install failure", func(t *testing.T) {
		deps, controller, _, provider := testDeps()
		svc, err := New(deps)
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		ctx := context.Background()
		if err := svc.Start(ctx); err != nil {
			t.Fatalf("start: %v", err)
		}

		provider.addZone(
			zone.ZoneConfig{Name: zone.ZoneStorage},
			zoneflows.NetworkSummary{VLAN: 300, Subnet: "10.0.30.0/24"},
		)
		controller.mu.Lock()
		controller.installErr = errors.New("switch down")
		controller.mu.Unlock()

		if err := svc.Reconcile(ctx); err == nil {
			t.Error("expected reconcile install error")
		}
	})
}

func TestService_Health_Inactive(t *testing.T) {
	deps, _, _, _ := testDeps()
	svc, err := New(deps)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	health := svc.Health()
	if health.Active || health.FlowCount != 0 || len(health.CTZones) != 0 {
		t.Errorf("unexpected inactive health: %+v", health)
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr error
	}{
		{name: "allow", cfg: Config{DefaultPolicy: PolicyAllow, Bridge: "br0"}},
		{name: "deny", cfg: Config{DefaultPolicy: PolicyDeny, Bridge: "br0"}},
		{name: "bad policy", cfg: Config{DefaultPolicy: "open", Bridge: "br0"}, wantErr: ErrInvalidDefaultPolicy},
		{name: "empty policy", cfg: Config{Bridge: "br0"}, wantErr: ErrInvalidDefaultPolicy},
		{name: "empty bridge", cfg: Config{DefaultPolicy: PolicyDeny}, wantErr: ErrEmptyBridge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestOpError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("boom")
	err := &OpError{Op: "install", Err: inner}
	if err.Error() != "firewall: install: boom" {
		t.Errorf("unexpected message: %s", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("Unwrap must expose the inner error")
	}
}
