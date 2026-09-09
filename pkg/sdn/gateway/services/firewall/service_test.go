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

	mu            sync.Mutex
	strictDeletes []*ovs.FlowMod
	cookieDeletes []uint64
	strictErr     error
	cookieErr     error
	ofPortErr     error
	ofPort        int32
	// ofPorts maps port names to OpenFlow ports for multi-uplink tests;
	// a name not present falls back to ofPort (or 7).
	ofPorts map[string]int32
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
			{Name: zone.ZoneTrusted, AllowTo: []zone.ZonePath{{Zone: zone.ZonePublic}}},
			{Name: zone.ZonePublic, IsolateFrom: []zone.Zone{zone.ZoneTrusted}},
		},
		networks: map[zone.Zone]zoneflows.NetworkSummary{
			zone.ZoneTrusted: {VLAN: 100, Subnet: "10.0.100.0/24"},
			zone.ZonePublic:  {VLAN: 200, Subnet: "10.0.200.0/24"},
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
	controller := &fakeController{}
	ovsClient := &fakeOVS{}
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

	// Every rule carries the firewall cookie.
	wantCookie := fmt.Sprintf("0x%x", CookieFirewall)
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
	if _, ok := deps.Allocator.Lookup(AllocatorOwnerFirewall, string(zone.ZoneTrusted)); ok {
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
		zone.ZoneConfig{Name: zone.ZoneStorage, AllowTo: []zone.ZonePath{{Zone: zone.ZoneTrusted}}},
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
