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

package gateway

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ct"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/firewall"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// fakeFlowController records installed flows in memory.
type fakeFlowController struct {
	mu       sync.Mutex
	installs [][]zoneflows.FlowRule
}

func (f *fakeFlowController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	return f.InstallFlows(bridgeName, []zoneflows.FlowRule{{Priority: priority, Match: match, Actions: actions}})
}

func (f *fakeFlowController) InstallFlows(bridgeName string, rules []zoneflows.FlowRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installs = append(f.installs, rules)
	return nil
}

func (f *fakeFlowController) DeleteFlow(bridgeName string, match string) error { return nil }

func (f *fakeFlowController) DeleteFlowsByPort(bridgeName string, portID string) error { return nil }

func (f *fakeFlowController) ListFlows(bridgeName string) ([]string, error) { return nil, nil }

// fakeOVSClient overrides only the methods the firewall/NAT services call;
// any other call panics via the embedded nil interface, flagging an
// unexpected dependency in the test.
type fakeOVSClient struct {
	ovs.ClientInterface

	mu            sync.Mutex
	strictDeletes []*ovs.FlowMod
	cookieDeletes []uint64
}

func (f *fakeOVSClient) DeleteFlowStrict(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.strictDeletes = append(f.strictDeletes, flow)
	return nil
}

func (f *fakeOVSClient) DeleteFlowsByCookie(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cookieDeletes = append(f.cookieDeletes, cookie)
	return nil
}

func (f *fakeOVSClient) GetOFPort(ctx context.Context, portName string) (int32, error) {
	return 7, nil
}

// newTestRuntime builds a GatewayRuntime backed by in-memory fakes with a
// two-zone topology (trusted → public allowed, public → trusted denied).
func newTestRuntime() *GatewayRuntime {
	zones := []zone.ZoneConfig{
		{Name: zone.ZoneTrusted, AllowTo: []zone.ZonePath{{Zone: zone.ZonePublic}}},
		{Name: zone.ZonePublic, IsolateFrom: []zone.Zone{zone.ZoneTrusted}},
	}
	networks := map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneTrusted: {VLAN: 100, Subnet: "10.0.100.0/24"},
		zone.ZonePublic:  {VLAN: 200, Subnet: "10.0.200.0/24"},
	}
	return &GatewayRuntime{
		Controller: &fakeFlowController{},
		OVS:        &fakeOVSClient{},
		Bridge:     "br-test",
		Zones:      func() []zone.ZoneConfig { return zones },
		Networks:   func() map[zone.Zone]zoneflows.NetworkSummary { return networks },
		CTZones:    ct.NewZoneAllocator(nil),
	}
}

// firewallGatewayConfig returns a gateway config with the firewall service
// enabled and the test runtime injected.
func firewallGatewayConfig() *GatewayConfig {
	return &GatewayConfig{
		Enabled:       true,
		ID:            "fw-handler-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Firewall:      &FirewallConfig{Enabled: true, DefaultPolicy: "deny"},
		Runtime:       newTestRuntime(),
	}
}

// natGatewayConfig returns a gateway config with the NAT service enabled
// and the test runtime injected.
func natGatewayConfig() *GatewayConfig {
	return &GatewayConfig{
		Enabled:       true,
		ID:            "nat-handler-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Uplinks:       []UplinkConfig{{Name: "eth0", MTU: 1500}},
		NAT: &NATConfig{
			Enabled:        true,
			ExternalIP:     "203.0.113.10",
			PortRangeStart: 1024,
			PortRangeEnd:   65535,
			MaxSessions:    1000,
			InternalCIDR:   "10.0.100.0/24",
		},
		Runtime: newTestRuntime(),
	}
}

// startGateway creates and starts a gateway, failing the test on error.
func startGateway(t *testing.T, cfg *GatewayConfig) *Gateway {
	t.Helper()

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	if err := gw.Start(context.Background()); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	return gw
}

func TestFirewallServiceHandler_Lifecycle(t *testing.T) {
	gw := startGateway(t, firewallGatewayConfig())
	ctx := context.Background()
	defer func() {
		if err := gw.Stop(ctx); err != nil {
			t.Errorf("stop: %v", err)
		}
	}()

	if !gw.HasService(ServiceFirewall) {
		t.Fatal("firewall service should be active")
	}

	health, ok := gw.FirewallHealth()
	if !ok {
		t.Fatal("FirewallHealth should be available while running")
	}
	if !health.Active {
		t.Error("firewall health should report active")
	}
	if health.FlowCount == 0 {
		t.Error("firewall should have installed conntrack flows")
	}
	if len(health.CTZones) != 2 {
		t.Errorf("expected 2 ct zones, got %d", len(health.CTZones))
	}

	if err := gw.ReconcileFirewall(ctx); err != nil {
		t.Errorf("reconcile: %v", err)
	}
}

func TestFirewallServiceHandler_MissingRuntime(t *testing.T) {
	cfg := firewallGatewayConfig()
	cfg.Runtime = nil

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	err = gw.Start(context.Background())
	if err == nil {
		t.Fatal("start should fail without injected runtime")
	}
	var runtimeErr *ErrRuntimeMissing
	if !errors.As(err, &runtimeErr) {
		t.Errorf("expected ErrRuntimeMissing in chain, got %v", err)
	}
}

func TestFirewallServiceHandler_StopReleasesState(t *testing.T) {
	cfg := firewallGatewayConfig()
	gw := startGateway(t, cfg)
	ctx := context.Background()

	if err := gw.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	if _, ok := gw.FirewallHealth(); ok {
		t.Error("FirewallHealth should be unavailable after stop")
	}

	fakeOVS := cfg.Runtime.OVS.(*fakeOVSClient)
	fakeOVS.mu.Lock()
	defer fakeOVS.mu.Unlock()
	if len(fakeOVS.cookieDeletes) == 0 {
		t.Error("stop should delete firewall flows by cookie")
	}
	if len(fakeOVS.strictDeletes) == 0 {
		t.Error("stop should strict-delete the table 10 gate")
	}
}

func TestNATServiceHandler_Lifecycle(t *testing.T) {
	gw := startGateway(t, natGatewayConfig())
	ctx := context.Background()
	defer func() {
		if err := gw.Stop(ctx); err != nil {
			t.Errorf("stop: %v", err)
		}
	}()

	if !gw.HasService(ServiceNAT) {
		t.Fatal("nat service should be active")
	}

	health, ok := gw.NATHealth()
	if !ok {
		t.Fatal("NATHealth should be available while running")
	}
	if !health.Active {
		t.Error("nat health should report active")
	}
	if !health.SNATEnabled {
		t.Error("SNAT should be enabled from InternalCIDR")
	}

	svc, ok := gw.NATService()
	if !ok {
		t.Fatal("NATService should be available while running")
	}
	if !svc.Active() {
		t.Error("nat service should be active")
	}
}

func TestNATServiceHandler_MissingRuntime(t *testing.T) {
	cfg := natGatewayConfig()
	cfg.Runtime = nil

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	err = gw.Start(context.Background())
	if err == nil {
		t.Fatal("start should fail without injected runtime")
	}
	var runtimeErr *ErrRuntimeMissing
	if !errors.As(err, &runtimeErr) {
		t.Errorf("expected ErrRuntimeMissing in chain, got %v", err)
	}
}

func TestNATServiceHandler_InvalidConfig(t *testing.T) {
	cfg := natGatewayConfig()
	cfg.NAT.ExternalIP = "not-an-ip"

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	err = gw.Start(context.Background())
	if err == nil {
		t.Fatal("start should fail with invalid external IP")
	}
	if !errors.Is(err, firewall.ErrInvalidExternalIP) {
		t.Errorf("expected ErrInvalidExternalIP in chain, got %v", err)
	}
}

func TestGateway_HealthAccessors_NotRegistered(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "plain-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
	}
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	if _, ok := gw.FirewallHealth(); ok {
		t.Error("FirewallHealth should be unavailable without the service")
	}
	if _, ok := gw.NATHealth(); ok {
		t.Error("NATHealth should be unavailable without the service")
	}
	if _, ok := gw.NATService(); ok {
		t.Error("NATService should be unavailable without the service")
	}
	if err := gw.ReconcileFirewall(context.Background()); err == nil {
		t.Error("ReconcileFirewall should fail without the service")
	}
}
