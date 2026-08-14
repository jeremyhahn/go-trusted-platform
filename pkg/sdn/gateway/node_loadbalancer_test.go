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
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// fakeGroupClient records OpenFlow group programming for LB handler tests.
type fakeGroupClient struct {
	mu     sync.Mutex
	groups map[uint32]*openflow.GroupMod
}

func newFakeGroupClient() *fakeGroupClient {
	return &fakeGroupClient{groups: make(map[uint32]*openflow.GroupMod)}
}

func (f *fakeGroupClient) AddGroup(ctx context.Context, bridgeName string, group *openflow.GroupMod) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups[group.GroupID] = group
	return nil
}

func (f *fakeGroupClient) ModifyGroup(ctx context.Context, bridgeName string, group *openflow.GroupMod) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups[group.GroupID] = group
	return nil
}

func (f *fakeGroupClient) DeleteGroup(ctx context.Context, bridgeName string, groupID uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.groups, groupID)
	return nil
}

func (f *fakeGroupClient) GetGroupDesc(ctx context.Context, bridgeName string) ([]openflow.GroupDesc, error) {
	return nil, nil
}

// lbGatewayConfig returns a gateway config with the load balancer service
// enabled, one configured VIP, and the test runtime injected.
func lbGatewayConfig() *GatewayConfig {
	runtime := newTestRuntime()
	runtime.Groups = newFakeGroupClient()
	return &GatewayConfig{
		Enabled:       true,
		ID:            "lb-handler-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		LoadBalancer: &LoadBalancerConfig{
			Enabled:             true,
			Algorithm:           "hash",
			HealthCheckInterval: time.Hour,
			HealthCheckTimeout:  time.Second,
			MaxBackends:         8,
			VIPs: []VIPConfig{
				{
					Address:  "10.100.0.10",
					Port:     443,
					Protocol: "tcp",
					Backends: []BackendConfig{
						{Address: "10.0.1.5", Port: 8443, Weight: 2},
						{Address: "10.0.1.6", Port: 8443},
					},
				},
			},
		},
		Runtime: runtime,
	}
}

func TestLoadBalancerServiceHandler_Lifecycle(t *testing.T) {
	gw := startGateway(t, lbGatewayConfig())
	defer gw.Stop(context.Background())

	if !gw.HasService(ServiceLoadBalancer) {
		t.Fatal("load balancer service not active after Start")
	}

	health, ok := gw.LBHealth()
	if !ok {
		t.Fatal("LBHealth returned false for running service")
	}
	if !health.Active || health.VIPCount != 1 || health.TotalBackends != 2 {
		t.Errorf("LBHealth = %+v", health)
	}

	svc, ok := gw.LBService()
	if !ok || svc == nil {
		t.Fatal("LBService returned false for running service")
	}

	if err := gw.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, ok := gw.LBHealth(); ok {
		t.Error("LBHealth returned true after Stop")
	}
	if _, ok := gw.LBService(); ok {
		t.Error("LBService returned true after Stop")
	}
}

func TestLoadBalancerServiceHandler_MissingRuntime(t *testing.T) {
	cfg := lbGatewayConfig()
	cfg.Runtime = nil

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	err = gw.Start(context.Background())
	if err == nil {
		t.Fatal("Start succeeded without runtime")
	}
	var missing *ErrRuntimeMissing
	if !errors.As(err, &missing) || missing.Service != ServiceLoadBalancer {
		t.Fatalf("Start error = %v, want ErrRuntimeMissing for %s", err, ServiceLoadBalancer)
	}
}

func TestLoadBalancerServiceHandler_MissingGroups(t *testing.T) {
	cfg := lbGatewayConfig()
	cfg.Runtime.Groups = nil

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	err = gw.Start(context.Background())
	var missing *ErrRuntimeMissing
	if !errors.As(err, &missing) || missing.Service != ServiceLoadBalancer {
		t.Fatalf("Start error = %v, want ErrRuntimeMissing for %s", err, ServiceLoadBalancer)
	}
}

func TestLoadBalancerServiceHandler_InvalidVIPConfig(t *testing.T) {
	cfg := lbGatewayConfig()
	// Bypass config validation to prove the handler surfaces the typed
	// parse error from lbDeps.
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	cfg.LoadBalancer.VIPs[0].Address = "not-an-ip"
	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	err = gw.Start(context.Background())
	if err == nil {
		t.Fatal("Start succeeded with invalid VIP address")
	}
	if !errors.Is(err, loadbalancer.ErrInvalidVIPAddress) {
		t.Fatalf("Start error = %v, want ErrInvalidVIPAddress", err)
	}
}

func TestGatewayVIPOperations(t *testing.T) {
	gw := startGateway(t, lbGatewayConfig())
	defer gw.Stop(context.Background())

	ctx := context.Background()
	addr := netip.MustParseAddrPort("10.100.0.10:443")

	status, err := gw.GetVIP(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("GetVIP: %v", err)
	}
	if len(status.Backends) != 2 {
		t.Errorf("backends = %d, want 2", len(status.Backends))
	}

	vips, err := gw.ListVIPs(ctx)
	if err != nil || len(vips) != 1 {
		t.Fatalf("ListVIPs = %v (%v)", vips, err)
	}

	newVIP := loadbalancer.VIP{
		Address:  netip.MustParseAddr("10.100.0.11"),
		Port:     80,
		Protocol: "tcp",
		Backends: []loadbalancer.Backend{
			{Address: netip.MustParseAddr("10.0.1.7"), Port: 8080},
		},
	}
	if err := gw.AddVIP(ctx, newVIP); err != nil {
		t.Fatalf("AddVIP: %v", err)
	}

	if err := gw.SetVIPBackends(ctx, "tcp", netip.MustParseAddrPort("10.100.0.11:80"), []loadbalancer.Backend{
		{Address: netip.MustParseAddr("10.0.1.8"), Port: 8080},
	}); err != nil {
		t.Fatalf("SetVIPBackends: %v", err)
	}

	if err := gw.RemoveVIP(ctx, "tcp", netip.MustParseAddrPort("10.100.0.11:80")); err != nil {
		t.Fatalf("RemoveVIP: %v", err)
	}

	lbStatus, err := gw.LBStatus(ctx)
	if err != nil {
		t.Fatalf("LBStatus: %v", err)
	}
	if lbStatus.VIPCount != 1 {
		t.Errorf("VIPCount = %d, want 1", lbStatus.VIPCount)
	}
}

func TestGatewayVIPOperations_ServiceNotActive(t *testing.T) {
	// A gateway without the load balancer section registers no LB handler:
	// every VIP operation returns the typed not-active error.
	gw, err := NewGateway(&GatewayConfig{
		Enabled:       true,
		ID:            "no-lb-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	ctx := context.Background()
	addr := netip.MustParseAddrPort("10.100.0.10:443")
	var notActive *ErrServiceNotActive

	if err := gw.AddVIP(ctx, loadbalancer.VIP{}); !errors.As(err, &notActive) {
		t.Errorf("AddVIP = %v", err)
	}
	if err := gw.RemoveVIP(ctx, "tcp", addr); !errors.As(err, &notActive) {
		t.Errorf("RemoveVIP = %v", err)
	}
	if _, err := gw.GetVIP(ctx, "tcp", addr); !errors.As(err, &notActive) {
		t.Errorf("GetVIP = %v", err)
	}
	if _, err := gw.ListVIPs(ctx); !errors.As(err, &notActive) {
		t.Errorf("ListVIPs = %v", err)
	}
	if err := gw.SetVIPBackends(ctx, "tcp", addr, nil); !errors.As(err, &notActive) {
		t.Errorf("SetVIPBackends = %v", err)
	}
	if _, err := gw.LBStatus(ctx); !errors.As(err, &notActive) {
		t.Errorf("LBStatus = %v", err)
	}
	if _, ok := gw.LBHealth(); ok {
		t.Error("LBHealth = true without LB service")
	}
}

func TestVIPConfigServiceVIP(t *testing.T) {
	cfg := VIPConfig{
		Address:   "10.100.0.10",
		Port:      443,
		Protocol:  "tcp",
		Algorithm: "round-robin",
		Backends:  []BackendConfig{{Address: "10.0.1.5", Port: 8443, Weight: 4}},
	}
	vip, err := cfg.ServiceVIP()
	if err != nil {
		t.Fatalf("ServiceVIP: %v", err)
	}
	if vip.Address.String() != "10.100.0.10" || vip.Port != 443 || vip.Algorithm != "round-robin" {
		t.Errorf("vip = %+v", vip)
	}
	if len(vip.Backends) != 1 || vip.Backends[0].Weight != 4 {
		t.Errorf("backends = %+v", vip.Backends)
	}

	cfg.Address = "bogus"
	if _, err := cfg.ServiceVIP(); !errors.Is(err, loadbalancer.ErrInvalidVIPAddress) {
		t.Errorf("ServiceVIP bad address = %v", err)
	}
	cfg.Address = "10.100.0.10"
	cfg.Backends[0].Address = "bogus"
	if _, err := cfg.ServiceVIP(); !errors.Is(err, loadbalancer.ErrInvalidBackend) {
		t.Errorf("ServiceVIP bad backend = %v", err)
	}
}

func TestLoadBalancerConfigValidate(t *testing.T) {
	valid := func() *LoadBalancerConfig {
		return &LoadBalancerConfig{
			Enabled:             true,
			Algorithm:           "hash",
			HealthCheckInterval: 10 * time.Second,
			HealthCheckTimeout:  time.Second,
			MaxBackends:         4,
			VIPs: []VIPConfig{{
				Address:  "10.100.0.10",
				Port:     443,
				Protocol: "tcp",
				Backends: []BackendConfig{{Address: "10.0.1.5", Port: 8443}},
			}},
		}
	}

	if err := valid().Validate(); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}

	disabled := valid()
	disabled.Enabled = false
	disabled.Algorithm = ""
	if err := disabled.Validate(); err != nil {
		t.Errorf("disabled Validate = %v, want nil", err)
	}

	tests := []struct {
		name   string
		mutate func(*LoadBalancerConfig)
	}{
		{"empty algorithm", func(c *LoadBalancerConfig) { c.Algorithm = "" }},
		{"zero interval", func(c *LoadBalancerConfig) { c.HealthCheckInterval = 0 }},
		{"timeout above interval", func(c *LoadBalancerConfig) { c.HealthCheckTimeout = time.Minute }},
		{"negative rise", func(c *LoadBalancerConfig) { c.HealthCheckRise = -1 }},
		{"negative fall", func(c *LoadBalancerConfig) { c.HealthCheckFall = -1 }},
		{"zero max backends", func(c *LoadBalancerConfig) { c.MaxBackends = 0 }},
		{"bad vip address", func(c *LoadBalancerConfig) { c.VIPs[0].Address = "bogus" }},
		{"least-conn vip", func(c *LoadBalancerConfig) { c.VIPs[0].Algorithm = "least-conn" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			tt.mutate(cfg)
			if err := cfg.Validate(); !errors.Is(err, ErrConfigurationInvalid) {
				t.Errorf("Validate = %v, want ErrConfigurationInvalid", err)
			}
		})
	}
}
