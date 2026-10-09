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
	"strings"
	"testing"
	"time"
)

// validConfig is a gateway with one runnable service — the firewall on
// the fake OVS runtime — so lifecycle tests exercise a real backed handler
// rather than a stub that flips a bool (#568).
func validConfig() *GatewayConfig {
	return &GatewayConfig{
		Enabled:       true,
		ID:            "test-gateway",
		NodeID:        12345,
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Firewall:      &FirewallConfig{Enabled: true, DefaultPolicy: "deny"},
		Runtime:       newTestRuntime(),
	}
}

// validNodeMetrics returns valid metrics that meet all requirements.
func validNodeMetrics() (float64, time.Duration, float64) {
	reputation := 0.90
	age := time.Duration(MinAgeDays+10) * 24 * time.Hour
	uptime := 99.0
	return reputation, age, uptime
}

func TestNewGateway(t *testing.T) {
	tests := []struct {
		name        string
		config      *GatewayConfig
		expectError error
	}{
		{
			name:        "valid config with overlay",
			config:      validConfig(),
			expectError: nil,
		},
		{
			name:        "nil config",
			config:      nil,
			expectError: ErrConfigNil,
		},
		{
			name: "invalid config - empty ID",
			config: func() *GatewayConfig {
				cfg := validConfig()
				cfg.ID = ""
				return cfg
			}(),
			expectError: ErrConfigurationInvalid,
		},
		{
			name: "valid config - no services enabled",
			config: &GatewayConfig{
				Enabled:       true,
				ID:            "gw-no-services",
				MinReputation: MinReputation,
				MinAgeDays:    MinAgeDays,
				MinUptimePct:  MinUptimePct,
			},
			expectError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw, err := NewGateway(tt.config)
			if tt.expectError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectError)
				}
				if !errors.Is(err, tt.expectError) {
					if err.Error() != tt.expectError.Error() {
						t.Errorf("expected error %v, got %v", tt.expectError, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gw == nil {
				t.Fatal("gateway is nil")
			}
			if gw.config != tt.config {
				t.Error("gateway config does not match")
			}
			if gw.node == nil {
				t.Error("gateway node is nil")
			}
			if gw.GetState() != GatewayStateStopped {
				t.Errorf("initial state = %v, want %v", gw.GetState(), GatewayStateStopped)
			}
		})
	}
}

func TestGateway_StartStop(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Set valid metrics
	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()

	// Start the gateway
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}

	// Verify running state
	if !gw.IsRunning() {
		t.Error("gateway should be running after Start")
	}
	if gw.GetState() != GatewayStateRunning {
		t.Errorf("state = %v, want %v", gw.GetState(), GatewayStateRunning)
	}

	// Start again should fail
	if err := gw.Start(ctx); err == nil {
		t.Error("expected error when starting already running gateway")
	} else if !errors.Is(err, ErrGatewayAlreadyRunning) {
		t.Errorf("expected ErrGatewayAlreadyRunning, got %v", err)
	}

	// Stop the gateway
	if err := gw.Stop(ctx); err != nil {
		t.Fatalf("failed to stop gateway: %v", err)
	}

	// Verify stopped state
	if gw.IsRunning() {
		t.Error("gateway should not be running after Stop")
	}
	if gw.GetState() != GatewayStateStopped {
		t.Errorf("state = %v, want %v", gw.GetState(), GatewayStateStopped)
	}

	// Stop again should be idempotent
	if err := gw.Stop(ctx); err != nil {
		t.Errorf("stopping already stopped gateway should not error: %v", err)
	}
}

func TestGateway_StartWithInvalidMetrics(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	ctx := context.Background()

	// Don't set metrics (default zero values)
	err = gw.Start(ctx)
	if err == nil {
		t.Fatal("expected error when starting with invalid metrics")
	}

	var startErr *ErrStartupFailed
	if !errors.As(err, &startErr) {
		t.Errorf("expected ErrStartupFailed, got %T: %v", err, err)
	}

	// Verify gateway is not running
	if gw.IsRunning() {
		t.Error("gateway should not be running after failed start")
	}
}

func TestGateway_ConfigDrivenServiceLoading(t *testing.T) {
	cfg := firewallGatewayConfig()
	gw := startGateway(t, cfg)
	defer gw.Stop(context.Background())

	if !gw.HasService(ServiceFirewall) {
		t.Error("firewall service should be active")
	}
	// Sections absent from the config register nothing.
	for _, absent := range []string{ServiceNAT, ServiceLoadBalancer, ServiceTransit, ServiceHostFW, ServiceTunnels} {
		if gw.HasService(absent) {
			t.Errorf("%s should not be active", absent)
		}
	}
}

func TestGateway_MissingConfigSectionNotStarted(t *testing.T) {
	// Config with no service sections
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "empty-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// No services should be active
	services := gw.ActiveServices()
	if len(services) != 0 {
		t.Errorf("expected 0 active services, got %d: %v", len(services), services)
	}
}

func TestGateway_EnabledFalseNotStarted(t *testing.T) {
	// Sections present but disabled register no handler at all — neither a
	// backed one nor a refusal.
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "disabled-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Overlay:       &OverlayServiceConfig{Enabled: false},
		Edge:          &EdgeConfig{Enabled: false, MaxDevices: 100, MaxServices: 50},
		Firewall:      &FirewallConfig{Enabled: false},
	}
	gw := startGateway(t, cfg)
	defer gw.Stop(context.Background())

	if len(gw.serviceHandlers) != 0 {
		t.Errorf("expected no handlers, got %v", gw.serviceOrder)
	}
	if gw.HasService(ServiceOverlay) || gw.HasService(ServiceEdge) || gw.HasService(ServiceFirewall) {
		t.Error("disabled sections must not be active")
	}
}

func TestGateway_MultipleServicesConfig(t *testing.T) {
	// Three real datapath services on one runtime: firewall, NAT and the
	// load balancer all gate out of the base pipeline.
	cfg := lbGatewayConfig()
	cfg.ID = "multi-gw"
	cfg.Firewall = &FirewallConfig{Enabled: true, DefaultPolicy: "deny"}
	cfg.Uplinks = []UplinkConfig{{Name: "eth0", MTU: 1500}}
	cfg.NAT = &NATConfig{Enabled: true, ExternalIP: "203.0.113.10", PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 1000, InternalCIDR: "10.0.100.0/24"}
	gw := startGateway(t, cfg)
	defer gw.Stop(context.Background())

	for _, want := range []string{ServiceFirewall, ServiceNAT, ServiceLoadBalancer} {
		if !gw.HasService(want) {
			t.Errorf("%s should be active", want)
		}
	}
	status := gw.GetStatus()
	if len(status.ActiveServiceNames) != 3 {
		t.Errorf("expected 3 active services, got %d: %v", len(status.ActiveServiceNames), status.ActiveServiceNames)
	}
	if got := gw.ActiveServices(); len(got) != 3 || got[0] != ServiceFirewall || got[1] != ServiceNAT || got[2] != ServiceLoadBalancer {
		t.Errorf("start order should be the declared order, got %v", got)
	}
}

func TestGateway_GetStatus(t *testing.T) {
	cfg := firewallGatewayConfig()
	cfg.ID = "status-gw"
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Status when stopped
	status := gw.GetStatus()
	if status.State != GatewayStateStopped {
		t.Errorf("status state = %v, want %v", status.State, GatewayStateStopped)
	}
	if status.ID != cfg.ID {
		t.Errorf("status ID = %q, want %q", status.ID, cfg.ID)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// Status when running
	status = gw.GetStatus()
	if status.State != GatewayStateRunning {
		t.Errorf("status state = %v, want %v", status.State, GatewayStateRunning)
	}
	if status.StartedAt.IsZero() {
		t.Error("status StartedAt should not be zero")
	}
	if len(status.ActiveServiceNames) != 1 || status.ActiveServiceNames[0] != ServiceFirewall {
		t.Errorf("active services = %v, want [firewall]", status.ActiveServiceNames)
	}
}

func TestGateway_MeetsRequirements(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Without setting metrics, should fail
	if err := gw.MeetsRequirements(); err == nil {
		t.Error("expected error when requirements not met")
	}

	// Set valid metrics
	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	// Should pass now
	if err := gw.MeetsRequirements(); err != nil {
		t.Errorf("expected requirements to be met: %v", err)
	}

	// Set low reputation
	gw.SetNodeMetrics(0.5, age, uptime)
	if err := gw.MeetsRequirements(); err == nil {
		t.Error("expected error when reputation too low")
	}

	// Reset and set low age
	gw.SetNodeMetrics(rep, 10*24*time.Hour, uptime)
	if err := gw.MeetsRequirements(); err == nil {
		t.Error("expected error when age too young")
	}

	// Reset and set low uptime
	gw.SetNodeMetrics(rep, age, 50.0)
	if err := gw.MeetsRequirements(); err == nil {
		t.Error("expected error when uptime too low")
	}
}

func TestGateway_IsOperational(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Not operational when stopped
	if gw.IsOperational() {
		t.Error("gateway should not be operational when stopped")
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// Operational when running
	if !gw.IsOperational() {
		t.Error("gateway should be operational when running")
	}
}

func TestGateway_GetNode(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	node := gw.GetNode()
	if node.ID != cfg.ID {
		t.Errorf("node ID = %q, want %q", node.ID, cfg.ID)
	}
	if node.NodeID != cfg.NodeID {
		t.Errorf("node NodeID = %d, want %d", node.NodeID, cfg.NodeID)
	}
}

func TestGateway_GetConfig(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	gotCfg := gw.GetConfig()
	if gotCfg != cfg {
		t.Error("GetConfig should return the same config instance")
	}
}

func TestGateway_ActiveServices(t *testing.T) {
	cfg := firewallGatewayConfig()
	cfg.ID = "active-svc-gw"
	cfg.Tunnels = []TunnelConfig{{Name: "gre1", Type: "gre", Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.1/30"}}
	cfg.Host = &HostRuntime{TunnelManager: &fakeTunnelManager{}}
	gw := startGateway(t, cfg)
	defer gw.Stop(context.Background())

	services := gw.ActiveServices()
	if len(services) != 2 {
		t.Fatalf("expected 2 active services, got %d: %v", len(services), services)
	}
	if services[0] != ServiceFirewall || services[1] != ServiceTunnels {
		t.Errorf("services = %v, want [firewall tunnels] in declared order", services)
	}
}

func TestGateway_SetNodeMetrics(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep := 0.95
	age := 200 * 24 * time.Hour
	uptime := 99.5

	gw.SetNodeMetrics(rep, age, uptime)

	node := gw.GetNode()
	if node.Reputation != rep {
		t.Errorf("reputation = %v, want %v", node.Reputation, rep)
	}
	if node.Age != age {
		t.Errorf("age = %v, want %v", node.Age, age)
	}
	if node.Uptime != uptime {
		t.Errorf("uptime = %v, want %v", node.Uptime, uptime)
	}
}

func TestGateway_Uptime(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Uptime when stopped should be 0
	if gw.Uptime() != 0 {
		t.Errorf("uptime when stopped = %v, want 0", gw.Uptime())
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// Uptime when running should be > 0
	if gw.Uptime() == 0 {
		t.Error("uptime when running should be > 0")
	}
}

func TestGateway_StopCleansUpServices(t *testing.T) {
	cfg := firewallGatewayConfig()
	cfg.ID = "cleanup-gw"
	cfg.Tunnels = []TunnelConfig{{Name: "gre1", Type: "gre", Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.1/30"}}
	cfg.Host = &HostRuntime{TunnelManager: &fakeTunnelManager{}}
	gw := startGateway(t, cfg)

	if !gw.HasService(ServiceFirewall) || !gw.HasService(ServiceTunnels) {
		t.Error("services should be active before stop")
	}
	if err := gw.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop gateway: %v", err)
	}
	if gw.HasService(ServiceFirewall) || gw.HasService(ServiceTunnels) {
		t.Error("services should be inactive after stop")
	}
	if _, ok := gw.FirewallHealth(); ok {
		t.Error("a stopped service has no backend")
	}
}

func TestGateway_ConcurrentOperations(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// Concurrent reads should be safe
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				_ = gw.GetStatus()
				_ = gw.IsRunning()
				_ = gw.ActiveServices()
				_ = gw.GetNode()
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestFormatHelpers(t *testing.T) {
	tests := []struct {
		input    float64
		expected string
	}{
		{95.0, "95.0%"},
		{99.9, "99.9%"},
		{0.0, "0.0%"},
		{100.0, "100.0%"},
	}

	for _, tt := range tests {
		result := formatPercent(tt.input)
		if result != tt.expected {
			t.Errorf("formatPercent(%v) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestGateway_DisabledConfig(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled: false,
		ID:      "", // Empty ID is OK when disabled
	}

	// Validation should pass for disabled config
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled config should pass validation: %v", err)
	}

	// But we still need valid config to create gateway
	cfg.Enabled = true
	cfg.ID = "test"
	cfg.Overlay = validOverlayServiceConfig()

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	if gw.GetConfig().ID != "test" {
		t.Error("config ID not set correctly")
	}
}

func TestGateway_MeetsRequirementsWithCustomThresholds(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "test-gateway",
		MinReputation: 0.90, // Higher than default
		MinAgeDays:    200,  // Higher than default
		MinUptimePct:  98.0, // Higher than default
		Overlay:       validOverlayServiceConfig(),
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Set metrics that meet default but not custom requirements
	gw.SetNodeMetrics(0.88, 180*24*time.Hour, 96.0)

	err = gw.MeetsRequirements()
	if err == nil {
		t.Error("expected error when metrics don't meet custom thresholds")
	}

	var reqErr *ErrRequirementsNotMet
	if !errors.As(err, &reqErr) {
		t.Errorf("expected ErrRequirementsNotMet, got %T: %v", err, err)
	}

	// Verify there are multiple failed checks
	if len(reqErr.Checks) == 0 {
		t.Error("expected failed checks in error")
	}
}

// TestServiceHandler_RefusedSections replaces the three stub-handler tests
// (#568): overlay, edge, dhcp and pxe are enabled sections the gateway
// cannot run, and their handlers say so with a typed error instead of
// flipping a bool.
func TestServiceHandler_RefusedSections(t *testing.T) {
	cfg := baseGatewayConfig("refused-handlers")
	cfg.Edge = &EdgeConfig{Enabled: true, MaxDevices: 100, MaxServices: 50}
	cfg.DHCP = &DHCPServiceConfig{Enabled: true, Interface: "eth0"}
	cfg.PXE = &PXEServiceConfig{Enabled: true, HTTPPort: 8069}
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	for _, name := range []string{ServiceEdge, ServiceDHCP, ServicePXE} {
		handler, ok := gw.serviceHandlers[name]
		if !ok {
			t.Fatalf("%s handler not registered", name)
		}
		if handler.Name() != name {
			t.Errorf("handler name = %q, want %q", handler.Name(), name)
		}
		if handler.IsActive() {
			t.Errorf("%s must not report active", name)
		}
		var unavailable *ErrServiceUnavailable
		if err := handler.Start(context.Background()); !errors.As(err, &unavailable) || unavailable.Service != name {
			t.Errorf("%s Start = %v, want ErrServiceUnavailable", name, err)
		}
		if err := handler.Health(); !errors.As(err, &unavailable) {
			t.Errorf("%s Health = %v, want ErrServiceUnavailable", name, err)
		}
	}
	// The gateway's own state never shows a refused section as active.
	if gw.GetStatus().OverlayState != nil || gw.GetStatus().EdgeState != nil || gw.GetStatus().TransitState != nil {
		t.Error("no per-mode state may be fabricated for a service that did not run")
	}
}

func TestGateway_TunnelConfig(t *testing.T) {
	mgr := &fakeTunnelManager{}
	cfg := baseGatewayConfig("tunnel-gw")
	cfg.Tunnels = []TunnelConfig{
		{Name: "gre1", Type: "gre", Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.1/30"},
	}
	cfg.Host = &HostRuntime{TunnelManager: mgr}
	gw := startGateway(t, cfg)
	defer gw.Stop(context.Background())

	if !gw.HasService(ServiceTunnels) {
		t.Error("tunnels service should be active")
	}
	if len(mgr.ensured) != 1 || mgr.ensured[0] != "gre1" {
		t.Errorf("tunnel manager ensured %v, want [gre1]", mgr.ensured)
	}
}

func TestGateway_FirewallConfig(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "fw-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Firewall:      &FirewallConfig{Enabled: true, DefaultPolicy: "deny"},
		Runtime:       newTestRuntime(),
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	if !gw.HasService(ServiceFirewall) {
		t.Error("firewall service should be active")
	}
}

func TestGateway_DHCPConfig(t *testing.T) {
	// DHCP is an enabled section the gateway cannot run yet: no IPAM
	// allocator exists in gatewayd. Starting must say so, not pretend.
	cfg := baseGatewayConfig("dhcp-gw")
	cfg.DHCP = &DHCPServiceConfig{Enabled: true, Interface: "eth0"}
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	gw.SetNodeMetrics(validNodeMetrics())
	err = gw.Start(context.Background())
	var unavailable *ErrServiceUnavailable
	if !errors.As(err, &unavailable) || unavailable.Service != ServiceDHCP {
		t.Fatalf("Start = %v, want ErrServiceUnavailable for dhcp", err)
	}
	if !strings.Contains(unavailable.Reason, "IPAM") {
		t.Errorf("reason should name the missing allocator: %q", unavailable.Reason)
	}
}

// registeredTestHandler is a minimal ServiceHandler for registration tests.
type registeredTestHandler struct {
	name   string
	active bool
}

func (h *registeredTestHandler) Name() string                    { return h.name }
func (h *registeredTestHandler) Start(ctx context.Context) error { h.active = true; return nil }
func (h *registeredTestHandler) Stop(ctx context.Context) error  { h.active = false; return nil }
func (h *registeredTestHandler) IsActive() bool                  { return h.active }
func (h *registeredTestHandler) Health() error                   { return nil }

func TestGateway_RegisterServiceHandler(t *testing.T) {
	gw, err := NewGateway(validConfig())
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	handler := &registeredTestHandler{name: ServiceProxy}
	if err := gw.RegisterServiceHandler(handler); err != nil {
		t.Fatalf("RegisterServiceHandler: %v", err)
	}

	// Duplicate registration is rejected.
	if err := gw.RegisterServiceHandler(&registeredTestHandler{name: ServiceProxy}); err == nil {
		t.Fatal("duplicate registration must fail")
	} else if _, ok := err.(*ErrServiceAlreadyExists); !ok {
		t.Fatalf("err = %v, want *ErrServiceAlreadyExists", err)
	}

	// The registered handler participates in the start/stop lifecycle.
	gw.SetNodeMetrics(validNodeMetrics())
	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !gw.HasService(ServiceProxy) || !handler.active {
		t.Fatal("registered handler not started")
	}

	// Registration is rejected while running.
	if err := gw.RegisterServiceHandler(&registeredTestHandler{name: "late"}); err == nil {
		t.Fatal("registration while running must fail")
	} else if _, ok := err.(*ErrInvalidState); !ok {
		t.Fatalf("err = %v, want *ErrInvalidState", err)
	}

	if err := gw.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if handler.active {
		t.Fatal("registered handler not stopped")
	}
}

func TestGateway_RegisterServiceHandlerInvalid(t *testing.T) {
	gw, err := NewGateway(validConfig())
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	if err := gw.RegisterServiceHandler(nil); err == nil {
		t.Fatal("nil handler must fail")
	} else if _, ok := err.(*ErrNilServiceHandler); !ok {
		t.Fatalf("err = %v, want *ErrNilServiceHandler", err)
	}
	if err := gw.RegisterServiceHandler(&registeredTestHandler{name: ""}); err == nil {
		t.Fatal("unnamed handler must fail")
	} else if _, ok := err.(*ErrNilServiceHandler); !ok {
		t.Fatalf("err = %v, want *ErrNilServiceHandler", err)
	}
}
