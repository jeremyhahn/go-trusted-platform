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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

func validOverlayServiceConfig() *OverlayServiceConfig {
	return &OverlayServiceConfig{
		Enabled:           true,
		LocalVTEP:         netip.MustParseAddr("10.4.100.20"),
		UnderlayInterface: "vtep0",
		UnderlayMTU:       9216,
		AccessPort:        "patch-workloads",
		OverlayASN:        65000,
		VXLANPort:         4789,
		DefaultVNI:        40100,
		MaxVNIs:           DefaultMaxVNIs,
		VerdictMaxAge:     time.Minute,
	}
}

func TestPortState_String(t *testing.T) {
	tests := []struct {
		name     string
		state    PortState
		expected string
	}{
		{"up", PortStateUp, "up"},
		{"down", PortStateDown, "down"},
		{"error", PortStateError, "error"},
		{"unknown", PortStateUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("PortState.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPortState_Valid(t *testing.T) {
	tests := []struct {
		name     string
		state    PortState
		expected bool
	}{
		{"unknown valid", PortStateUnknown, true},
		{"up valid", PortStateUp, true},
		{"down valid", PortStateDown, true},
		{"error valid", PortStateError, true},
		{"invalid value", PortState(100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.Valid(); got != tt.expected {
				t.Errorf("PortState.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPortState_IsUp(t *testing.T) {
	tests := []struct {
		name     string
		state    PortState
		expected bool
	}{
		{"up is up", PortStateUp, true},
		{"down is not up", PortStateDown, false},
		{"error is not up", PortStateError, false},
		{"unknown is not up", PortStateUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsUp(); got != tt.expected {
				t.Errorf("PortState.IsUp() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayState_String(t *testing.T) {
	tests := []struct {
		name     string
		state    GatewayState
		expected string
	}{
		{"initializing", GatewayStateInitializing, "initializing"},
		{"running", GatewayStateRunning, "running"},
		{"degraded", GatewayStateDegraded, "degraded"},
		{"stopping", GatewayStateStopping, "stopping"},
		{"stopped", GatewayStateStopped, "stopped"},
		{"error", GatewayStateError, "error"},
		{"unknown", GatewayStateUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("GatewayState.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayState_Valid(t *testing.T) {
	tests := []struct {
		name     string
		state    GatewayState
		expected bool
	}{
		{"unknown valid", GatewayStateUnknown, true},
		{"running valid", GatewayStateRunning, true},
		{"error valid", GatewayStateError, true},
		{"out of range invalid", GatewayState(100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.Valid(); got != tt.expected {
				t.Errorf("GatewayState.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayState_IsHealthy(t *testing.T) {
	tests := []struct {
		name     string
		state    GatewayState
		expected bool
	}{
		{"running is healthy", GatewayStateRunning, true},
		{"degraded is not healthy", GatewayStateDegraded, false},
		{"stopped is not healthy", GatewayStateStopped, false},
		{"error is not healthy", GatewayStateError, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsHealthy(); got != tt.expected {
				t.Errorf("GatewayState.IsHealthy() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayState_IsOperational(t *testing.T) {
	tests := []struct {
		name     string
		state    GatewayState
		expected bool
	}{
		{"running is operational", GatewayStateRunning, true},
		{"degraded is operational", GatewayStateDegraded, true},
		{"stopped is not operational", GatewayStateStopped, false},
		{"error is not operational", GatewayStateError, false},
		{"initializing is not operational", GatewayStateInitializing, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsOperational(); got != tt.expected {
				t.Errorf("GatewayState.IsOperational() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUplinkPort_Valid(t *testing.T) {
	tests := []struct {
		name     string
		port     UplinkPort
		expected bool
	}{
		{
			name:     "valid port",
			port:     UplinkPort{Name: "eth0", MTU: 1500, Speed: 1000000000},
			expected: true,
		},
		{
			name:     "empty name invalid",
			port:     UplinkPort{Name: "", MTU: 1500, Speed: 1000000000},
			expected: false,
		},
		{
			name:     "zero MTU invalid",
			port:     UplinkPort{Name: "eth0", MTU: 0, Speed: 1000000000},
			expected: false,
		},
		{
			name:     "zero speed invalid",
			port:     UplinkPort{Name: "eth0", MTU: 1500, Speed: 0},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.port.Valid(); got != tt.expected {
				t.Errorf("UplinkPort.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayNode_MeetsMinReputation(t *testing.T) {
	tests := []struct {
		name       string
		reputation float64
		expected   bool
	}{
		{"exactly minimum", MinReputation, true},
		{"above minimum", 0.90, true},
		{"below minimum", 0.80, false},
		{"zero", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &GatewayNode{Reputation: tt.reputation}
			if got := node.MeetsMinReputation(); got != tt.expected {
				t.Errorf("GatewayNode.MeetsMinReputation() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayNode_MeetsMinAge(t *testing.T) {
	minAge := time.Duration(MinAgeDays) * 24 * time.Hour

	tests := []struct {
		name     string
		age      time.Duration
		expected bool
	}{
		{"exactly minimum", minAge, true},
		{"above minimum", minAge + 24*time.Hour, true},
		{"below minimum", minAge - 24*time.Hour, false},
		{"zero", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &GatewayNode{Age: tt.age}
			if got := node.MeetsMinAge(); got != tt.expected {
				t.Errorf("GatewayNode.MeetsMinAge() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayNode_MeetsMinUptime(t *testing.T) {
	tests := []struct {
		name     string
		uptime   float64
		expected bool
	}{
		{"exactly minimum", MinUptimePct, true},
		{"above minimum", 99.0, true},
		{"below minimum", 90.0, false},
		{"zero", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &GatewayNode{Uptime: tt.uptime}
			if got := node.MeetsMinUptime(); got != tt.expected {
				t.Errorf("GatewayNode.MeetsMinUptime() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayNode_MeetsAllRequirements(t *testing.T) {
	minAge := time.Duration(MinAgeDays) * 24 * time.Hour

	tests := []struct {
		name       string
		reputation float64
		age        time.Duration
		uptime     float64
		expected   bool
	}{
		{
			name:       "all requirements met",
			reputation: 0.90,
			age:        minAge + 24*time.Hour,
			uptime:     99.0,
			expected:   true,
		},
		{
			name:       "reputation too low",
			reputation: 0.80,
			age:        minAge + 24*time.Hour,
			uptime:     99.0,
			expected:   false,
		},
		{
			name:       "age too young",
			reputation: 0.90,
			age:        minAge - 24*time.Hour,
			uptime:     99.0,
			expected:   false,
		},
		{
			name:       "uptime too low",
			reputation: 0.90,
			age:        minAge + 24*time.Hour,
			uptime:     90.0,
			expected:   false,
		},
		{
			name:       "multiple requirements not met",
			reputation: 0.50,
			age:        0,
			uptime:     50.0,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &GatewayNode{
				Reputation: tt.reputation,
				Age:        tt.age,
				Uptime:     tt.uptime,
			}
			if got := node.MeetsAllRequirements(); got != tt.expected {
				t.Errorf("GatewayNode.MeetsAllRequirements() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayNode_HasService(t *testing.T) {
	tests := []struct {
		name     string
		services map[string]bool
		check    string
		expected bool
	}{
		{
			name:     "service present",
			services: map[string]bool{ServiceOverlay: true},
			check:    ServiceOverlay,
			expected: true,
		},
		{
			name:     "service not present",
			services: map[string]bool{ServiceOverlay: true},
			check:    ServiceEdge,
			expected: false,
		},
		{
			name:     "nil services map",
			services: nil,
			check:    ServiceOverlay,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &GatewayNode{ActiveServices: tt.services}
			if got := node.HasService(tt.check); got != tt.expected {
				t.Errorf("GatewayNode.HasService(%q) = %v, want %v", tt.check, got, tt.expected)
			}
		})
	}
}

func TestGatewayCapabilities_DefaultCapabilities(t *testing.T) {
	caps := DefaultCapabilities()

	if !caps.OverlaySupported {
		t.Error("DefaultCapabilities should support overlay")
	}
	if !caps.EdgeSupported {
		t.Error("DefaultCapabilities should support edge")
	}
	if caps.TransitSupported {
		t.Error("DefaultCapabilities should not support transit by default")
	}
	if caps.MaxVNIs != DefaultMaxVNIs {
		t.Errorf("DefaultCapabilities MaxVNIs = %d, want %d", caps.MaxVNIs, DefaultMaxVNIs)
	}
	if caps.MaxPeers != DefaultMaxPeers {
		t.Errorf("DefaultCapabilities MaxPeers = %d, want %d", caps.MaxPeers, DefaultMaxPeers)
	}
	if caps.MaxServices != DefaultMaxServices {
		t.Errorf("DefaultCapabilities MaxServices = %d, want %d", caps.MaxServices, DefaultMaxServices)
	}
}

func TestUplinkConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      UplinkConfig
		expectError bool
	}{
		{
			name:        "valid config",
			config:      UplinkConfig{Name: "eth0", MTU: 1500},
			expectError: false,
		},
		{
			name:        "empty name",
			config:      UplinkConfig{Name: "", MTU: 1500},
			expectError: true,
		},
		{
			name:        "zero MTU",
			config:      UplinkConfig{Name: "eth0", MTU: 0},
			expectError: true,
		},
		{
			name:        "negative MTU",
			config:      UplinkConfig{Name: "eth0", MTU: -1},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("UplinkConfig.Validate() expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("UplinkConfig.Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestEdgeConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      EdgeConfig
		expectError bool
	}{
		{
			name:        "valid enabled config",
			config:      EdgeConfig{Enabled: true, MaxDevices: 100, MaxServices: 50},
			expectError: false,
		},
		{
			name:        "disabled config skips validation",
			config:      EdgeConfig{Enabled: false, MaxDevices: 0, MaxServices: 0},
			expectError: false,
		},
		{
			name:        "zero max devices",
			config:      EdgeConfig{Enabled: true, MaxDevices: 0, MaxServices: 50},
			expectError: true,
		},
		{
			name:        "zero max services",
			config:      EdgeConfig{Enabled: true, MaxDevices: 100, MaxServices: 0},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("EdgeConfig.Validate() expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("EdgeConfig.Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestFirewallConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      FirewallConfig
		expectError bool
	}{
		{
			name:        "valid deny policy",
			config:      FirewallConfig{Enabled: true, DefaultPolicy: "deny"},
			expectError: false,
		},
		{
			name:        "valid allow policy",
			config:      FirewallConfig{Enabled: true, DefaultPolicy: "allow"},
			expectError: false,
		},
		{
			name:        "disabled skips validation",
			config:      FirewallConfig{Enabled: false},
			expectError: false,
		},
		{
			name:        "invalid policy",
			config:      FirewallConfig{Enabled: true, DefaultPolicy: "invalid"},
			expectError: true,
		},
		{
			name:        "empty policy",
			config:      FirewallConfig{Enabled: true, DefaultPolicy: ""},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("FirewallConfig.Validate() expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("FirewallConfig.Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestTunnelConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      TunnelConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: TunnelConfig{
				Name: "gre1", Type: "gre",
				Local: "198.51.100.4", Remote: "198.51.100.100",
				TunnelIP: "10.255.0.1/30",
			},
			expectError: false,
		},
		{
			name: "valid with ipv6",
			config: TunnelConfig{
				Name: "gre2", Type: "gre",
				Local: "198.51.100.5", Remote: "198.51.100.100",
				TunnelIP: "10.255.0.5/30", TunnelIPv6: "2001:db8::1/64",
			},
			expectError: false,
		},
		{
			name: "empty name",
			config: TunnelConfig{
				Name: "", Type: "gre",
				Local: "198.51.100.4", Remote: "198.51.100.100",
				TunnelIP: "10.255.0.1",
			},
			expectError: true,
		},
		{
			name: "empty type",
			config: TunnelConfig{
				Name: "gre1", Type: "",
				Local: "198.51.100.4", Remote: "198.51.100.100",
				TunnelIP: "10.255.0.1",
			},
			expectError: true,
		},
		{
			name: "empty local",
			config: TunnelConfig{
				Name: "gre1", Type: "gre",
				Local: "", Remote: "198.51.100.100",
				TunnelIP: "10.255.0.1",
			},
			expectError: true,
		},
		{
			name: "empty remote",
			config: TunnelConfig{
				Name: "gre1", Type: "gre",
				Local: "198.51.100.4", Remote: "",
				TunnelIP: "10.255.0.1",
			},
			expectError: true,
		},
		{
			name: "empty tunnel ip",
			config: TunnelConfig{
				Name: "gre1", Type: "gre",
				Local: "198.51.100.4", Remote: "198.51.100.100",
				TunnelIP: "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("TunnelConfig.Validate() expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("TunnelConfig.Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestNATConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      NATConfig
		expectError bool
	}{
		{
			name: "valid enabled config",
			config: NATConfig{
				Enabled:        true,
				ExternalIP:     "192.168.1.1",
				PortRangeStart: 1024,
				PortRangeEnd:   65535,
				MaxSessions:    10000,
			},
			expectError: false,
		},
		{
			name:        "disabled config skips validation",
			config:      NATConfig{Enabled: false},
			expectError: false,
		},
		{
			name: "uplinks replace the external ip (#586)",
			config: NATConfig{
				Enabled: true, PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 10000,
				Uplinks: []NATUplinkConfig{{Name: "isp-a", Addresses: []string{"198.51.100.4"}, Default: true}, {Name: "isp-b", Addresses: []string{"192.0.2.4-192.0.2.5"}}},
				Static:  []NATStaticConfig{{Internal: "10.4.200.10", External: "203.0.113.4"}, {Internal: "10.4.200.11", External: "192.0.2.6", Uplink: "isp-b"}},
			},
			expectError: false,
		},
		{
			name: "static without uplinks",
			config: NATConfig{
				Enabled: true, ExternalIP: "192.168.1.1", PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 10000,
				Static: []NATStaticConfig{{Internal: "10.4.200.10", External: "203.0.113.4"}},
			},
			expectError: true,
		},
		{
			name: "uplink without a name",
			config: NATConfig{
				Enabled: true, PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 10000,
				Uplinks: []NATUplinkConfig{{Addresses: []string{"198.51.100.4"}}},
			},
			expectError: true,
		},
		{
			name: "uplink without addresses",
			config: NATConfig{
				Enabled: true, PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 10000,
				Uplinks: []NATUplinkConfig{{Name: "isp-a"}},
			},
			expectError: true,
		},
		{
			name: "duplicate uplink",
			config: NATConfig{
				Enabled: true, PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 10000,
				Uplinks: []NATUplinkConfig{{Name: "isp-a", Addresses: []string{"198.51.100.4"}}, {Name: "isp-a", Addresses: []string{"198.51.100.5"}}},
			},
			expectError: true,
		},
		{
			name: "static naming an unknown uplink",
			config: NATConfig{
				Enabled: true, PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 10000,
				Uplinks: []NATUplinkConfig{{Name: "isp-a", Addresses: []string{"198.51.100.4"}}},
				Static:  []NATStaticConfig{{Internal: "10.4.200.10", External: "203.0.113.4", Uplink: "starlink"}},
			},
			expectError: true,
		},
		{
			name: "static missing an address",
			config: NATConfig{
				Enabled: true, PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 10000,
				Uplinks: []NATUplinkConfig{{Name: "isp-a", Addresses: []string{"198.51.100.4"}}},
				Static:  []NATStaticConfig{{Internal: "", External: "203.0.113.4"}},
			},
			expectError: true,
		},
		{
			name: "empty external IP",
			config: NATConfig{
				Enabled:        true,
				ExternalIP:     "",
				PortRangeStart: 1024,
				PortRangeEnd:   65535,
				MaxSessions:    10000,
			},
			expectError: true,
		},
		{
			name: "invalid port range",
			config: NATConfig{
				Enabled:        true,
				ExternalIP:     "192.168.1.1",
				PortRangeStart: 65535,
				PortRangeEnd:   1024,
				MaxSessions:    10000,
			},
			expectError: true,
		},
		{
			name: "zero max sessions",
			config: NATConfig{
				Enabled:        true,
				ExternalIP:     "192.168.1.1",
				PortRangeStart: 1024,
				PortRangeEnd:   65535,
				MaxSessions:    0,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("NATConfig.Validate() expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("NATConfig.Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestLoadBalancerConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      LoadBalancerConfig
		expectError bool
	}{
		{
			name: "valid enabled config",
			config: LoadBalancerConfig{
				Enabled:             true,
				Algorithm:           "round-robin",
				HealthCheckInterval: 30 * time.Second,
				HealthCheckTimeout:  5 * time.Second,
				MaxBackends:         10,
			},
			expectError: false,
		},
		{
			name:        "disabled config skips validation",
			config:      LoadBalancerConfig{Enabled: false},
			expectError: false,
		},
		{
			name: "empty algorithm",
			config: LoadBalancerConfig{
				Enabled:             true,
				Algorithm:           "",
				HealthCheckInterval: 30 * time.Second,
				HealthCheckTimeout:  5 * time.Second,
				MaxBackends:         10,
			},
			expectError: true,
		},
		{
			name: "zero health check interval",
			config: LoadBalancerConfig{
				Enabled:             true,
				Algorithm:           "round-robin",
				HealthCheckInterval: 0,
				HealthCheckTimeout:  5 * time.Second,
				MaxBackends:         10,
			},
			expectError: true,
		},
		{
			name: "timeout greater than interval",
			config: LoadBalancerConfig{
				Enabled:             true,
				Algorithm:           "round-robin",
				HealthCheckInterval: 5 * time.Second,
				HealthCheckTimeout:  30 * time.Second,
				MaxBackends:         10,
			},
			expectError: true,
		},
		{
			name: "zero max backends",
			config: LoadBalancerConfig{
				Enabled:             true,
				Algorithm:           "round-robin",
				HealthCheckInterval: 30 * time.Second,
				HealthCheckTimeout:  5 * time.Second,
				MaxBackends:         0,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("LoadBalancerConfig.Validate() expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("LoadBalancerConfig.Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestGatewayConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *GatewayConfig
		expectError bool
	}{
		{
			name: "valid config with overlay",
			config: &GatewayConfig{
				Enabled:       true,
				ID:            "gw-1",
				MinReputation: MinReputation,
				MinAgeDays:    MinAgeDays,
				MinUptimePct:  MinUptimePct,
				Overlay:       validOverlayServiceConfig(),
			},
			expectError: false,
		},
		{
			name: "disabled config skips validation",
			config: &GatewayConfig{
				Enabled: false, ID: "",
			},
			expectError: false,
		},
		{
			name: "empty ID",
			config: &GatewayConfig{
				Enabled: true, ID: "",
				Overlay: validOverlayServiceConfig(),
			},
			expectError: true,
		},
		{
			name: "valid config no services",
			config: &GatewayConfig{
				Enabled:       true,
				ID:            "gw-2",
				MinReputation: MinReputation,
				MinAgeDays:    MinAgeDays,
				MinUptimePct:  MinUptimePct,
			},
			expectError: false,
		},
		{
			name: "invalid uplink config",
			config: &GatewayConfig{
				Enabled: true,
				ID:      "gw-3",
				Uplinks: []UplinkConfig{{Name: "", MTU: 0}},
			},
			expectError: true,
		},
		{
			name: "invalid edge config",
			config: &GatewayConfig{
				Enabled: true,
				ID:      "gw-4",
				Edge:    &EdgeConfig{Enabled: true, MaxDevices: 0},
			},
			expectError: true,
		},
		{
			name: "invalid firewall config",
			config: &GatewayConfig{
				Enabled:  true,
				ID:       "gw-5",
				Firewall: &FirewallConfig{Enabled: true, DefaultPolicy: "invalid"},
			},
			expectError: true,
		},
		{
			name: "invalid tunnel config",
			config: &GatewayConfig{
				Enabled: true,
				ID:      "gw-6",
				Tunnels: []TunnelConfig{{Name: "", Type: ""}},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("GatewayConfig.Validate() expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("GatewayConfig.Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestGatewayConfig_HasEnabledServices(t *testing.T) {
	tests := []struct {
		name     string
		config   *GatewayConfig
		expected bool
	}{
		{
			name:     "overlay enabled",
			config:   &GatewayConfig{Overlay: validOverlayServiceConfig()},
			expected: true,
		},
		{
			name:     "edge enabled",
			config:   &GatewayConfig{Edge: &EdgeConfig{Enabled: true}},
			expected: true,
		},
		{
			name:     "bgp present",
			config:   &GatewayConfig{BGP: &bgp.BGPConfig{}},
			expected: true,
		},
		{
			name:     "tunnels present",
			config:   &GatewayConfig{Tunnels: []TunnelConfig{{Name: "gre1"}}},
			expected: true,
		},
		{
			name:     "no services",
			config:   &GatewayConfig{},
			expected: false,
		},
		{
			name:     "overlay disabled",
			config:   &GatewayConfig{Overlay: &OverlayServiceConfig{Enabled: false}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.HasEnabledServices(); got != tt.expected {
				t.Errorf("HasEnabledServices() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayStatus_IsHealthy(t *testing.T) {
	tests := []struct {
		name              string
		state             GatewayState
		healthCheckPassed bool
		expected          bool
	}{
		{
			name:              "running and passed health check",
			state:             GatewayStateRunning,
			healthCheckPassed: true,
			expected:          true,
		},
		{
			name:              "running but failed health check",
			state:             GatewayStateRunning,
			healthCheckPassed: false,
			expected:          false,
		},
		{
			name:              "degraded with passed health check",
			state:             GatewayStateDegraded,
			healthCheckPassed: true,
			expected:          false,
		},
		{
			name:              "stopped",
			state:             GatewayStateStopped,
			healthCheckPassed: false,
			expected:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &GatewayStatus{
				State:             tt.state,
				HealthCheckPassed: tt.healthCheckPassed,
			}
			if got := status.IsHealthy(); got != tt.expected {
				t.Errorf("GatewayStatus.IsHealthy() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOverlayGatewayState_Fields(t *testing.T) {
	state := &OverlayGatewayState{
		ActiveVNIs:           100,
		TunnelCount:          10,
		EVPNRoutesReceived:   500,
		EVPNRoutesAdvertised: 200,
		LastBGPUpdate:        time.Now(),
	}

	if state.ActiveVNIs != 100 {
		t.Errorf("ActiveVNIs = %d, want 100", state.ActiveVNIs)
	}
	if state.TunnelCount != 10 {
		t.Errorf("TunnelCount = %d, want 10", state.TunnelCount)
	}
}

func TestEdgeGatewayState_Fields(t *testing.T) {
	state := &EdgeGatewayState{
		ConnectedDevices:        50,
		ActiveServices:          10,
		NATSessionCount:         1000,
		LoadBalancedConnections: 500,
		LastHealthCheck:         time.Now(),
	}

	if state.ConnectedDevices != 50 {
		t.Errorf("ConnectedDevices = %d, want 50", state.ConnectedDevices)
	}
	if state.ActiveServices != 10 {
		t.Errorf("ActiveServices = %d, want 10", state.ActiveServices)
	}
}

func TestTransitGatewayState_Fields(t *testing.T) {
	state := &TransitGatewayState{
		AnnouncedPrefixes:     20,
		ReceivedPrefixes:      100,
		BGPPeersEstablished:   5,
		IPv6PrefixesAnnounced: 15,
		IPv4PrefixesAnnounced: 5,
		LastRouteUpdate:       time.Now(),
	}

	if state.AnnouncedPrefixes != 20 {
		t.Errorf("AnnouncedPrefixes = %d, want 20", state.AnnouncedPrefixes)
	}
	if state.BGPPeersEstablished != 5 {
		t.Errorf("BGPPeersEstablished = %d, want 5", state.BGPPeersEstablished)
	}
}

func TestUplinkPort_WithMACAddress(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	port := &UplinkPort{
		Name:       "eth0",
		MTU:        1500,
		Speed:      1000000000,
		MACAddress: mac,
		State:      PortStateUp,
	}

	if port.MACAddress.String() != "00:11:22:33:44:55" {
		t.Errorf("MACAddress = %s, want 00:11:22:33:44:55", port.MACAddress.String())
	}
	if !port.Valid() {
		t.Error("port should be valid")
	}
}

func TestDHCPServiceConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      DHCPServiceConfig
		expectError bool
	}{
		{
			name:        "valid config",
			config:      DHCPServiceConfig{Enabled: true, Interface: "eth0"},
			expectError: false,
		},
		{
			name:        "disabled skips validation",
			config:      DHCPServiceConfig{Enabled: false},
			expectError: false,
		},
		{
			name:        "missing interface",
			config:      DHCPServiceConfig{Enabled: true, Interface: ""},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("DHCPServiceConfig.Validate() expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("DHCPServiceConfig.Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestOverlayServiceConfig_Validate(t *testing.T) {
	valid := OverlayServiceConfig{
		Enabled:           true,
		LocalVTEP:         netip.MustParseAddr("10.4.100.20"),
		UnderlayInterface: "vtep0",
		UnderlayMTU:       9216,
		AccessPort:        "patch-workloads",
		OverlayASN:        65000,
		VXLANPort:         4789,
		DefaultVNI:        10100,
		MaxVNIs:           DefaultMaxVNIs,
		VerdictMaxAge:     time.Minute,
	}
	tests := []struct {
		name        string
		config      OverlayServiceConfig
		expectError bool
	}{
		{
			name:        "valid enabled config",
			config:      valid,
			expectError: false,
		},
		{
			name:        "disabled skips validation",
			config:      OverlayServiceConfig{Enabled: false},
			expectError: false,
		},
		{
			name: "enabled requires local VTEP",
			config: func() OverlayServiceConfig {
				cfg := valid
				cfg.LocalVTEP = netip.Addr{}
				return cfg
			}(),
			expectError: true,
		},
		{
			name: "enabled requires underlay MTU at VXLAN minimum",
			config: func() OverlayServiceConfig {
				cfg := valid
				cfg.UnderlayMTU = 1500
				return cfg
			}(),
			expectError: true,
		},
		{
			name: "enabled requires access port",
			config: func() OverlayServiceConfig {
				cfg := valid
				cfg.AccessPort = ""
				return cfg
			}(),
			expectError: true,
		},
		{
			name: "enabled requires overlay ASN",
			config: func() OverlayServiceConfig {
				cfg := valid
				cfg.OverlayASN = 0
				return cfg
			}(),
			expectError: true,
		},
		{
			name: "enabled accepts four byte overlay ASN",
			config: func() OverlayServiceConfig {
				cfg := valid
				cfg.OverlayASN = 65536
				return cfg
			}(),
			expectError: false,
		},
		{
			name: "enabled defaults underlay MTU and verdict age",
			config: func() OverlayServiceConfig {
				cfg := valid
				cfg.UnderlayMTU = 0
				cfg.VerdictMaxAge = 0
				return cfg
			}(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("OverlayServiceConfig.Validate() expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("OverlayServiceConfig.Validate() unexpected error: %v", err)
			}
			if tt.name == "enabled defaults underlay MTU and verdict age" {
				if tt.config.UnderlayMTU != vxlan.MinimumUnderlayMTU {
					t.Errorf("UnderlayMTU default = %d", tt.config.UnderlayMTU)
				}
				if tt.config.VerdictMaxAge != DefaultOverlayVerdictMaxAge {
					t.Errorf("VerdictMaxAge default = %s", tt.config.VerdictMaxAge)
				}
			}
		})
	}
}
