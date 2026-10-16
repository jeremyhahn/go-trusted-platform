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
	"bytes"
	"errors"
	"maps"
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
		VNIs:              []OverlayVNIConfig{{VNI: 40100, VLAN: 100}, {VNI: 40200, VLAN: 200}},
		DefaultVNI:        40100,
		MaxVNIs:           DefaultMaxVNIs,
		VerdictMaxAge:     time.Minute,
	}
}

// withOverlayIRB turns symmetric IRB on in an overlay config: both VNIs
// routed, the anycast gateway MAC, an L3VNI and the route reflector it needs.
func withOverlayIRB(c *OverlayServiceConfig) {
	c.VNIs[0].Subnet = netip.MustParsePrefix("10.40.1.0/24")
	c.VNIs[1].Subnet = netip.MustParsePrefix("10.40.2.0/24")
	c.AnycastGatewayMAC = "02:aa:aa:aa:aa:aa"
	c.L3VNI = 50000
	c.RRPeers = []bgp.NeighborConfig{{Address: netip.MustParseAddr("10.4.100.10"), ASN: 65000}}
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
	tests := []struct {
		name string
		edit func(*OverlayServiceConfig)
		// field is the overlay field the typed error must name; empty means
		// the config is valid.
		field string
	}{
		{name: "valid enabled config", edit: func(*OverlayServiceConfig) {}},
		{name: "requires local VTEP", edit: func(c *OverlayServiceConfig) { c.LocalVTEP = netip.Addr{} }, field: "local-vtep"},
		{name: "requires underlay interface", edit: func(c *OverlayServiceConfig) { c.UnderlayInterface = "" }, field: "underlay-interface"},
		{name: "requires underlay MTU at VXLAN minimum", edit: func(c *OverlayServiceConfig) { c.UnderlayMTU = 1500 }, field: "underlay-mtu"},
		{name: "requires access port", edit: func(c *OverlayServiceConfig) { c.AccessPort = "" }, field: "access-port"},
		{name: "requires overlay ASN", edit: func(c *OverlayServiceConfig) { c.OverlayASN = 0 }, field: "overlay-asn"},
		{name: "rejects public 2-byte overlay ASN", edit: func(c *OverlayServiceConfig) { c.OverlayASN = 64511 }, field: "overlay-asn"},
		{name: "rejects four byte overlay ASN", edit: func(c *OverlayServiceConfig) { c.OverlayASN = 65536 }, field: "overlay-asn"},
		{name: "accepts top private overlay ASN", edit: func(c *OverlayServiceConfig) { c.OverlayASN = 65534 }},
		{name: "requires VXLAN port", edit: func(c *OverlayServiceConfig) { c.VXLANPort = 0 }, field: "vxlan-port"},
		{name: "rejects a passive route reflector peer", edit: func(c *OverlayServiceConfig) {
			c.RRPeers = []bgp.NeighborConfig{{Address: netip.MustParseAddr("10.4.100.10"), ASN: 65000, PassiveMode: true}}
		}, field: "rr-peers"},
		{name: "rejects negative max VNIs", edit: func(c *OverlayServiceConfig) { c.MaxVNIs = -1 }, field: "max-vnis"},
		{name: "requires a VNI to join", edit: func(c *OverlayServiceConfig) { c.VNIs = nil; c.DefaultVNI = 0 }, field: "vnis"},
		{name: "rejects more VNIs than max VNIs", edit: func(c *OverlayServiceConfig) { c.MaxVNIs = 1 }, field: "vnis"},
		{name: "rejects VNI zero", edit: func(c *OverlayServiceConfig) { c.VNIs[1].VNI = 0 }, field: "vnis"},
		{name: "rejects VNI wider than 24 bits", edit: func(c *OverlayServiceConfig) { c.VNIs[1].VNI = MaxOverlayVNI + 1 }, field: "vnis"},
		{name: "accepts the top 24-bit VNI", edit: func(c *OverlayServiceConfig) { c.VNIs[1].VNI = MaxOverlayVNI }},
		{name: "rejects VLAN zero", edit: func(c *OverlayServiceConfig) { c.VNIs[1].VLAN = 0 }, field: "vnis"},
		{name: "rejects VLAN above 4094", edit: func(c *OverlayServiceConfig) { c.VNIs[1].VLAN = MaxOverlayVLAN + 1 }, field: "vnis"},
		{name: "rejects a VNI listed twice", edit: func(c *OverlayServiceConfig) { c.VNIs[1].VNI = c.VNIs[0].VNI }, field: "vnis"},
		{name: "rejects a VLAN carrying two VNIs", edit: func(c *OverlayServiceConfig) { c.VNIs[1].VLAN = c.VNIs[0].VLAN }, field: "vnis"},
		{name: "rejects a default VNI the overlay does not join", edit: func(c *OverlayServiceConfig) { c.DefaultVNI = 40300 }, field: "default-vni"},
		{name: "accepts no default VNI", edit: func(c *OverlayServiceConfig) { c.DefaultVNI = 0 }},
		{name: "rejects negative verdict age", edit: func(c *OverlayServiceConfig) { c.VerdictMaxAge = -time.Second }, field: "verdict-max-age"},
		{name: "rejects negative verdict clock skew", edit: func(c *OverlayServiceConfig) { c.VerdictClockSkew = -time.Second }, field: "verdict-clock-skew"},
		{name: "rejects negative sweep interval", edit: func(c *OverlayServiceConfig) { c.AdmissionSweepInterval = -time.Second }, field: "admission-sweep-interval"},

		// Symmetric IRB.
		{name: "accepts symmetric IRB", edit: withOverlayIRB},
		{name: "accepts routing without an L3VNI", edit: func(c *OverlayServiceConfig) { withOverlayIRB(c); c.L3VNI = 0; c.RRPeers = nil }},
		{name: "accepts a routed VNI beside a bridged one", edit: func(c *OverlayServiceConfig) { withOverlayIRB(c); c.VNIs[1].Subnet = netip.Prefix{} }},
		{name: "rejects an IPv6 VNI subnet", edit: func(c *OverlayServiceConfig) {
			withOverlayIRB(c)
			c.VNIs[1].Subnet = netip.MustParsePrefix("fd00::/64")
		}, field: "vnis"},
		{name: "rejects a VNI subnet with host bits set", edit: func(c *OverlayServiceConfig) {
			withOverlayIRB(c)
			c.VNIs[1].Subnet = netip.MustParsePrefix("10.40.2.5/24")
		}, field: "vnis"},
		{name: "rejects a VNI subnet with no gateway address", edit: func(c *OverlayServiceConfig) {
			withOverlayIRB(c)
			c.VNIs[1].Subnet = netip.MustParsePrefix("10.40.2.0/32")
		}, field: "vnis"},
		{name: "rejects overlapping VNI subnets", edit: func(c *OverlayServiceConfig) {
			withOverlayIRB(c)
			c.VNIs[1].Subnet = netip.MustParsePrefix("10.40.1.128/25")
		}, field: "vnis"},
		{name: "rejects a VNI subnet containing an earlier listed one", edit: func(c *OverlayServiceConfig) {
			withOverlayIRB(c)
			c.VNIs[1].Subnet = netip.MustParsePrefix("10.40.0.0/16")
		}, field: "vnis"},
		{name: "requires the anycast MAC with a VNI subnet", edit: func(c *OverlayServiceConfig) { withOverlayIRB(c); c.AnycastGatewayMAC = "" }, field: "anycast-gateway-mac"},
		{name: "rejects the anycast MAC without a VNI subnet", edit: func(c *OverlayServiceConfig) { c.AnycastGatewayMAC = "02:aa:aa:aa:aa:aa" }, field: "anycast-gateway-mac"},
		{name: "rejects a malformed anycast MAC", edit: func(c *OverlayServiceConfig) { withOverlayIRB(c); c.AnycastGatewayMAC = "02:aa:aa" }, field: "anycast-gateway-mac"},
		{name: "rejects an 8-byte anycast MAC", edit: func(c *OverlayServiceConfig) { withOverlayIRB(c); c.AnycastGatewayMAC = "02:aa:aa:aa:aa:aa:aa:aa" }, field: "anycast-gateway-mac"},
		{name: "rejects a multicast anycast MAC", edit: func(c *OverlayServiceConfig) { withOverlayIRB(c); c.AnycastGatewayMAC = "01:00:5e:00:00:01" }, field: "anycast-gateway-mac"},
		{name: "rejects the zero anycast MAC", edit: func(c *OverlayServiceConfig) { withOverlayIRB(c); c.AnycastGatewayMAC = "00:00:00:00:00:00" }, field: "anycast-gateway-mac"},
		{name: "rejects an anycast MAC in the router MAC space", edit: func(c *OverlayServiceConfig) { withOverlayIRB(c); c.AnycastGatewayMAC = "02:00:0a:04:64:15" }, field: "anycast-gateway-mac"},
		{name: "accepts the top 24-bit L3VNI", edit: func(c *OverlayServiceConfig) { withOverlayIRB(c); c.L3VNI = MaxOverlayVNI }},
		{name: "rejects an L3VNI wider than 24 bits", edit: func(c *OverlayServiceConfig) { withOverlayIRB(c); c.L3VNI = MaxOverlayVNI + 1 }, field: "l3vni"},
		{name: "rejects an L3VNI that is also an L2VNI", edit: func(c *OverlayServiceConfig) { withOverlayIRB(c); c.L3VNI = c.VNIs[1].VNI }, field: "l3vni"},
		{name: "rejects an L3VNI without a routed VNI", edit: func(c *OverlayServiceConfig) {
			withOverlayIRB(c)
			c.VNIs[0].Subnet, c.VNIs[1].Subnet, c.AnycastGatewayMAC = netip.Prefix{}, netip.Prefix{}, ""
		}, field: "l3vni"},
		{name: "rejects an L3VNI without RR peers", edit: func(c *OverlayServiceConfig) { withOverlayIRB(c); c.RRPeers = nil }, field: "l3vni"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validOverlayServiceConfig()
			tt.edit(cfg)
			err := cfg.Validate()
			if tt.field == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			var invalid *ErrOverlayConfigInvalid
			if !errors.As(err, &invalid) {
				t.Fatalf("Validate() = %v, want *ErrOverlayConfigInvalid", err)
			}
			if invalid.Field != tt.field {
				t.Errorf("Field = %q, want %q", invalid.Field, tt.field)
			}
		})
	}
}

func TestOverlayServiceConfig_ValidateDisabledSkipsChecks(t *testing.T) {
	cfg := &OverlayServiceConfig{Enabled: false, OverlayASN: 70000}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() on a disabled overlay = %v, want nil", err)
	}
}

func TestOverlayServiceConfig_AnycastGateways(t *testing.T) {
	t.Run("each routed VNI gets the first host of its subnet", func(t *testing.T) {
		cfg := validOverlayServiceConfig()
		withOverlayIRB(cfg)
		cfg.VNIs = append(cfg.VNIs, OverlayVNIConfig{VNI: 40300, VLAN: 300})
		gateways, mac, err := cfg.anycastGateways()
		if err != nil {
			t.Fatalf("anycastGateways() = %v", err)
		}
		want := map[uint32]netip.Addr{
			40100: netip.MustParseAddr("10.40.1.1"),
			40200: netip.MustParseAddr("10.40.2.1"),
		}
		if !maps.Equal(gateways, want) {
			t.Errorf("gateways = %v, want %v (VNI 40300 has no subnet and stays bridged)", gateways, want)
		}
		if mac.String() != "02:aa:aa:aa:aa:aa" {
			t.Errorf("anycast MAC = %s, want 02:aa:aa:aa:aa:aa", mac)
		}
	})
	t.Run("no subnet and no MAC bridges only", func(t *testing.T) {
		gateways, mac, err := validOverlayServiceConfig().anycastGateways()
		if err != nil || gateways != nil || mac != nil {
			t.Errorf("anycastGateways() = %v, %v, %v; want nil, nil, nil", gateways, mac, err)
		}
	})
	t.Run("a subnet without a gateway address is a typed error", func(t *testing.T) {
		cfg := validOverlayServiceConfig()
		withOverlayIRB(cfg)
		cfg.VNIs[0].Subnet = netip.MustParsePrefix("10.40.1.7/32")
		var invalid *ErrOverlayConfigInvalid
		if _, _, err := cfg.anycastGateways(); !errors.As(err, &invalid) || invalid.Field != "vnis" {
			t.Errorf("anycastGateways() = %v, want *ErrOverlayConfigInvalid naming vnis", err)
		}
	})
}

func TestOverlayServiceConfig_RouterMAC(t *testing.T) {
	cfg := validOverlayServiceConfig()
	withOverlayIRB(cfg)
	if got, want := cfg.routerMAC(), (net.HardwareAddr{0x02, 0x00, 10, 4, 100, 20}); !bytes.Equal(got, want) {
		t.Errorf("routerMAC() = %s, want %s from local-vtep 10.4.100.20", got, want)
	}
	cfg.L3VNI = 0
	if got := cfg.routerMAC(); got != nil {
		t.Errorf("routerMAC() without an L3VNI = %s, want nil", got)
	}
	cfg.L3VNI = 50000
	cfg.LocalVTEP = netip.MustParseAddr("fd00::20")
	if got := cfg.routerMAC(); got != nil {
		t.Errorf("routerMAC() for an IPv6 VTEP = %s, want nil", got)
	}
}

func TestOverlayServiceConfig_ValidateDefaults(t *testing.T) {
	cfg := validOverlayServiceConfig()
	cfg.UnderlayMTU = 0
	cfg.VerdictMaxAge = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if cfg.UnderlayMTU != vxlan.MinimumUnderlayMTU {
		t.Errorf("UnderlayMTU default = %d, want %d", cfg.UnderlayMTU, vxlan.MinimumUnderlayMTU)
	}
	if cfg.VerdictMaxAge != DefaultOverlayVerdictMaxAge {
		t.Errorf("VerdictMaxAge default = %s, want %s", cfg.VerdictMaxAge, DefaultOverlayVerdictMaxAge)
	}
	if got := cfg.admissionSweepInterval(); got != DefaultOverlayAdmissionSweepInterval {
		t.Errorf("admissionSweepInterval() = %s, want %s", got, DefaultOverlayAdmissionSweepInterval)
	}
	cfg.AdmissionSweepInterval = time.Minute
	if got := cfg.admissionSweepInterval(); got != time.Minute {
		t.Errorf("admissionSweepInterval() = %s, want the configured 1m", got)
	}
}

func TestGatewayConfig_ValidateOverlayExcludesEdgeServices(t *testing.T) {
	base := func() *GatewayConfig {
		return &GatewayConfig{Enabled: true, ID: "gw-overlay", Overlay: validOverlayServiceConfig()}
	}
	tests := []struct {
		name    string
		edit    func(*GatewayConfig)
		service string
	}{
		{
			name:    "firewall",
			edit:    func(c *GatewayConfig) { c.Firewall = &FirewallConfig{Enabled: true, DefaultPolicy: "deny"} },
			service: ServiceFirewall,
		},
		{
			name: "nat",
			edit: func(c *GatewayConfig) {
				c.NAT = &NATConfig{Enabled: true, ExternalIP: "192.0.2.1", PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 10}
			},
			service: ServiceNAT,
		},
		{
			name: "load balancer",
			edit: func(c *GatewayConfig) {
				c.LoadBalancer = &LoadBalancerConfig{Enabled: true, Algorithm: "round-robin", HealthCheckInterval: 30 * time.Second, HealthCheckTimeout: 5 * time.Second, MaxBackends: 10}
			},
			service: ServiceLoadBalancer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base()
			tt.edit(cfg)
			var conflict *ErrOverlayServiceConflict
			if err := cfg.Validate(); !errors.As(err, &conflict) {
				t.Fatalf("Validate() = %v, want *ErrOverlayServiceConflict", err)
			}
			if conflict.Service != tt.service {
				t.Errorf("Service = %q, want %q", conflict.Service, tt.service)
			}
		})
	}

	t.Run("disabled sections do not conflict", func(t *testing.T) {
		cfg := base()
		cfg.Firewall = &FirewallConfig{Enabled: false}
		cfg.NAT = &NATConfig{Enabled: false}
		cfg.LoadBalancer = &LoadBalancerConfig{Enabled: false}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})
}
