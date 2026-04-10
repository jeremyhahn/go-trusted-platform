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
	"testing"
	"time"
)

func TestGatewayMode_String(t *testing.T) {
	tests := []struct {
		name     string
		mode     GatewayMode
		expected string
	}{
		{"overlay", GatewayModeOverlay, "overlay"},
		{"edge", GatewayModeEdge, "edge"},
		{"transit", GatewayModeTransit, "transit"},
		{"none", GatewayMode(0), "none"},
		{"mixed", GatewayModeOverlay | GatewayModeEdge, "mixed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.expected {
				t.Errorf("GatewayMode.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayMode_Valid(t *testing.T) {
	tests := []struct {
		name     string
		mode     GatewayMode
		expected bool
	}{
		{"overlay valid", GatewayModeOverlay, true},
		{"edge valid", GatewayModeEdge, true},
		{"transit valid", GatewayModeTransit, true},
		{"combined valid", GatewayModeOverlay | GatewayModeEdge, true},
		{"all modes valid", GatewayModeOverlay | GatewayModeEdge | GatewayModeTransit, true},
		{"zero invalid", GatewayMode(0), false},
		{"invalid bit set", GatewayMode(8), false},
		{"partially invalid", GatewayModeOverlay | GatewayMode(16), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mode.Valid(); got != tt.expected {
				t.Errorf("GatewayMode.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayMode_HasMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     GatewayMode
		check    GatewayMode
		expected bool
	}{
		{"overlay has overlay", GatewayModeOverlay, GatewayModeOverlay, true},
		{"overlay does not have edge", GatewayModeOverlay, GatewayModeEdge, false},
		{"combined has overlay", GatewayModeOverlay | GatewayModeEdge, GatewayModeOverlay, true},
		{"combined has edge", GatewayModeOverlay | GatewayModeEdge, GatewayModeEdge, true},
		{"combined does not have transit", GatewayModeOverlay | GatewayModeEdge, GatewayModeTransit, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mode.HasMode(tt.check); got != tt.expected {
				t.Errorf("GatewayMode.HasMode() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGatewayMode_Modes(t *testing.T) {
	tests := []struct {
		name          string
		mode          GatewayMode
		expectedCount int
	}{
		{"single mode", GatewayModeOverlay, 1},
		{"two modes", GatewayModeOverlay | GatewayModeEdge, 2},
		{"all modes", GatewayModeOverlay | GatewayModeEdge | GatewayModeTransit, 3},
		{"no modes", GatewayMode(0), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modes := tt.mode.Modes()
			if len(modes) != tt.expectedCount {
				t.Errorf("GatewayMode.Modes() returned %d modes, want %d", len(modes), tt.expectedCount)
			}
		})
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

func TestGatewayCapabilities_DefaultCapabilities(t *testing.T) {
	caps := DefaultCapabilities()

	if !caps.OverlaySupported {
		t.Error("DefaultCapabilities should support overlay mode")
	}
	if !caps.EdgeSupported {
		t.Error("DefaultCapabilities should support edge mode")
	}
	if caps.TransitSupported {
		t.Error("DefaultCapabilities should not support transit mode by default")
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

func TestGatewayCapabilities_SupportsMode(t *testing.T) {
	caps := GatewayCapabilities{
		OverlaySupported: true,
		EdgeSupported:    true,
		TransitSupported: false,
	}

	tests := []struct {
		name     string
		mode     GatewayMode
		expected bool
	}{
		{"overlay supported", GatewayModeOverlay, true},
		{"edge supported", GatewayModeEdge, true},
		{"transit not supported", GatewayModeTransit, false},
		{"invalid mode", GatewayMode(0), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := caps.SupportsMode(tt.mode); got != tt.expected {
				t.Errorf("GatewayCapabilities.SupportsMode(%v) = %v, want %v", tt.mode, got, tt.expected)
			}
		})
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
	validConfig := func() *GatewayConfig {
		return &GatewayConfig{
			Enabled:       true,
			ID:            "gw-1",
			Modes:         []GatewayMode{GatewayModeOverlay},
			MinReputation: MinReputation,
			MinAgeDays:    MinAgeDays,
			MinUptimePct:  MinUptimePct,
		}
	}

	tests := []struct {
		name        string
		modify      func(*GatewayConfig)
		expectError bool
	}{
		{
			name:        "valid config",
			modify:      func(c *GatewayConfig) {},
			expectError: false,
		},
		{
			name:        "disabled config skips validation",
			modify:      func(c *GatewayConfig) { c.Enabled = false; c.ID = "" },
			expectError: false,
		},
		{
			name:        "empty ID",
			modify:      func(c *GatewayConfig) { c.ID = "" },
			expectError: true,
		},
		{
			name:        "no modes",
			modify:      func(c *GatewayConfig) { c.Modes = nil },
			expectError: true,
		},
		{
			name:        "invalid mode",
			modify:      func(c *GatewayConfig) { c.Modes = []GatewayMode{GatewayMode(0)} },
			expectError: true,
		},
		{
			name: "invalid uplink config",
			modify: func(c *GatewayConfig) {
				c.Uplinks = []UplinkConfig{{Name: "", MTU: 0}}
			},
			expectError: true,
		},
		{
			name: "invalid edge config",
			modify: func(c *GatewayConfig) {
				c.EdgeConfig = &EdgeConfig{Enabled: true, MaxDevices: 0}
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.expectError && err == nil {
				t.Error("GatewayConfig.Validate() expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("GatewayConfig.Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestGatewayConfig_CombinedModes(t *testing.T) {
	tests := []struct {
		name     string
		modes    []GatewayMode
		expected GatewayMode
	}{
		{
			name:     "single mode",
			modes:    []GatewayMode{GatewayModeOverlay},
			expected: GatewayModeOverlay,
		},
		{
			name:     "two modes",
			modes:    []GatewayMode{GatewayModeOverlay, GatewayModeEdge},
			expected: GatewayModeOverlay | GatewayModeEdge,
		},
		{
			name:     "all modes",
			modes:    []GatewayMode{GatewayModeOverlay, GatewayModeEdge, GatewayModeTransit},
			expected: GatewayModeOverlay | GatewayModeEdge | GatewayModeTransit,
		},
		{
			name:     "no modes",
			modes:    []GatewayMode{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &GatewayConfig{Modes: tt.modes}
			if got := cfg.CombinedModes(); got != tt.expected {
				t.Errorf("GatewayConfig.CombinedModes() = %v, want %v", got, tt.expected)
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
