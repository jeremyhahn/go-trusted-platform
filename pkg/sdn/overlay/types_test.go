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

package overlay

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestControllerState_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state ControllerState
		want  string
	}{
		{ControllerStateUnknown, "unknown"},
		{ControllerStateInitializing, "initializing"},
		{ControllerStateRunning, "running"},
		{ControllerStateDegraded, "degraded"},
		{ControllerStateStopping, "stopping"},
		{ControllerStateStopped, "stopped"},
		{ControllerStateError, "error"},
		{ControllerState(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestControllerState_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state ControllerState
		want  bool
	}{
		{ControllerStateUnknown, true},
		{ControllerStateInitializing, true},
		{ControllerStateRunning, true},
		{ControllerStateDegraded, true},
		{ControllerStateStopping, true},
		{ControllerStateStopped, true},
		{ControllerStateError, true},
		{ControllerState(99), false},
	}

	for _, tt := range tests {
		t.Run(tt.state.String(), func(t *testing.T) {
			if got := tt.state.Valid(); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestControllerState_IsOperational(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state ControllerState
		want  bool
	}{
		{ControllerStateUnknown, false},
		{ControllerStateInitializing, false},
		{ControllerStateRunning, true},
		{ControllerStateDegraded, true},
		{ControllerStateStopping, false},
		{ControllerStateStopped, false},
		{ControllerStateError, false},
	}

	for _, tt := range tests {
		t.Run(tt.state.String(), func(t *testing.T) {
			if got := tt.state.IsOperational(); got != tt.want {
				t.Errorf("IsOperational() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestControllerState_IsHealthy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state ControllerState
		want  bool
	}{
		{ControllerStateRunning, true},
		{ControllerStateDegraded, false},
		{ControllerStateStopped, false},
	}

	for _, tt := range tests {
		t.Run(tt.state.String(), func(t *testing.T) {
			if got := tt.state.IsHealthy(); got != tt.want {
				t.Errorf("IsHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		wantErr error
	}{
		{
			name: "valid config",
			config: &Config{
				NodeID:            "node1",
				VTEPIP:            netip.MustParseAddr("10.0.0.1"),
				UnderlayInterface: "eth0",
				UnderlayMTU:       9000,
				VXLANPort:         4789,
				BridgeName:        "br-overlay",
			},
			wantErr: nil,
		},
		{
			name: "empty node ID",
			config: &Config{
				NodeID:            "",
				VTEPIP:            netip.MustParseAddr("10.0.0.1"),
				UnderlayInterface: "eth0",
				UnderlayMTU:       9000,
				VXLANPort:         4789,
				BridgeName:        "br-overlay",
			},
			wantErr: ErrNodeIDEmpty,
		},
		{
			name: "invalid VTEP IP",
			config: &Config{
				NodeID:            "node1",
				VTEPIP:            netip.Addr{},
				UnderlayInterface: "eth0",
				UnderlayMTU:       9000,
				VXLANPort:         4789,
				BridgeName:        "br-overlay",
			},
			wantErr: ErrInvalidVTEPIP,
		},
		{
			name: "unspecified VTEP IP",
			config: &Config{
				NodeID:            "node1",
				VTEPIP:            netip.MustParseAddr("0.0.0.0"),
				UnderlayInterface: "eth0",
				UnderlayMTU:       9000,
				VXLANPort:         4789,
				BridgeName:        "br-overlay",
			},
			wantErr: ErrInvalidVTEPIP,
		},
		{
			name: "empty underlay interface",
			config: &Config{
				NodeID:            "node1",
				VTEPIP:            netip.MustParseAddr("10.0.0.1"),
				UnderlayInterface: "",
				UnderlayMTU:       9000,
				VXLANPort:         4789,
				BridgeName:        "br-overlay",
			},
			wantErr: ErrUnderlayInterfaceEmpty,
		},
		{
			name: "MTU too small",
			config: &Config{
				NodeID:            "node1",
				VTEPIP:            netip.MustParseAddr("10.0.0.1"),
				UnderlayInterface: "eth0",
				UnderlayMTU:       500, // Too small for VXLAN
				VXLANPort:         4789,
				BridgeName:        "br-overlay",
			},
			wantErr: ErrMTUTooSmall,
		},
		{
			name: "zero VXLAN port",
			config: &Config{
				NodeID:            "node1",
				VTEPIP:            netip.MustParseAddr("10.0.0.1"),
				UnderlayInterface: "eth0",
				UnderlayMTU:       9000,
				VXLANPort:         0,
				BridgeName:        "br-overlay",
			},
			wantErr: ErrInvalidVXLANPort,
		},
		{
			name: "empty bridge name",
			config: &Config{
				NodeID:            "node1",
				VTEPIP:            netip.MustParseAddr("10.0.0.1"),
				UnderlayInterface: "eth0",
				UnderlayMTU:       9000,
				VXLANPort:         4789,
				BridgeName:        "",
			},
			wantErr: ErrBridgeNameEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_ApplyDefaults(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "node1",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
	}

	config.ApplyDefaults()

	if config.UnderlayMTU != DefaultUnderlayMTU {
		t.Errorf("UnderlayMTU = %d, want %d", config.UnderlayMTU, DefaultUnderlayMTU)
	}
	if config.VXLANPort != DefaultVXLANPort {
		t.Errorf("VXLANPort = %d, want %d", config.VXLANPort, DefaultVXLANPort)
	}
	if config.Environment != 0 {
		t.Errorf("Environment = %d, want 0 (no default environment)", config.Environment)
	}
	if config.BridgeName != DefaultBridgeName || DefaultBridgeName != "br-int" {
		t.Errorf("BridgeName = %s, want br-int", config.BridgeName)
	}
	if config.StateBackend != DefaultStateBackend {
		t.Errorf("StateBackend = %s, want %s", config.StateBackend, DefaultStateBackend)
	}
	if config.HealthCheckInterval != DefaultHealthCheckInterval {
		t.Errorf("HealthCheckInterval = %v, want %v", config.HealthCheckInterval, DefaultHealthCheckInterval)
	}
	if config.MACExpiration != DefaultMACExpiration {
		t.Errorf("MACExpiration = %v, want %v", config.MACExpiration, DefaultMACExpiration)
	}
}

func TestVNIConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *VNIConfig
		wantErr error
	}{
		{
			name:    "valid config",
			config:  &VNIConfig{VNI: 100000, VLAN: 100},
			wantErr: nil,
		},
		{
			name:    "VNI zero",
			config:  &VNIConfig{VNI: 0, VLAN: 100},
			wantErr: ErrVNIOutOfRange,
		},
		{
			name:    "VNI too large",
			config:  &VNIConfig{VNI: 16777216, VLAN: 100},
			wantErr: ErrVNIOutOfRange,
		},
		{
			name:    "VLAN out of range",
			config:  &VNIConfig{VNI: 100000, VLAN: 4095},
			wantErr: ErrVLANOutOfRange,
		},
		{
			name:    "valid zero VLAN",
			config:  &VNIConfig{VNI: 100000, VLAN: 0},
			wantErr: nil,
		},
		{
			name:    "valid max VLAN",
			config:  &VNIConfig{VNI: 100000, VLAN: 4094},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestRemoteMACEntry_IsExpired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "zero expiration (never expires)",
			expiresAt: time.Time{},
			want:      false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "not expired",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			entry := &RemoteMACEntry{
				ExpiresAt: tt.expiresAt,
			}

			if got := entry.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemoteMACEntry_Key(t *testing.T) {
	t.Parallel()

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	entry := &RemoteMACEntry{
		VNI: 100000,
		MAC: mac,
	}

	key := entry.Key()

	if key == "" {
		t.Errorf("Key() returned empty string")
	}

	// Key should contain VNI and MAC
	expected := "100000:00:11:22:33:44:55"
	if key != expected {
		t.Errorf("Key() = %s, want %s", key, expected)
	}
}

func TestFormatUint32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		n    uint32
		want string
	}{
		{0, "0"},
		{1, "1"},
		{100, "100"},
		{100000, "100000"},
		{4294967295, "4294967295"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			if got := formatUint32(tt.n); got != tt.want {
				t.Errorf("formatUint32(%d) = %s, want %s", tt.n, got, tt.want)
			}
		})
	}
}

func TestFormatMACKey(t *testing.T) {
	t.Parallel()

	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	key := formatMACKey(100000, mac)

	expected := "100000:00:11:22:33:44:55"
	if key != expected {
		t.Errorf("formatMACKey() = %s, want %s", key, expected)
	}
}
