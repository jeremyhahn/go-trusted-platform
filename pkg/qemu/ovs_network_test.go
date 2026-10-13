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

package qemu

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOVSNetwork_NilConfig(t *testing.T) {
	n, err := NewOVSNetwork(nil, nil)
	assert.Nil(t, n)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidConfiguration)
}

func TestNewOVSNetwork_OVSNotEnabled(t *testing.T) {
	config := &Config{
		OVS: nil, // OVS not enabled
	}

	n, err := NewOVSNetwork(config, nil)
	assert.Nil(t, n)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidOVSConfig)
}

func TestNewOVSNetwork_OVSDisabled(t *testing.T) {
	config := &Config{
		OVS: &OVSConfig{
			Enable: false,
		},
	}

	n, err := NewOVSNetwork(config, nil)
	assert.Nil(t, n)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidOVSConfig)
}

func TestNewOVSNetwork_SocketNotFound(t *testing.T) {
	config := &Config{
		OVS: &OVSConfig{
			Enable:     true,
			SocketPath: "/nonexistent/socket.sock",
		},
	}

	n, err := NewOVSNetwork(config, nil)
	assert.Nil(t, n)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrOVSNotAvailable)
}

func TestValidateOVSConfig_NilConfig(t *testing.T) {
	err := ValidateOVSConfig(nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidOVSConfig)
}

func TestValidateOVSConfig_OVSNotEnabled(t *testing.T) {
	config := &Config{
		OVS: nil,
	}

	err := ValidateOVSConfig(config)
	assert.NoError(t, err) // No error when OVS is not enabled
}

func TestValidateOVSConfig_ValidConfig(t *testing.T) {
	config := &Config{
		OVS: &OVSConfig{
			Enable:     true,
			BridgeName: "test-br",
			VLAN:       100,
			VLANMode:   "access",
		},
	}

	err := ValidateOVSConfig(config)
	assert.NoError(t, err)
}

func TestValidateOVSConfig_InvalidVLAN(t *testing.T) {
	config := &Config{
		OVS: &OVSConfig{
			Enable: true,
			VLAN:   5000, // Invalid: > 4094
		},
	}

	err := ValidateOVSConfig(config)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidOVSConfig)
}

func TestValidateOVSConfig_InvalidTrunkVLAN(t *testing.T) {
	config := &Config{
		OVS: &OVSConfig{
			Enable: true,
			Trunks: []uint16{100, 200, 5000}, // 5000 is invalid
		},
	}

	err := ValidateOVSConfig(config)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidOVSConfig)
}

func TestValidateOVSConfig_InvalidVLANMode(t *testing.T) {
	config := &Config{
		OVS: &OVSConfig{
			Enable:   true,
			VLANMode: "invalid-mode",
		},
	}

	err := ValidateOVSConfig(config)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidOVSConfig)
}

func TestValidateOVSConfig_ValidVLANModes(t *testing.T) {
	validModes := []string{"access", "trunk", "native-tagged"}

	for _, mode := range validModes {
		t.Run(mode, func(t *testing.T) {
			config := &Config{
				OVS: &OVSConfig{
					Enable:   true,
					VLANMode: mode,
				},
			}

			err := ValidateOVSConfig(config)
			assert.NoError(t, err)
		})
	}
}

func TestValidateOVSConfig_InvalidQoSMaxRate(t *testing.T) {
	config := &Config{
		OVS: &OVSConfig{
			Enable: true,
			QoS: &OVSQoSConfig{
				MaxRate: -100,
			},
		},
	}

	err := ValidateOVSConfig(config)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidOVSConfig)
}

func TestValidateOVSConfig_InvalidQoSMinRate(t *testing.T) {
	config := &Config{
		OVS: &OVSConfig{
			Enable: true,
			QoS: &OVSQoSConfig{
				MinRate: -100,
			},
		},
	}

	err := ValidateOVSConfig(config)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidOVSConfig)
}

func TestValidateOVSConfig_InvalidQoSBurst(t *testing.T) {
	config := &Config{
		OVS: &OVSConfig{
			Enable: true,
			QoS: &OVSQoSConfig{
				Burst: -100,
			},
		},
	}

	err := ValidateOVSConfig(config)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidOVSConfig)
}

func TestValidateOVSConfig_InvalidQoSPriority(t *testing.T) {
	tests := []struct {
		name     string
		priority int
		wantErr  bool
	}{
		{"negative", -1, true},
		{"zero", 0, false},
		{"valid", 5, false},
		{"max_valid", 7, false},
		{"too_high", 8, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				OVS: &OVSConfig{
					Enable: true,
					QoS: &OVSQoSConfig{
						Priority: tt.priority,
					},
				},
			}

			err := ValidateOVSConfig(config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidOVSConfig)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateOVSConfig_ValidQoS(t *testing.T) {
	config := &Config{
		OVS: &OVSConfig{
			Enable: true,
			QoS: &OVSQoSConfig{
				MaxRate:  1000000000, // 1 Gbps
				MinRate:  100000000,  // 100 Mbps
				Burst:    1000000,    // 1 MB
				Priority: 5,
			},
		},
	}

	err := ValidateOVSConfig(config)
	assert.NoError(t, err)
}

func TestOVSNetwork_GenerateTAPName_WithPortName(t *testing.T) {
	n := &OVSNetwork{
		config: &Config{
			OVS: &OVSConfig{
				Enable:   true,
				PortName: "my-custom-tap",
			},
		},
	}

	name := n.generateTAPName()
	assert.Equal(t, "my-custom-tap", name)
}

func TestOVSNetwork_GenerateTAPName_AutoGenerated(t *testing.T) {
	n := &OVSNetwork{
		config: &Config{
			OVS: &OVSConfig{
				Enable: true,
			},
		},
	}

	name := n.generateTAPName()
	assert.Regexp(t, `^qemu-[0-9a-f]{8}$`, name)
	assert.True(t, len(name) <= 15) // TAP names must be <= 15 chars

	// Back-to-back names must differ; the old timestamp suffix could not
	// guarantee that.
	seen := map[string]bool{name: true}
	for i := 0; i < 100; i++ {
		next := n.generateTAPName()
		assert.False(t, seen[next], "duplicate TAP name %q", next)
		seen[next] = true
	}
}

func TestOVSNetwork_GetTAPName_Empty(t *testing.T) {
	n := &OVSNetwork{
		config: &Config{
			OVS: &OVSConfig{
				Enable: true,
			},
		},
	}

	// Before setup, should be empty
	assert.Equal(t, "", n.GetTAPName())
}

func TestOVSNetwork_GetOwnership(t *testing.T) {
	n := &OVSNetwork{
		config: &Config{
			OVS: &OVSConfig{
				Enable: true,
			},
		},
	}

	uid, gid := n.getOwnership()
	// Verify getOwnership returns valid values (any uint32 is valid)
	_ = uid
	_ = gid
}

func TestOVSNetwork_Close_NilClient(t *testing.T) {
	n := &OVSNetwork{
		config: &Config{
			OVS: &OVSConfig{
				Enable: true,
			},
		},
		ovsClient: nil,
	}

	err := n.Close()
	assert.NoError(t, err)
}

func TestOVSNetwork_Cleanup_EmptyTAPName(t *testing.T) {
	n := &OVSNetwork{
		config: &Config{
			OVS: &OVSConfig{
				Enable:     true,
				BridgeName: "test-br",
			},
		},
		tapName: "",
	}

	// Cleanup should be no-op when tapName is empty
	err := n.Cleanup(context.TODO())
	assert.NoError(t, err)
}

func TestOVSConfigIntegration(t *testing.T) {
	// Test that OVS config integrates properly with main Config
	config := DefaultConfig()
	require.NotNil(t, config)

	// Enable OVS
	config.OVS = &OVSConfig{
		Enable:     true,
		BridgeName: "br-int",
		SocketPath: "/var/run/openvswitch/db.sock",
		VLAN:       100,
		VLANMode:   "access",
		ExternalIDs: map[string]string{
			"vm-name": "test-vm",
		},
	}

	// Verify OVS is enabled
	assert.True(t, config.OVSEnabled())
	assert.Equal(t, "br-int", config.GetOVSBridgeName())
	assert.Equal(t, "/var/run/openvswitch/db.sock", config.GetOVSSocketPath())

	// Validate
	err := ValidateOVSConfig(config)
	assert.NoError(t, err)
}

func TestOVSConfigDefaults(t *testing.T) {
	config := &Config{
		OVS: &OVSConfig{
			Enable: true,
			// Leave other fields empty to test defaults
		},
	}

	// Should use default bridge name
	assert.Equal(t, DefaultBridgeName, config.GetOVSBridgeName())

	// Should use default socket path
	assert.Equal(t, DefaultOVSSocketPath, config.GetOVSSocketPath())
}

func TestVLANBoundaryValues(t *testing.T) {
	tests := []struct {
		name    string
		vlan    uint16
		wantErr bool
	}{
		{"zero", 0, false},
		{"one", 1, false},
		{"max_valid", 4094, false},
		{"just_over_max", 4095, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				OVS: &OVSConfig{
					Enable: true,
					VLAN:   tt.vlan,
				},
			}

			err := ValidateOVSConfig(config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
