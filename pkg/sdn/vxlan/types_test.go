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

package vxlan

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVNI_Valid(t *testing.T) {
	tests := []struct {
		name     string
		vni      VNI
		expected bool
	}{
		{
			name:     "minimum valid VNI",
			vni:      MinVNI,
			expected: true,
		},
		{
			name:     "maximum valid VNI",
			vni:      MaxVNI,
			expected: true,
		},
		{
			name:     "mid-range VNI",
			vni:      1000100,
			expected: true,
		},
		{
			name:     "zero VNI is invalid",
			vni:      0,
			expected: false,
		},
		{
			name:     "VNI exceeding maximum",
			vni:      MaxVNI + 1,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.vni.Valid()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestVNI_Uint32(t *testing.T) {
	tests := []struct {
		name     string
		vni      VNI
		expected uint32
	}{
		{
			name:     "minimum VNI",
			vni:      MinVNI,
			expected: 1,
		},
		{
			name:     "maximum VNI",
			vni:      MaxVNI,
			expected: 16777215,
		},
		{
			name:     "default base VNI",
			vni:      DefaultBaseVNI,
			expected: 1000000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.vni.Uint32()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestVTEPConfig_Validate(t *testing.T) {
	validIP := netip.MustParseAddr("10.0.0.1")

	tests := []struct {
		name        string
		config      VTEPConfig
		expectError error
	}{
		{
			name: "valid configuration",
			config: VTEPConfig{
				LocalIP:       validIP,
				UnderlayIface: "eth0",
				UnderlayMTU:   9216,
				VXLANPort:     DefaultVXLANPort,
			},
			expectError: nil,
		},
		{
			name: "invalid IP - unspecified",
			config: VTEPConfig{
				LocalIP:       netip.Addr{},
				UnderlayIface: "eth0",
				UnderlayMTU:   9216,
				VXLANPort:     DefaultVXLANPort,
			},
			expectError: ErrInvalidVTEPIP,
		},
		{
			name: "invalid IP - zero address",
			config: VTEPConfig{
				LocalIP:       netip.MustParseAddr("0.0.0.0"),
				UnderlayIface: "eth0",
				UnderlayMTU:   9216,
				VXLANPort:     DefaultVXLANPort,
			},
			expectError: ErrInvalidVTEPIP,
		},
		{
			name: "empty underlay interface",
			config: VTEPConfig{
				LocalIP:       validIP,
				UnderlayIface: "",
				UnderlayMTU:   9216,
				VXLANPort:     DefaultVXLANPort,
			},
			expectError: ErrUnderlayNotReady,
		},
		{
			name: "a 9000-byte underlay cannot carry a 9000-byte overlay",
			config: VTEPConfig{
				LocalIP:       validIP,
				UnderlayIface: "eth0",
				UnderlayMTU:   OverlayMTU,
				VXLANPort:     DefaultVXLANPort,
			},
			expectError: ErrMTUTooSmall,
		},
		{
			name: "zero VXLAN port",
			config: VTEPConfig{
				LocalIP:       validIP,
				UnderlayIface: "eth0",
				UnderlayMTU:   9216,
				VXLANPort:     0,
			},
			expectError: ErrInvalidVXLANPort,
		},
		{
			name: "minimum valid MTU",
			config: VTEPConfig{
				LocalIP:       validIP,
				UnderlayIface: "eth0",
				UnderlayMTU:   MinimumUnderlayMTU,
				VXLANPort:     DefaultVXLANPort,
			},
			expectError: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.expectError != nil {
				assert.ErrorIs(t, err, tc.expectError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTunnelStatus_String(t *testing.T) {
	tests := []struct {
		name     string
		status   TunnelStatus
		expected string
	}{
		{
			name:     "unknown status",
			status:   TunnelStatusUnknown,
			expected: "unknown",
		},
		{
			name:     "up status",
			status:   TunnelStatusUp,
			expected: "up",
		},
		{
			name:     "down status",
			status:   TunnelStatusDown,
			expected: "down",
		},
		{
			name:     "error status",
			status:   TunnelStatusError,
			expected: "error",
		},
		{
			name:     "undefined status value",
			status:   TunnelStatus(99),
			expected: "unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.status.String()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestDefaultVNIMappingConfig(t *testing.T) {
	config := DefaultVNIMappingConfig()

	assert.Equal(t, DefaultBaseVNI, config.BaseVNI)
	assert.Equal(t, uint16(4094), config.MaxVLAN)
}

func TestConstants(t *testing.T) {
	t.Run("VXLAN constants", func(t *testing.T) {
		assert.Equal(t, uint16(4789), DefaultVXLANPort)
		assert.Equal(t, 9000, OverlayMTU)
		assert.Equal(t, 9050, MinimumUnderlayMTU)
		assert.Equal(t, 50, VXLANOverhead)
	})
}

func TestVNIMappingConfig_Fields(t *testing.T) {
	config := VNIMappingConfig{
		BaseVNI: 2000000,
		MaxVLAN: 1000,
	}

	assert.Equal(t, VNI(2000000), config.BaseVNI)
	assert.Equal(t, uint16(1000), config.MaxVLAN)
}
