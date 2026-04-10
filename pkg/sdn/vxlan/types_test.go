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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				UnderlayMTU:   9000,
				VXLANPort:     DefaultVXLANPort,
			},
			expectError: nil,
		},
		{
			name: "invalid IP - unspecified",
			config: VTEPConfig{
				LocalIP:       netip.Addr{},
				UnderlayIface: "eth0",
				UnderlayMTU:   9000,
				VXLANPort:     DefaultVXLANPort,
			},
			expectError: ErrInvalidVTEPIP,
		},
		{
			name: "invalid IP - zero address",
			config: VTEPConfig{
				LocalIP:       netip.MustParseAddr("0.0.0.0"),
				UnderlayIface: "eth0",
				UnderlayMTU:   9000,
				VXLANPort:     DefaultVXLANPort,
			},
			expectError: ErrInvalidVTEPIP,
		},
		{
			name: "empty underlay interface",
			config: VTEPConfig{
				LocalIP:       validIP,
				UnderlayIface: "",
				UnderlayMTU:   9000,
				VXLANPort:     DefaultVXLANPort,
			},
			expectError: ErrUnderlayNotReady,
		},
		{
			name: "MTU too small",
			config: VTEPConfig{
				LocalIP:       validIP,
				UnderlayIface: "eth0",
				UnderlayMTU:   1500,
				VXLANPort:     DefaultVXLANPort,
			},
			expectError: ErrMTUTooSmall,
		},
		{
			name: "zero VXLAN port",
			config: VTEPConfig{
				LocalIP:       validIP,
				UnderlayIface: "eth0",
				UnderlayMTU:   9000,
				VXLANPort:     0,
			},
			expectError: ErrInvalidVXLANPort,
		},
		{
			name: "minimum valid MTU",
			config: VTEPConfig{
				LocalIP:       validIP,
				UnderlayIface: "eth0",
				UnderlayMTU:   MinimumMTU,
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

func TestVTEPConfig_EffectiveMTU(t *testing.T) {
	tests := []struct {
		name        string
		underlayMTU int
		expectedMTU int
	}{
		{
			name:        "jumbo frames",
			underlayMTU: 9000,
			expectedMTU: 9000 - VXLANOverhead,
		},
		{
			name:        "standard MTU",
			underlayMTU: 1550,
			expectedMTU: 1550 - VXLANOverhead,
		},
		{
			name:        "large jumbo",
			underlayMTU: 16000,
			expectedMTU: 16000 - VXLANOverhead,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := VTEPConfig{
				UnderlayMTU: tc.underlayMTU,
			}
			assert.Equal(t, tc.expectedMTU, config.EffectiveMTU())
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

func TestRemoteMACEntry_IsExpired(t *testing.T) {
	mac, err := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)

	tests := []struct {
		name          string
		expiresAt     time.Time
		expectExpired bool
	}{
		{
			name:          "not expired - future",
			expiresAt:     time.Now().Add(time.Hour),
			expectExpired: false,
		},
		{
			name:          "expired - past",
			expiresAt:     time.Now().Add(-time.Hour),
			expectExpired: true,
		},
		{
			name:          "just expired",
			expiresAt:     time.Now().Add(-time.Second),
			expectExpired: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := RemoteMACEntry{
				MAC:        mac,
				VNI:        1000100,
				RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
				LearnedAt:  time.Now().Add(-time.Hour),
				ExpiresAt:  tc.expiresAt,
			}
			assert.Equal(t, tc.expectExpired, entry.IsExpired())
		})
	}
}

func TestDefaultVNIMappingConfig(t *testing.T) {
	config := DefaultVNIMappingConfig()

	assert.Equal(t, DefaultBaseVNI, config.BaseVNI)
	assert.Equal(t, uint16(4094), config.MaxVLAN)
}

func TestVXLANPortConfig_Options(t *testing.T) {
	t.Run("valid configuration with all options", func(t *testing.T) {
		config := VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("10.0.0.2"),
			VNI:      1000100,
			DstPort:  4789,
			TOS:      0,
			TTL:      64,
			DF:       true,
		}

		opts := config.Options()

		assert.Contains(t, opts, "remote_ip")
		assert.Equal(t, "10.0.0.2", opts["remote_ip"])
		assert.Contains(t, opts, "key")
		assert.Contains(t, opts, "df_default")
		assert.Equal(t, "true", opts["df_default"])
	})

	t.Run("flow-based VNI when VNI is zero", func(t *testing.T) {
		config := VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("10.0.0.2"),
			VNI:      0,
		}

		opts := config.Options()

		assert.Equal(t, "flow", opts["key"])
	})

	t.Run("invalid remote IP", func(t *testing.T) {
		config := VXLANPortConfig{
			RemoteIP: netip.Addr{},
			VNI:      1000100,
		}

		opts := config.Options()

		assert.NotContains(t, opts, "remote_ip")
	})
}

func TestConstants(t *testing.T) {
	t.Run("VNI constants", func(t *testing.T) {
		assert.Equal(t, VNI(1), MinVNI)
		assert.Equal(t, VNI(16777215), MaxVNI)
		assert.Equal(t, VNI(1000000), DefaultBaseVNI)
	})

	t.Run("VXLAN constants", func(t *testing.T) {
		assert.Equal(t, uint16(4789), DefaultVXLANPort)
		assert.Equal(t, 1550, MinimumMTU)
		assert.Equal(t, 50, VXLANOverhead)
	})
}

func TestTunnelState_Fields(t *testing.T) {
	now := time.Now()
	localVTEP := netip.MustParseAddr("10.0.0.1")
	remoteVTEP := netip.MustParseAddr("10.0.0.2")

	tunnel := TunnelState{
		ID:         "10.0.0.1-10.0.0.2-1000100",
		LocalVTEP:  localVTEP,
		RemoteVTEP: remoteVTEP,
		VNI:        1000100,
		OVSPort:    "vxlan-abc123",
		OFPort:     10,
		State:      TunnelStatusUp,
		CreatedAt:  now,
		UpdatedAt:  now,
		BytesSent:  1000,
		BytesRecv:  2000,
	}

	assert.Equal(t, "10.0.0.1-10.0.0.2-1000100", tunnel.ID)
	assert.Equal(t, localVTEP, tunnel.LocalVTEP)
	assert.Equal(t, remoteVTEP, tunnel.RemoteVTEP)
	assert.Equal(t, VNI(1000100), tunnel.VNI)
	assert.Equal(t, "vxlan-abc123", tunnel.OVSPort)
	assert.Equal(t, int32(10), tunnel.OFPort)
	assert.Equal(t, TunnelStatusUp, tunnel.State)
	assert.Equal(t, now, tunnel.CreatedAt)
	assert.Equal(t, now, tunnel.UpdatedAt)
	assert.Equal(t, uint64(1000), tunnel.BytesSent)
	assert.Equal(t, uint64(2000), tunnel.BytesRecv)
}

func TestTunnelStats_Fields(t *testing.T) {
	stats := TunnelStats{
		BytesSent:   1000,
		BytesRecv:   2000,
		PacketsSent: 100,
		PacketsRecv: 200,
		ErrorsSent:  5,
		ErrorsRecv:  10,
	}

	assert.Equal(t, uint64(1000), stats.BytesSent)
	assert.Equal(t, uint64(2000), stats.BytesRecv)
	assert.Equal(t, uint64(100), stats.PacketsSent)
	assert.Equal(t, uint64(200), stats.PacketsRecv)
	assert.Equal(t, uint64(5), stats.ErrorsSent)
	assert.Equal(t, uint64(10), stats.ErrorsRecv)
}

func TestVNIMappingConfig_Fields(t *testing.T) {
	config := VNIMappingConfig{
		BaseVNI: 2000000,
		MaxVLAN: 1000,
	}

	assert.Equal(t, VNI(2000000), config.BaseVNI)
	assert.Equal(t, uint16(1000), config.MaxVLAN)
}
