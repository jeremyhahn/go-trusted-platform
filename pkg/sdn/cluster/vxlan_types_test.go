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

package cluster

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestVTEPStatus_String(t *testing.T) {
	tests := []struct {
		name     string
		status   VTEPStatus
		expected string
	}{
		{
			name:     "unknown status",
			status:   VTEPStatusUnknown,
			expected: "unknown",
		},
		{
			name:     "active status",
			status:   VTEPStatusActive,
			expected: "active",
		},
		{
			name:     "degraded status",
			status:   VTEPStatusDegraded,
			expected: "degraded",
		},
		{
			name:     "down status",
			status:   VTEPStatusDown,
			expected: "down",
		},
		{
			name:     "invalid status defaults to unknown",
			status:   VTEPStatus(99),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.status.String()
			assert.Equal(t, tt.expected, result)
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
			name:     "invalid status defaults to unknown",
			status:   TunnelStatus(99),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.status.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVTEPState_EntityID(t *testing.T) {
	vtep := &VTEPState{
		ID:     "vtep-123",
		IP:     netip.MustParseAddr("10.0.0.1"),
		NodeID: 1,
	}

	entityID := vtep.EntityID()
	assert.NotEqual(t, uint64(0), entityID)

	// Verify consistency
	entityID2 := vtep.EntityID()
	assert.Equal(t, entityID, entityID2)
}

func TestVTEPState_SetEntityID(t *testing.T) {
	vtep := &VTEPState{
		ID:     "vtep-123",
		IP:     netip.MustParseAddr("10.0.0.1"),
		NodeID: 1,
	}

	originalID := vtep.EntityID()
	vtep.SetEntityID(999)

	// SetEntityID is a no-op
	assert.Equal(t, originalID, vtep.EntityID())
}

func TestVTEPState_DifferentIDsProduceDifferentEntityIDs(t *testing.T) {
	vtep1 := &VTEPState{ID: "vtep-1"}
	vtep2 := &VTEPState{ID: "vtep-2"}

	assert.NotEqual(t, vtep1.EntityID(), vtep2.EntityID())
}

func TestTunnelState_EntityID(t *testing.T) {
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		VNI:        100,
	}

	entityID := tunnel.EntityID()
	assert.NotEqual(t, uint64(0), entityID)

	// Verify consistency
	entityID2 := tunnel.EntityID()
	assert.Equal(t, entityID, entityID2)
}

func TestTunnelState_SetEntityID(t *testing.T) {
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
	}

	originalID := tunnel.EntityID()
	tunnel.SetEntityID(999)

	// SetEntityID is a no-op
	assert.Equal(t, originalID, tunnel.EntityID())
}

func TestVNIMappingState_EntityID(t *testing.T) {
	mapping := &VNIMappingState{
		VNI:      100,
		VLAN:     10,
		BridgeID: "br-test",
	}

	// VNI is used directly as EntityID
	entityID := mapping.EntityID()
	assert.Equal(t, uint64(100), entityID)
}

func TestVNIMappingState_SetEntityID(t *testing.T) {
	mapping := &VNIMappingState{
		VNI:  100,
		VLAN: 10,
	}

	originalID := mapping.EntityID()
	mapping.SetEntityID(999)

	// SetEntityID is a no-op
	assert.Equal(t, originalID, mapping.EntityID())
}

func TestRemoteMACState_EntityID(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	entry := &RemoteMACState{
		ID:         "mac-123",
		MAC:        mac,
		VNI:        100,
		RemoteVTEP: "vtep-1",
	}

	entityID := entry.EntityID()
	assert.NotEqual(t, uint64(0), entityID)

	// Verify consistency
	entityID2 := entry.EntityID()
	assert.Equal(t, entityID, entityID2)
}

func TestRemoteMACState_SetEntityID(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	entry := &RemoteMACState{
		ID:  "mac-123",
		MAC: mac,
		VNI: 100,
	}

	originalID := entry.EntityID()
	entry.SetEntityID(999)

	// SetEntityID is a no-op
	assert.Equal(t, originalID, entry.EntityID())
}

func TestRemoteMACState_IsExpired(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "zero expiration never expires",
			expiresAt: time.Time{},
			expected:  false,
		},
		{
			name:      "future expiration not expired",
			expiresAt: time.Now().Add(1 * time.Hour),
			expected:  false,
		},
		{
			name:      "past expiration is expired",
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &RemoteMACState{
				ID:        "mac-123",
				MAC:       mac,
				VNI:       100,
				ExpiresAt: tt.expiresAt,
			}
			assert.Equal(t, tt.expected, entry.IsExpired())
		})
	}
}

func TestMACLearnSource_Constants(t *testing.T) {
	assert.Equal(t, MACLearnSource("evpn"), MACLearnSourceEVPN)
	assert.Equal(t, MACLearnSource("dataplane"), MACLearnSourceDataplane)
	assert.Equal(t, MACLearnSource("static"), MACLearnSourceStatic)
}

func TestVTEPState_Fields(t *testing.T) {
	now := time.Now()
	vtep := &VTEPState{
		ID:            "vtep-test",
		NodeID:        1,
		IP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayIface: "eth0",
		UnderlayMTU:   1500,
		VXLANPort:     4789,
		Status:        VTEPStatusActive,
		Tunnels:       []string{"tunnel-1", "tunnel-2"},
		ExternalIDs:   map[string]string{"key": "value"},
		Version:       1,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	assert.Equal(t, "vtep-test", vtep.ID)
	assert.Equal(t, uint64(1), vtep.NodeID)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), vtep.IP)
	assert.Equal(t, "eth0", vtep.UnderlayIface)
	assert.Equal(t, 1500, vtep.UnderlayMTU)
	assert.Equal(t, uint16(4789), vtep.VXLANPort)
	assert.Equal(t, VTEPStatusActive, vtep.Status)
	assert.Len(t, vtep.Tunnels, 2)
	assert.Equal(t, "value", vtep.ExternalIDs["key"])
}

func TestTunnelState_Fields(t *testing.T) {
	now := time.Now()
	tunnel := &TunnelState{
		ID:          "tunnel-test",
		LocalVTEP:   "vtep-1",
		RemoteVTEP:  "vtep-2",
		LocalIP:     netip.MustParseAddr("10.0.0.1"),
		RemoteIP:    netip.MustParseAddr("10.0.0.2"),
		VNI:         100,
		OVSPort:     "vxlan-100",
		OFPort:      10,
		Status:      TunnelStatusUp,
		NodeID:      1,
		ExternalIDs: map[string]string{"key": "value"},
		Stats: TunnelStats{
			BytesSent:   1000,
			BytesRecv:   2000,
			PacketsSent: 10,
			PacketsRecv: 20,
			LastUpdated: now,
		},
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
	}

	assert.Equal(t, "tunnel-test", tunnel.ID)
	assert.Equal(t, "vtep-1", tunnel.LocalVTEP)
	assert.Equal(t, "vtep-2", tunnel.RemoteVTEP)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), tunnel.LocalIP)
	assert.Equal(t, netip.MustParseAddr("10.0.0.2"), tunnel.RemoteIP)
	assert.Equal(t, uint32(100), tunnel.VNI)
	assert.Equal(t, "vxlan-100", tunnel.OVSPort)
	assert.Equal(t, int32(10), tunnel.OFPort)
	assert.Equal(t, TunnelStatusUp, tunnel.Status)
	assert.Equal(t, uint64(1000), tunnel.Stats.BytesSent)
	assert.Equal(t, uint64(2000), tunnel.Stats.BytesRecv)
}

func TestVNIMappingState_Fields(t *testing.T) {
	now := time.Now()
	mapping := &VNIMappingState{
		VNI:         100,
		VLAN:        10,
		BridgeID:    "br-test",
		TenantID:    "tenant-1",
		Description: "Test mapping",
		ExternalIDs: map[string]string{"key": "value"},
		Version:     1,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	assert.Equal(t, uint32(100), mapping.VNI)
	assert.Equal(t, uint16(10), mapping.VLAN)
	assert.Equal(t, "br-test", mapping.BridgeID)
	assert.Equal(t, "tenant-1", mapping.TenantID)
	assert.Equal(t, "Test mapping", mapping.Description)
	assert.Equal(t, "value", mapping.ExternalIDs["key"])
}

func TestRemoteMACState_Fields(t *testing.T) {
	now := time.Now()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	entry := &RemoteMACState{
		ID:          "mac-test",
		MAC:         mac,
		VNI:         100,
		RemoteVTEP:  "vtep-1",
		RemoteIP:    netip.MustParseAddr("10.0.0.1"),
		LearnedFrom: MACLearnSourceEVPN,
		NodeID:      1,
		ExternalIDs: map[string]string{"key": "value"},
		Version:     1,
		LearnedAt:   now,
		ExpiresAt:   now.Add(1 * time.Hour),
	}

	assert.Equal(t, "mac-test", entry.ID)
	assert.Equal(t, "00:11:22:33:44:55", entry.MAC.String())
	assert.Equal(t, uint32(100), entry.VNI)
	assert.Equal(t, "vtep-1", entry.RemoteVTEP)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), entry.RemoteIP)
	assert.Equal(t, MACLearnSourceEVPN, entry.LearnedFrom)
	assert.Equal(t, uint64(1), entry.NodeID)
	assert.Equal(t, "value", entry.ExternalIDs["key"])
}
