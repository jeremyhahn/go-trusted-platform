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
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Partition constant tests
// ---------------------------------------------------------------------------

func TestGatewayPartitionConstants(t *testing.T) {
	// Data-plane partitions (highperf SM).
	assert.Equal(t, "gw/conntrack", PartitionGatewayConnTrack)
	assert.Equal(t, "gw/nat/sessions", PartitionGatewayNATSessions)

	// Control-plane partitions (durable SM).
	assert.Equal(t, "gw/vips", PartitionGatewayVIPs)
	assert.Equal(t, "gw/firewall/rules", PartitionGatewayFirewallRules)
	assert.Equal(t, "gw/bgp/routes", PartitionGatewayBGPRoutes)
}

func TestGatewayPartitionConstants_Uniqueness(t *testing.T) {
	partitions := []string{
		PartitionGatewayConnTrack,
		PartitionGatewayNATSessions,
		PartitionGatewayVIPs,
		PartitionGatewayFirewallRules,
		PartitionGatewayBGPRoutes,
	}

	seen := make(map[string]struct{})
	for _, p := range partitions {
		_, exists := seen[p]
		assert.False(t, exists, "duplicate partition: %s", p)
		seen[p] = struct{}{}
	}
}

// ---------------------------------------------------------------------------
// VIPEntry tests
// ---------------------------------------------------------------------------

func TestVIPEntry_Serialization(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	entry := &VIPEntry{
		Address:   "23.143.36.1/24",
		OwnerNode: "lab-node-1",
		Priority:  100,
		LastSeen:  now,
		Active:    true,
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var decoded VIPEntry
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, entry.Address, decoded.Address)
	assert.Equal(t, entry.OwnerNode, decoded.OwnerNode)
	assert.Equal(t, entry.Priority, decoded.Priority)
	assert.True(t, entry.LastSeen.Equal(decoded.LastSeen))
	assert.Equal(t, entry.Active, decoded.Active)
}

func TestVIPEntry_EntityID(t *testing.T) {
	v1 := &VIPEntry{Address: "23.143.36.1/24"}
	v2 := &VIPEntry{Address: "23.143.36.1/24"}
	v3 := &VIPEntry{Address: "10.0.0.1/32"}

	// Same address produces same ID.
	assert.Equal(t, v1.EntityID(), v2.EntityID())

	// Different address produces different ID.
	assert.NotEqual(t, v1.EntityID(), v3.EntityID())
}

func TestVIPEntry_SetEntityID(t *testing.T) {
	v := &VIPEntry{Address: "192.168.1.1/24"}
	original := v.EntityID()

	// SetEntityID is a no-op.
	v.SetEntityID(99999)
	assert.Equal(t, original, v.EntityID())
}

func TestVIPEntry_JSONFields(t *testing.T) {
	entry := &VIPEntry{
		Address:   "10.0.0.1/32",
		OwnerNode: "node-1",
		Priority:  50,
		LastSeen:  time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC),
		Active:    false,
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	// Verify JSON field names.
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Contains(t, raw, "address")
	assert.Contains(t, raw, "owner_node")
	assert.Contains(t, raw, "priority")
	assert.Contains(t, raw, "last_seen")
	assert.Contains(t, raw, "active")
}

// ---------------------------------------------------------------------------
// ConnTrackEntry tests
// ---------------------------------------------------------------------------

func TestConnTrackEntry_Serialization(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	entry := &ConnTrackEntry{
		ID:          "ct-12345",
		Protocol:    6,
		SrcAddr:     "192.168.1.100",
		DstAddr:     "10.0.0.1",
		SrcPort:     54321,
		DstPort:     443,
		State:       "ESTABLISHED",
		CreatedAt:   now.Add(-5 * time.Minute),
		LastSeen:    now,
		BytesSent:   1048576,
		BytesRecv:   2097152,
		PacketsSent: 1024,
		PacketsRecv: 2048,
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var decoded ConnTrackEntry
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, entry.ID, decoded.ID)
	assert.Equal(t, entry.Protocol, decoded.Protocol)
	assert.Equal(t, entry.SrcAddr, decoded.SrcAddr)
	assert.Equal(t, entry.DstAddr, decoded.DstAddr)
	assert.Equal(t, entry.SrcPort, decoded.SrcPort)
	assert.Equal(t, entry.DstPort, decoded.DstPort)
	assert.Equal(t, entry.State, decoded.State)
	assert.Equal(t, entry.BytesSent, decoded.BytesSent)
	assert.Equal(t, entry.BytesRecv, decoded.BytesRecv)
	assert.Equal(t, entry.PacketsSent, decoded.PacketsSent)
	assert.Equal(t, entry.PacketsRecv, decoded.PacketsRecv)
}

func TestConnTrackEntry_EntityID(t *testing.T) {
	c1 := &ConnTrackEntry{ID: "ct-1"}
	c2 := &ConnTrackEntry{ID: "ct-1"}
	c3 := &ConnTrackEntry{ID: "ct-2"}

	assert.Equal(t, c1.EntityID(), c2.EntityID())
	assert.NotEqual(t, c1.EntityID(), c3.EntityID())
}

func TestConnTrackEntry_SetEntityID(t *testing.T) {
	c := &ConnTrackEntry{ID: "ct-1"}
	original := c.EntityID()
	c.SetEntityID(99999)
	assert.Equal(t, original, c.EntityID())
}

// ---------------------------------------------------------------------------
// NATSessionEntry tests
// ---------------------------------------------------------------------------

func TestNATSessionEntry_Serialization(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	entry := &NATSessionEntry{
		ID:          "nat-1234",
		ConnTrackID: "ct-1234",
		OrigSrcAddr: "192.168.1.100",
		OrigSrcPort: 54321,
		TransAddr:   "23.143.36.1",
		TransPort:   10001,
		DstAddr:     "8.8.8.8",
		DstPort:     53,
		Protocol:    17,
		CreatedAt:   now,
		ExpiresAt:   now.Add(30 * time.Second),
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var decoded NATSessionEntry
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, entry.ID, decoded.ID)
	assert.Equal(t, entry.ConnTrackID, decoded.ConnTrackID)
	assert.Equal(t, entry.OrigSrcAddr, decoded.OrigSrcAddr)
	assert.Equal(t, entry.OrigSrcPort, decoded.OrigSrcPort)
	assert.Equal(t, entry.TransAddr, decoded.TransAddr)
	assert.Equal(t, entry.TransPort, decoded.TransPort)
	assert.Equal(t, entry.DstAddr, decoded.DstAddr)
	assert.Equal(t, entry.DstPort, decoded.DstPort)
	assert.Equal(t, entry.Protocol, decoded.Protocol)
}

func TestNATSessionEntry_EntityID(t *testing.T) {
	n1 := &NATSessionEntry{ID: "nat-1"}
	n2 := &NATSessionEntry{ID: "nat-1"}
	n3 := &NATSessionEntry{ID: "nat-2"}

	assert.Equal(t, n1.EntityID(), n2.EntityID())
	assert.NotEqual(t, n1.EntityID(), n3.EntityID())
}

func TestNATSessionEntry_SetEntityID(t *testing.T) {
	n := &NATSessionEntry{ID: "nat-1"}
	original := n.EntityID()
	n.SetEntityID(99999)
	assert.Equal(t, original, n.EntityID())
}

// ---------------------------------------------------------------------------
// FirewallRuleEntry tests
// ---------------------------------------------------------------------------

func TestFirewallRuleEntry_Serialization(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	entry := &FirewallRuleEntry{
		ID:           "fw-rule-1",
		Priority:     100,
		Direction:    "inbound",
		Action:       "allow",
		Protocol:     "tcp",
		SrcCIDR:      "0.0.0.0/0",
		DstCIDR:      "23.143.36.0/24",
		DstPortRange: "443",
		Stateful:     true,
		Enabled:      true,
		Description:  "Allow HTTPS inbound",
		Version:      1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var decoded FirewallRuleEntry
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, entry.ID, decoded.ID)
	assert.Equal(t, entry.Priority, decoded.Priority)
	assert.Equal(t, entry.Direction, decoded.Direction)
	assert.Equal(t, entry.Action, decoded.Action)
	assert.Equal(t, entry.Protocol, decoded.Protocol)
	assert.Equal(t, entry.SrcCIDR, decoded.SrcCIDR)
	assert.Equal(t, entry.DstCIDR, decoded.DstCIDR)
	assert.Equal(t, entry.DstPortRange, decoded.DstPortRange)
	assert.Equal(t, entry.Stateful, decoded.Stateful)
	assert.Equal(t, entry.Enabled, decoded.Enabled)
	assert.Equal(t, entry.Description, decoded.Description)
	assert.Equal(t, entry.Version, decoded.Version)
}

func TestFirewallRuleEntry_EntityID(t *testing.T) {
	f1 := &FirewallRuleEntry{ID: "fw-1"}
	f2 := &FirewallRuleEntry{ID: "fw-1"}
	f3 := &FirewallRuleEntry{ID: "fw-2"}

	assert.Equal(t, f1.EntityID(), f2.EntityID())
	assert.NotEqual(t, f1.EntityID(), f3.EntityID())
}

func TestFirewallRuleEntry_SetEntityID(t *testing.T) {
	f := &FirewallRuleEntry{ID: "fw-1"}
	original := f.EntityID()
	f.SetEntityID(99999)
	assert.Equal(t, original, f.EntityID())
}

// ---------------------------------------------------------------------------
// BGPRouteEntry tests
// ---------------------------------------------------------------------------

func TestBGPRouteEntry_Serialization(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	entry := &BGPRouteEntry{
		Prefix:      "23.143.36.0/24",
		NextHop:     "10.255.0.1",
		ASPath:      []uint32{401870, 64515},
		LocalPref:   100,
		MED:         0,
		Origin:      "igp",
		Communities: []string{"401870:100", "401870:200"},
		Active:      true,
		Source:      "local",
		LastUpdated: now,
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var decoded BGPRouteEntry
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, entry.Prefix, decoded.Prefix)
	assert.Equal(t, entry.NextHop, decoded.NextHop)
	assert.Equal(t, entry.ASPath, decoded.ASPath)
	assert.Equal(t, entry.LocalPref, decoded.LocalPref)
	assert.Equal(t, entry.MED, decoded.MED)
	assert.Equal(t, entry.Origin, decoded.Origin)
	assert.Equal(t, entry.Communities, decoded.Communities)
	assert.Equal(t, entry.Active, decoded.Active)
	assert.Equal(t, entry.Source, decoded.Source)
}

func TestBGPRouteEntry_EntityID(t *testing.T) {
	b1 := &BGPRouteEntry{Prefix: "23.143.36.0/24"}
	b2 := &BGPRouteEntry{Prefix: "23.143.36.0/24"}
	b3 := &BGPRouteEntry{Prefix: "10.0.0.0/8"}

	assert.Equal(t, b1.EntityID(), b2.EntityID())
	assert.NotEqual(t, b1.EntityID(), b3.EntityID())
}

func TestBGPRouteEntry_SetEntityID(t *testing.T) {
	b := &BGPRouteEntry{Prefix: "23.143.36.0/24"}
	original := b.EntityID()
	b.SetEntityID(99999)
	assert.Equal(t, original, b.EntityID())
}

func TestBGPRouteEntry_EmptyASPath(t *testing.T) {
	entry := &BGPRouteEntry{
		Prefix:  "10.0.0.0/8",
		NextHop: "0.0.0.0",
		Origin:  "igp",
		Source:  "local",
		Active:  true,
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var decoded BGPRouteEntry
	require.NoError(t, json.Unmarshal(data, &decoded))

	// Empty AS path should be nil after round-trip.
	assert.Nil(t, decoded.ASPath)
}

// ---------------------------------------------------------------------------
// Cross-type entity ID uniqueness
// ---------------------------------------------------------------------------

func TestGatewayEntityID_CrossTypeUniqueness(t *testing.T) {
	ids := make(map[uint64]string)

	entries := map[string]uint64{
		"vip-23.143.36.1/24": (&VIPEntry{Address: "23.143.36.1/24"}).EntityID(),
		"ct-12345":           (&ConnTrackEntry{ID: "ct-12345"}).EntityID(),
		"nat-12345":          (&NATSessionEntry{ID: "nat-12345"}).EntityID(),
		"fw-rule-1":          (&FirewallRuleEntry{ID: "fw-rule-1"}).EntityID(),
		"bgp-23.143.36.0/24": (&BGPRouteEntry{Prefix: "23.143.36.0/24"}).EntityID(),
	}

	for name, id := range entries {
		if existing, found := ids[id]; found {
			t.Errorf("entity ID collision: %s and %s both produce %d", name, existing, id)
		}
		ids[id] = name
	}
}
