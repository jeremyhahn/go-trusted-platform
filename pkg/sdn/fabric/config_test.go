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

package fabric

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

func validFabricConfig() *FabricConfig {
	return &FabricConfig{
		Switches: []SwitchConfig{
			{ID: "sw-01", Vendor: "mock", MgmtIP: "192.0.2.10"},
			{ID: "sw-02", Vendor: "mock", MgmtIP: "192.0.2.11"},
		},
		Peers: []PeerConfig{
			{SwitchA: "sw-01", SwitchB: "sw-02", PeerLinkPorts: []string{"Ethernet1/49"}},
		},
		LAGs: []LAGConfig{
			{ID: "gw", PortChannelID: 103, Members: []PortRef{{SwitchID: "sw-01", Port: "Ethernet1/3"}}},
		},
		Ports: []PortAssignment{
			{PortRef: PortRef{SwitchID: "sw-01", Port: "Ethernet1/3"}, Class: zone.PortClassGateway},
			{PortRef: PortRef{SwitchID: "sw-01", Port: "Ethernet1/25"}, Class: zone.PortClassHypervisor},
			{PortRef: PortRef{SwitchID: "sw-02", Port: "Ethernet1/41"}, Class: zone.PortClassBMC},
		},
	}
}

// TestFabricConfig_Validate_Valid accepts a fabric with peers, a LAG and a
// port of each common class.
func TestFabricConfig_Validate_Valid(t *testing.T) {
	require.NoError(t, validFabricConfig().Validate())
}

// TestFabricConfig_Validate_Errors refuses every malformed field.
func TestFabricConfig_Validate_Errors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c *FabricConfig)
		check  func(t *testing.T, err error)
	}{
		{"no switches", func(c *FabricConfig) { c.Switches = nil }, invalidReason("at least one switch")},
		{"duplicate switch", func(c *FabricConfig) { c.Switches[1].ID = "sw-01"; c.Peers = nil }, invalidReason("duplicate switch id")},
		{"bad switch", func(c *FabricConfig) { c.Switches[0].Vendor = "" }, invalidReason("vendor")},
		{"bad peer", func(c *FabricConfig) { c.Peers[0].PeerLinkPorts = nil }, invalidReason("peer-link")},
		{"bad lag", func(c *FabricConfig) { c.LAGs[0].PortChannelID = 0 }, invalidReason("port-channel-id")},
		{"port without switch id", func(c *FabricConfig) { c.Ports[0].SwitchID = "" }, func(t *testing.T, err error) {
			var target ErrInvalidPortRef
			require.True(t, errors.As(err, &target), "got %v", err)
		}},
		{"port on unknown switch", func(c *FabricConfig) { c.Ports[0].SwitchID = "sw-09" }, func(t *testing.T, err error) {
			var target ErrUnknownSwitch
			require.True(t, errors.As(err, &target), "got %v", err)
			assert.Equal(t, "sw-09", target.ID)
		}},
		{"unknown class", func(c *FabricConfig) { c.Ports[0].Class = "uplink" }, func(t *testing.T, err error) {
			var target ErrUnknownPortClass
			require.True(t, errors.As(err, &target), "got %v", err)
			assert.Equal(t, zone.PortClass("uplink"), target.Class)
		}},
		{"port assigned twice", func(c *FabricConfig) {
			c.Ports = append(c.Ports, PortAssignment{PortRef: c.Ports[1].PortRef, Class: zone.PortClassGateway})
		}, func(t *testing.T, err error) {
			var target ErrDuplicatePort
			require.True(t, errors.As(err, &target), "got %v", err)
			assert.Equal(t, "Ethernet1/25", target.Port)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validFabricConfig()
			tc.mutate(c)
			err := c.Validate()
			require.Error(t, err)
			tc.check(t, err)
		})
	}

	var nilCfg *FabricConfig
	var target ErrNilConfig
	require.True(t, errors.As(nilCfg.Validate(), &target))
}

func invalidReason(want string) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		t.Helper()
		var target ErrInvalidFabricConfig
		require.True(t, errors.As(err, &target), "got %v", err)
		assert.Contains(t, target.Reason, want)
	}
}

// TestFabricConfig_YAML decodes the sdn.fabric form, with the port ref
// inlined into each port assignment.
func TestFabricConfig_YAML(t *testing.T) {
	const doc = `
switches:
  - {id: sw-01, vendor: cisco-nexus, mgmt-ip: 192.0.2.10}
ports:
  - {switch-id: sw-01, port: Ethernet1/25, class: hypervisor, description: cp-01}
  - {switch-id: sw-01, port: Ethernet1/41, class: bmc}
`
	var c FabricConfig
	require.NoError(t, yaml.Unmarshal([]byte(doc), &c))
	require.NoError(t, c.Validate())
	require.Len(t, c.Ports, 2)
	assert.Equal(t, "sw-01", c.Ports[0].SwitchID)
	assert.Equal(t, "Ethernet1/25", c.Ports[0].Port)
	assert.Equal(t, zone.PortClassHypervisor, c.Ports[0].Class)
	assert.Equal(t, "cp-01", c.Ports[0].Description)
}

// TestSwitchConfig_Validate covers the required switch fields.
func TestSwitchConfig_Validate(t *testing.T) {
	require.NoError(t, (&SwitchConfig{ID: "a", Vendor: "v", MgmtIP: "192.0.2.1"}).Validate())
	for _, c := range []SwitchConfig{
		{Vendor: "v", MgmtIP: "192.0.2.1"},
		{ID: "a", MgmtIP: "192.0.2.1"},
		{ID: "a", Vendor: "v"},
	} {
		var target ErrInvalidFabricConfig
		require.True(t, errors.As(c.Validate(), &target), "%+v", c)
	}
}

// TestPeerConfig_Validate covers known/unknown switches and peer-link ports.
func TestPeerConfig_Validate(t *testing.T) {
	ids := map[string]struct{}{"a": {}, "b": {}}
	require.NoError(t, (&PeerConfig{SwitchA: "a", SwitchB: "b", PeerLinkPorts: []string{"E1/49"}}).Validate(ids))

	var invalid ErrInvalidFabricConfig
	require.True(t, errors.As((&PeerConfig{SwitchB: "b"}).Validate(ids), &invalid))
	var unknown ErrUnknownSwitch
	require.True(t, errors.As((&PeerConfig{SwitchA: "x", SwitchB: "b"}).Validate(ids), &unknown))
	require.True(t, errors.As((&PeerConfig{SwitchA: "a", SwitchB: "x"}).Validate(ids), &unknown))
	require.True(t, errors.As((&PeerConfig{SwitchA: "a", SwitchB: "b"}).Validate(ids), &invalid))
}

// TestLAGConfig_Validate covers the required LAG fields.
func TestLAGConfig_Validate(t *testing.T) {
	ok := LAGConfig{ID: "l", PortChannelID: 1, Members: []PortRef{{SwitchID: "a", Port: "p"}}}
	require.NoError(t, ok.Validate())
	for _, c := range []LAGConfig{
		{PortChannelID: 1, Members: ok.Members},
		{ID: "l", PortChannelID: 1},
		{ID: "l", Members: ok.Members},
	} {
		var target ErrInvalidFabricConfig
		require.True(t, errors.As(c.Validate(), &target), "%+v", c)
	}
}

// TestPortRef_Validate covers the required port reference fields.
func TestPortRef_Validate(t *testing.T) {
	require.NoError(t, PortRef{SwitchID: "a", Port: "p"}.Validate())
	var target ErrInvalidPortRef
	require.True(t, errors.As(PortRef{Port: "p"}.Validate(), &target))
	require.True(t, errors.As(PortRef{SwitchID: "a"}.Validate(), &target))
}
