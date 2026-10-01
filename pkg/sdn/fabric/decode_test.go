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

package fabric_test

import (
	"bytes"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// fabricYAML is the sdn.fabric form the shipped templates use.
const fabricYAML = `
switches:
  - id: sw-01
    vendor: cisco-nexus
    model: N9K-C93180YC-EX
    mgmt-ip: 192.0.2.10
    credentials-ref: "kms://switches/sw-01"
  - id: sw-02
    vendor: cisco-nexus
    mgmt-ip: 192.0.2.11
peers:
  - switch-a: sw-01
    switch-b: sw-02
    peer-link-ports: [Ethernet1/50, Ethernet1/52]
ports:
  - {switch-id: sw-01, port: Ethernet1/3, class: gateway, description: gw-01}
  - {switch-id: sw-01, port: Ethernet1/25, class: hypervisor, description: cp-01}
  - {switch-id: sw-02, port: Ethernet1/41, class: bmc}
`

// checkFabric asserts what both decode paths must produce.
func checkFabric(t *testing.T, c *fabric.FabricConfig) {
	t.Helper()
	require.NoError(t, c.Validate())
	require.Len(t, c.Switches, 2)
	assert.Equal(t, "kms://switches/sw-01", c.Switches[0].CredentialsRef)
	require.Len(t, c.Peers, 1)
	assert.Equal(t, []string{"Ethernet1/50", "Ethernet1/52"}, c.Peers[0].PeerLinkPorts)
	require.Len(t, c.Ports, 3)
	assert.Equal(t, fabric.PortRef{SwitchID: "sw-01", Port: "Ethernet1/25"}, c.Ports[1].PortRef)
	assert.Equal(t, zone.PortClassHypervisor, c.Ports[1].Class)
	assert.Equal(t, "cp-01", c.Ports[1].Description)
	assert.Equal(t, zone.PortClassBMC, c.Ports[2].Class)
}

// TestFabricConfig_DecodePaths decodes the template form through yaml.v3
// (gatewayd, bootstrap) and through viper with the platform decode hook
// (platformd), and both must inline the port reference.
func TestFabricConfig_DecodePaths(t *testing.T) {
	var direct fabric.FabricConfig
	require.NoError(t, yaml.Unmarshal([]byte(fabricYAML), &direct))
	checkFabric(t, &direct)

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(fabricYAML)))
	var viaViper fabric.FabricConfig
	require.NoError(t, v.Unmarshal(&viaViper, config.DecodeHook()))
	checkFabric(t, &viaViper)
}

// TestFabricConfig_DecodeUnknownClass decodes a bad class through viper and
// lets Validate refuse it.
func TestFabricConfig_DecodeUnknownClass(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(`
switches: [{id: sw-01, vendor: cisco-nexus, mgmt-ip: 192.0.2.10}]
ports: [{switch-id: sw-01, port: Ethernet1/1, class: uplink}]
`)))
	var c fabric.FabricConfig
	require.NoError(t, v.Unmarshal(&c, config.DecodeHook()))
	var target fabric.ErrUnknownPortClass
	require.ErrorAs(t, c.Validate(), &target)
}
