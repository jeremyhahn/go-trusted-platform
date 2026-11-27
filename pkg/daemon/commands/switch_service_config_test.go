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

package commands

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
)

// decodeSwitches decodes the `switches:` block of a YAML document with the
// same viper decoder options the daemon uses for its whole config.
func decodeSwitches(t *testing.T, doc string) []switchmgmt.Config {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(doc)))
	var out []switchmgmt.Config
	require.NoError(t, v.UnmarshalKey("switches", &out, config.DecodeHook()))
	return out
}

func TestSwitchConfig_ViperKeepsTheSnakeCaseKeys(t *testing.T) {
	doc := `
switches:
  - name: core-1
    vendor: memory
    ssh_key: /etc/platform/switch.key
    known_hosts_path: /etc/platform/known_hosts
    vlans:
      - id: 10
        name: mgmt
        subnet: 192.0.2.0/24
    ports:
      - port: Eth1/1
        mode: access
        access_vlan: 10
      - port: Eth1/2
        mode: trunk
        vlans: [10, 20]
        native_vlan: 1
        mtu: 9000
`
	cfgs := decodeSwitches(t, doc)
	require.Len(t, cfgs, 1)
	c := cfgs[0]
	assert.Equal(t, "core-1", c.Name)
	assert.Equal(t, switchmgmt.VendorMemory, c.Vendor)
	assert.Equal(t, "/etc/platform/switch.key", c.SSHKey)
	assert.Equal(t, "/etc/platform/known_hosts", c.KnownHostsPath)
	require.Len(t, c.VLANs, 1)
	assert.Equal(t, "192.0.2.0/24", c.VLANs[0].Subnet)
	require.Len(t, c.Ports, 2)
	assert.Equal(t, 10, c.Ports[0].AccessVLAN)
	assert.Equal(t, []int{10, 20}, c.Ports[1].VLANs)
	assert.Equal(t, 1, c.Ports[1].NativeVLAN)
	assert.Equal(t, 9000, c.Ports[1].MTU)
}

func TestRealServerHarness_SwitchesBlockBuildsAMemorySwitch(t *testing.T) {
	raw, err := os.ReadFile("../../../web/e2e/real-server/platformd.test.yaml")
	require.NoError(t, err)
	cfgs := decodeSwitches(t, string(raw))
	require.Len(t, cfgs, 1, "the real-server harness configures one switch")
	require.Equal(t, "harness-1", cfgs[0].Name)
	require.Equal(t, switchmgmt.VendorMemory, cfgs[0].Vendor)

	svc, err := newSwitchService(logging.DefaultLogger(), &app.App{SwitchConfigs: cfgs})
	require.NoError(t, err)
	require.NotNil(t, svc)
	t.Cleanup(func() { _ = svc.Close() })

	mgr, err := svc.Manager("harness-1")
	require.NoError(t, err)
	ports, err := mgr.ListPorts(context.Background())
	require.NoError(t, err)

	want := []*switchwire.PortStatus{
		{Port: "Eth1/1", Mode: switchwire.PortModeAccess, AccessVLAN: 10, Enabled: true, LinkUp: true},
		{Port: "Eth1/2", Mode: switchwire.PortModeAccess, AccessVLAN: 10, Enabled: true, LinkUp: true},
		{Port: "Eth1/3", Mode: switchwire.PortModeAccess, AccessVLAN: 10, Enabled: true, LinkUp: true},
		{Port: "Eth1/4", Mode: switchwire.PortModeAccess, AccessVLAN: 10, Enabled: true, LinkUp: true},
		{Port: "Eth1/5", Mode: switchwire.PortModeTrunk, TrunkVLANs: []uint16{10, 20}, NativeVLAN: 1, Enabled: true, LinkUp: true},
	}
	require.Len(t, ports, len(want))
	for i := range want {
		assert.Equal(t, want[i], ports[i], "port %d", i)
	}
}
