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

package app

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

const strictGoodPlatform = `
hostname: cp-01
network:
  role: compute
  ip-forward: false
  platform-vrf: {address: 10.4.144.20/32}
  bridges:
    - name: br-fabric
      type: ovs
      interfaces: [bond0]
  bonds:
    - name: bond0
      type: ovs
      mode: balance-tcp
      interfaces: [eth6, eth7]
      vlans:
        - {zone: fabric, ipv4-address: 10.4.1.20/24, auto-start: true}
sdn:
  enabled: true
  environment: {id: 4, ula: fd12:3456:789a::/48}
  ovs: {socket: /var/run/openvswitch/db.sock, bridge: br-fabric}
pxe:
  enabled: true
  bind-host: 192.0.2.1
  http-port: 8080
  tftp-port: 69
  local-files-dir: /var/lib/platform/pxe/files
  installs-dir: /var/lib/platform/pxe/installs
  boot-entries:
    - name: alpine
      description: Alpine installer
      kernel: /data/vmlinuz
      initrd: /data/initramfs
      args: console=ttyS0
      architecture: x86_64
      auto-install: true
`

const strictStalePlatform = `
network:
  subnets: []
  bridges:
    - name: br-fabric
      members: [bond0]
sdn:
  enabled: true
  environment: {id: 4}
  networks: []
  transit: {vlan: 10}
`

func unknownPaths(t *testing.T, err error) []string {
	t.Helper()
	var target *config.ErrUnknownConfigKeys
	require.True(t, errors.As(err, &target), "got %v", err)
	out := make([]string, len(target.Keys))
	for i, k := range target.Keys {
		out[i] = k.Path
	}
	return out
}

// TestCheckPlatformConfigYAML accepts the current schema and refuses stale
// network and sdn keys with their paths and lines.
func TestCheckPlatformConfigYAML(t *testing.T) {
	require.NoError(t, CheckPlatformConfigYAML([]byte(strictGoodPlatform)))

	err := CheckPlatformConfigYAML([]byte(strictStalePlatform))
	assert.Equal(t, []string{"network.bridges[0].members", "network.subnets"}, unknownPaths(t, err))
	assert.Contains(t, err.Error(), "line 6")

	err = CheckPlatformConfigYAML([]byte("sdn:\n  enabled: true\n  networks: []\n  transit: {vlan: 10}\n"))
	assert.Equal(t, []string{"sdn.networks", "sdn.transit"}, unknownPaths(t, err))

	err = CheckPlatformConfigYAML([]byte("pxe:\n  enabled: true\n  http-prot: 8080\n  boot-entries:\n    - {name: a, description: b, kernal: /vmlinuz}\n"))
	assert.Equal(t, []string{"pxe.boot-entries[0].kernal", "pxe.http-prot"}, unknownPaths(t, err))
}

func platformViper(t *testing.T, doc string) *viper.Viper {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(doc)))
	return v
}

// TestCheckPlatformConfigViper applies the same refusal on platformd's
// viper load path.
func TestCheckPlatformConfigViper(t *testing.T) {
	require.NoError(t, CheckPlatformConfigViper(platformViper(t, strictGoodPlatform)))

	err := CheckPlatformConfigViper(platformViper(t, strictStalePlatform))
	assert.ElementsMatch(t, []string{"network.bridges[0].members", "network.subnets"}, unknownPaths(t, err))

	err = CheckPlatformConfigViper(platformViper(t, "sdn:\n  enabled: true\n  networks: []\n  transit: {vlan: 10}\n"))
	assert.ElementsMatch(t, []string{"sdn.networks", "sdn.transit"}, unknownPaths(t, err))
}
