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

package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeConfig_IsDiskless(t *testing.T) {
	for model, want := range map[string]bool{
		BootModelDiskless:    true,
		BootModelDisklessNBD: true,
		BootModelSD:          false,
	} {
		n := &NodeConfig{Platform: PlatformRaspberryPi, BootModel: model}
		assert.Equal(t, want, n.IsDiskless(), model)
	}
	assert.False(t, (&NodeConfig{Platform: PlatformRaspberryPi}).IsDiskless(), "a Pi defaults to sd")
	assert.False(t, (&NodeConfig{}).IsDiskless(), "a generic server installs to disk")
}

func TestRefuseDisklessImageTarget(t *testing.T) {
	image := map[string]interface{}{installTargetKey: "image"}
	diskless := &NodeConfig{Hostname: "pi", Platform: PlatformRaspberryPi, BootModel: BootModelDisklessNBD}

	err := refuseDisklessImageTarget(image, diskless)
	assert.Equal(t, ErrDisklessImageTarget{Hostname: "pi", BootModel: BootModelDisklessNBD}, err)
	assert.Contains(t, err.Error(), "install-target: disk")

	assert.NoError(t, refuseDisklessImageTarget(map[string]interface{}{installTargetKey: "disk"}, diskless))
	assert.NoError(t, refuseDisklessImageTarget(map[string]interface{}{}, diskless), "no target is the installer's default, disk")
	assert.NoError(t, refuseDisklessImageTarget(map[string]interface{}{installTargetKey: 7}, diskless), "a malformed target is the installer's to refuse")
	assert.NoError(t, refuseDisklessImageTarget(image, nil), "a hostname with no node entry")
	assert.NoError(t, refuseDisklessImageTarget(image, &NodeConfig{Hostname: "sd", Platform: PlatformRaspberryPi}))
	skipped := *diskless
	skipped.SkipInstall = true
	assert.NoError(t, refuseDisklessImageTarget(image, &skipped), "this run does not install it")
}

func TestMergedAddresses(t *testing.T) {
	const merged = `
network:
  interfaces:
    - {name: eth0, type: static, ipv4-address: 10.0.0.1/24, ipv6-address: "fd00::1/64"}
    - {name: eth1, type: manual}
  bridges:
    - {name: br0, ipv4-address: 10.0.1.1}
  bonds:
    - name: bond0
      ipv4-address: 10.0.2.1/24
      vlans:
        - {zone: fabric, ipv4-address: 10.0.3.1/24}
  vlans:
    - {name: zone401, zone: fabric, ipv4-address: 10.0.4.1/24}
  platform-vrf:
    address: 10.0.5.1/32
`
	addresses, err := mergedAddresses("n1", merged)
	require.NoError(t, err)
	got := map[string][]string{}
	for _, a := range addresses {
		assert.Equal(t, "n1", a.hostname)
		got[a.where] = append(got[a.where], a.addr.String())
	}
	assert.Equal(t, map[string][]string{
		"interface eth0":         {"10.0.0.1", "fd00::1"},
		"bridge br0":             {"10.0.1.1"},
		"bond bond0":             {"10.0.2.1"},
		"bond bond0 zone fabric": {"10.0.3.1"},
		"vlan zone401":           {"10.0.4.1"},
		"platform-vrf":           {"10.0.5.1"},
	}, got)

	none, err := mergedAddresses("n1", "os:\n  hostname: n1\n")
	require.NoError(t, err)
	assert.Empty(t, none, "a config with no network section")
}

func TestMergedAddresses_Malformed(t *testing.T) {
	_, err := mergedAddresses("n1", "network:\n  interfaces: not-a-list\n")
	assert.Error(t, err)
}

func TestMergedIDevID(t *testing.T) {
	merged := "tpm:\n  idevid:\n    model: Raspberry Pi 4 Model B\n    serial: rpi4-compute-01\n    handle: 0x81020000\n"
	idevid, err := mergedIDevID(merged)
	require.NoError(t, err)
	assert.Equal(t, nodeIDevID{Model: "Raspberry Pi 4 Model B", Serial: "rpi4-compute-01"}, idevid)

	none, err := mergedIDevID("os:\n  hostname: n1\n")
	require.NoError(t, err)
	assert.Equal(t, nodeIDevID{}, none, "a config without tpm.idevid names no device")
}

func TestMergedIDevID_Malformed(t *testing.T) {
	_, err := mergedIDevID("tpm:\n  idevid: not-a-map\n")
	assert.Error(t, err)
}

func TestKeepsConfigSerial(t *testing.T) {
	for model, want := range map[string]bool{
		BootModelDiskless:    false,
		BootModelDisklessNBD: true,
		BootModelSD:          true,
	} {
		n := &NodeConfig{Platform: PlatformRaspberryPi, BootModel: model}
		assert.Equal(t, want, keepsConfigSerial(n), model)
	}
	assert.True(t, keepsConfigSerial(&NodeConfig{}), "a generic server keeps its config's serial")
}

func TestParseNodeAddress(t *testing.T) {
	addr, ok := parseNodeAddress("10.4.1.20/24")
	require.True(t, ok)
	assert.Equal(t, "10.4.1.20", addr.String())

	addr, ok = parseNodeAddress("10.4.1.20")
	require.True(t, ok)
	assert.Equal(t, "10.4.1.20", addr.String())

	for _, bad := range []string{"", "dhcp", "10.4.1/24", "10.4.1.300"} {
		_, ok := parseNodeAddress(bad)
		assert.False(t, ok, bad)
	}
}
