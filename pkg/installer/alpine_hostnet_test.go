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

package installer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readRootFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	require.NoError(t, err)
	return string(b)
}

// TestConfigureHostIsolation_Compute writes forwarding off, the forward-drop
// ruleset and the nftables runlevel link.
func TestConfigureHostIsolation_Compute(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, configureHostIsolation(root, &NetworkConfig{Role: HostRoleCompute}))

	sysctl := readRootFile(t, root, forwardingSysctlPath)
	assert.Contains(t, sysctl, "net.ipv4.ip_forward = 0")
	assert.Contains(t, sysctl, "net.ipv6.conf.all.forwarding = 0")

	nft := readRootFile(t, root, hostFirewallPath)
	assert.Contains(t, nft, "type filter hook forward priority filter; policy drop;")

	target, err := os.Readlink(filepath.Join(root, "etc", "runlevels", "default", "nftables"))
	require.NoError(t, err)
	assert.Equal(t, "/etc/init.d/nftables", target)

	// Idempotent: a second run keeps the existing link.
	require.NoError(t, configureHostIsolation(root, &NetworkConfig{Role: HostRoleCompute}))
}

// TestConfigureHostIsolation_Gateway turns forwarding on and leaves the
// filter to gatewayd.
func TestConfigureHostIsolation_Gateway(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, configureHostIsolation(root, &NetworkConfig{Role: HostRoleGateway, IPForward: true}))
	assert.Contains(t, readRootFile(t, root, forwardingSysctlPath), "net.ipv4.ip_forward = 1")
	_, err := os.Stat(filepath.Join(root, hostFirewallPath))
	assert.True(t, os.IsNotExist(err), "gatewayd's host filter owns a gateway's ruleset")
}

// TestConfigureHostIsolation_NoRole writes nothing off a platform network.
func TestConfigureHostIsolation_NoRole(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, configureHostIsolation(root, &NetworkConfig{}))
	require.NoError(t, configureHostIsolation(root, nil))
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// TestConfigureHostIsolation_Errors surfaces write failures.
func TestConfigureHostIsolation_Errors(t *testing.T) {
	root := t.TempDir()
	// A file where the sysctl.d directory belongs blocks the first write.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc", "sysctl.d"), nil, 0o644))
	var wrapped *WrappedError
	require.True(t, errors.As(configureHostIsolation(root, &NetworkConfig{Role: HostRoleCompute}), &wrapped))

	root = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc", "nftables.d"), nil, 0o644))
	require.True(t, errors.As(configureHostIsolation(root, &NetworkConfig{Role: HostRoleCompute}), &wrapped))

	root = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc", "runlevels"), nil, 0o644))
	require.True(t, errors.As(configureHostIsolation(root, &NetworkConfig{Role: HostRoleCompute}), &wrapped))

	root = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc", "nftables.d", "60-platform-hostfw.nft"), 0o755))
	require.True(t, errors.As(configureHostIsolation(root, &NetworkConfig{Role: HostRoleCompute}), &wrapped),
		"a directory where the ruleset belongs cannot be written")
}

// TestEnableOpenRCService_Error surfaces a runlevel directory that cannot
// be created and a link that cannot be made.
func TestEnableOpenRCService_Error(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc", "runlevels"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc", "runlevels", "default"), nil, 0o644))
	var wrapped *WrappedError
	require.True(t, errors.As(enableOpenRCService(root, "nftables", "default"), &wrapped))
	assert.Contains(t, wrapped.Error(), "runlevel default")

	long := strings.Repeat("x", 300)
	require.True(t, errors.As(enableOpenRCService(t.TempDir(), long, "default"), &wrapped),
		"a link name longer than NAME_MAX cannot be created")
	assert.Contains(t, wrapped.Error(), "failed to enable service")
}

// TestGeneratePlatformVRFConfig renders the VRF device and its dummy.
func TestGeneratePlatformVRFConfig(t *testing.T) {
	assert.Empty(t, generatePlatformVRFConfig(nil))
	out := generatePlatformVRFConfig(&PlatformVRFConfig{Address: "10.4.144.10/32"})
	assert.Contains(t, out, "iface vrf-platform\n    vrf-table 1000")
	assert.Contains(t, out, "iface pvrf0\n    link-type dummy\n    vrf-member vrf-platform\n    address 10.4.144.10/32")
}

// TestGenerateBondVLANConfig resolves the zone VLAN from the plan.
func TestGenerateBondVLANConfig(t *testing.T) {
	plan := testPlan(t)
	out, err := generateBondVLANConfig(plan, "bond0", &BondVLANConfig{Zone: "control-plane", IPv4Address: "10.4.6.10/24", AutoStart: true})
	require.NoError(t, err)
	assert.Contains(t, out, "auto bond0.406")
	assert.Contains(t, out, "iface bond0.406 inet static")
	assert.Contains(t, out, "address 10.4.6.10/24")
	assert.NotContains(t, out, "gateway", "one default route, not one per zone")

	out, err = generateBondVLANConfig(plan, "bond0", &BondVLANConfig{Zone: "fabric"})
	require.NoError(t, err)
	assert.NotContains(t, out, "auto bond0.401")
	assert.Contains(t, out, "iface bond0.401 inet manual")
}

// TestGenerateBondVLANConfig_Errors refuses a missing plan or zone.
func TestGenerateBondVLANConfig_Errors(t *testing.T) {
	_, err := generateBondVLANConfig(nil, "bond0", &BondVLANConfig{Zone: "fabric"})
	var planErr *ErrNetworkPlanRequired
	require.True(t, errors.As(err, &planErr))

	_, err = generateBondVLANConfig(testPlan(t), "bond0", &BondVLANConfig{Zone: "trusted"})
	var zoneErr *ErrBondZoneVLAN
	require.True(t, errors.As(err, &zoneErr))
}

// TestAlpineConfigureNetwork_PlatformHost writes the interfaces file with
// the platform VRF and a Linux-bond zone VLAN, and the isolation files.
func TestAlpineConfigureNetwork_PlatformHost(t *testing.T) {
	root := t.TempDir()
	ai := &alpineInstaller{logger: createTestLogger(), config: &OSConfig{OS: OSAlpine}}
	nc := &NetworkConfig{
		Role: HostRoleCompute,
		Bonds: []BondConfig{{
			Name: "bond1", Type: BondTypeLinux, Mode: "802.3ad", Interfaces: []string{"eth0", "eth1"},
			VLANs: []BondVLANConfig{{Zone: "fabric", IPv4Address: "10.4.1.20/24", AutoStart: true}},
		}},
		Interfaces:  []InterfaceConfig{{Name: "eth2", Type: InterfaceTypeManual}},
		PlatformVRF: &PlatformVRFConfig{Address: "10.4.144.20/32"},
	}
	require.NoError(t, ai.ConfigureNetwork(context.Background(), root, nc, testPlan(t)))

	ifaces := readRootFile(t, root, "etc/network/interfaces")
	assert.Contains(t, ifaces, "iface bond1.401 inet static")
	assert.Contains(t, ifaces, "vrf-member vrf-platform")
	assert.Contains(t, readRootFile(t, root, forwardingSysctlPath), "ip_forward = 0")
	assert.Contains(t, readRootFile(t, root, hostFirewallPath), "policy drop")
}

// TestAlpineConfigureNetwork_ZoneVLANWithoutPlan refuses a Linux-bond zone
// VLAN with no plan.
func TestAlpineConfigureNetwork_ZoneVLANWithoutPlan(t *testing.T) {
	ai := &alpineInstaller{logger: createTestLogger(), config: &OSConfig{OS: OSAlpine}}
	nc := &NetworkConfig{Bonds: []BondConfig{{
		Name: "bond1", Type: BondTypeLinux, Mode: "802.3ad", Interfaces: []string{"eth0", "eth1"},
		VLANs: []BondVLANConfig{{Zone: "fabric"}},
	}}}
	var target *ErrNetworkPlanRequired
	require.True(t, errors.As(ai.ConfigureNetwork(context.Background(), t.TempDir(), nc, nil), &target))
}

// TestAlpineConfigureNetwork_IsolationFailure returns the isolation error.
func TestAlpineConfigureNetwork_IsolationFailure(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc", "sysctl.d"), nil, 0o644))
	ai := &alpineInstaller{logger: createTestLogger(), config: &OSConfig{OS: OSAlpine}}
	var wrapped *WrappedError
	require.True(t, errors.As(ai.ConfigureNetwork(context.Background(), root, &NetworkConfig{Role: HostRoleGateway}, testPlan(t)), &wrapped))
}

// TestAlpineConfigureNetwork_DefaultEth0OnlyOffPlatform emits the default
// DHCP eth0 only for a host with no role: on a control-plane or compute node
// it would address provisioning, and a gateway's eth0 belongs to gatewayd.
func TestAlpineConfigureNetwork_DefaultEth0OnlyOffPlatform(t *testing.T) {
	plan := testPlan(t)
	for role, want := range map[HostRole]bool{
		"":                   true,
		HostRoleControlPlane: false,
		HostRoleCompute:      false,
		HostRoleGateway:      false,
	} {
		root := t.TempDir()
		ai := &alpineInstaller{logger: createTestLogger(), config: &OSConfig{OS: OSAlpine}}
		require.NoError(t, ai.ConfigureNetwork(context.Background(), root, &NetworkConfig{Role: role}, plan), "role %q", role)
		ifaces := readRootFile(t, root, "etc/network/interfaces")
		assert.Equal(t, want, strings.Contains(ifaces, "iface eth0 inet dhcp"), "role %q", role)
	}
}

// TestGenerateVLANConfig resolves a zone VLAN's id from the plan and keeps
// a literal id as written.
func TestGenerateVLANConfig(t *testing.T) {
	ai := &alpineInstaller{logger: createTestLogger(), config: &OSConfig{OS: OSAlpine}}
	out, err := ai.generateVLANConfig(&VLANConfig{Name: "vtep", Parent: "eth1", Zone: "fabric", IPv4Address: "10.4.1.20/24", AutoStart: true}, testPlan(t))
	require.NoError(t, err)
	assert.Contains(t, out, "zone fabric, ID 401")
	assert.Contains(t, out, "iface vtep inet static")
	assert.Contains(t, out, "vlan-raw-device eth1\n    vlan-id 401")

	out, err = ai.generateVLANConfig(&VLANConfig{Name: "eth1.100", Parent: "eth1", ID: 100, DHCP: true}, nil)
	require.NoError(t, err)
	assert.Contains(t, out, "iface eth1.100 inet dhcp")
	assert.Contains(t, out, "vlan-id 100")
}

// TestGenerateVLANConfig_Errors refuses a zone VLAN with no plan or an
// unknown zone, and ConfigureNetwork returns the error.
func TestGenerateVLANConfig_Errors(t *testing.T) {
	ai := &alpineInstaller{logger: createTestLogger(), config: &OSConfig{OS: OSAlpine}}
	_, err := ai.generateVLANConfig(&VLANConfig{Name: "v", Parent: "eth1", Zone: "fabric"}, nil)
	var planErr *ErrNetworkPlanRequired
	require.True(t, errors.As(err, &planErr))

	_, err = ai.generateVLANConfig(&VLANConfig{Name: "v", Parent: "eth1", Zone: "trusted"}, testPlan(t))
	var zoneErr *ErrVLANZone
	require.True(t, errors.As(err, &zoneErr))

	nc := &NetworkConfig{VLANs: []VLANConfig{{Name: "v", Parent: "eth1", Zone: "trusted"}}}
	require.True(t, errors.As(ai.ConfigureNetwork(context.Background(), t.TempDir(), nc, testPlan(t)), &zoneErr))
}
