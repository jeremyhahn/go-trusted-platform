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
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAlpineInstaller_GenerateBondConfig_Interfaces covers the legacy Linux
// kernel bonding path (Type=linux). Device configs that explicitly opt into
// kernel bonding still produce ifenslave-style /etc/network/interfaces output.
func TestAlpineInstaller_GenerateBondConfig_Interfaces(t *testing.T) {
	ai := &alpineInstaller{
		config: &OSConfig{OS: OSAlpine},
	}

	bond := &BondConfig{
		Name:        "bond0",
		Type:        BondTypeLinux,
		Mode:        "802.3ad",
		Interfaces:  []string{"eth0", "eth1"},
		IPv4Address: "10.99.99.1/24",
		AutoStart:   true,
		MIIMon:      100,
	}

	result := ai.generateBondConfig(bond)

	// Member interfaces should be configured
	assert.Contains(t, result, "auto eth0")
	assert.Contains(t, result, "iface eth0 inet manual")
	assert.Contains(t, result, "bond-master bond0")
	assert.Contains(t, result, "auto eth1")
	assert.Contains(t, result, "iface eth1 inet manual")

	// Bond itself
	assert.Contains(t, result, "auto bond0")
	assert.Contains(t, result, "iface bond0 inet static")
	assert.Contains(t, result, "address 10.99.99.1/24")
	assert.Contains(t, result, "bond-slaves eth0 eth1")
	assert.Contains(t, result, "bond-mode 802.3ad")
	assert.Contains(t, result, "bond-miimon 100")
}

// TestAlpineInstaller_GenerateBondConfig_OVSDefault covers the default path
// when Type is unset: the installer emits an OVS-friendly stub that brings
// member interfaces up in inet manual so platformd's initOVSBonds can claim
// them at runtime without racing the kernel bonding driver.
func TestAlpineInstaller_GenerateBondConfig_OVSDefault(t *testing.T) {
	ai := &alpineInstaller{
		config: &OSConfig{OS: OSAlpine},
	}

	bond := &BondConfig{
		Name:        "bond0",
		Mode:        "802.3ad",
		Interfaces:  []string{"eth0", "eth1"},
		IPv4Address: "10.99.99.1/24",
		AutoStart:   true,
		MIIMon:      100,
	}

	result := ai.generateBondConfig(bond)

	// OVS bond marker comment
	assert.Contains(t, result, "OVS")
	assert.Contains(t, result, "initOVSBonds")

	// Members are brought up in inet manual; OVS owns the bond at runtime
	assert.Contains(t, result, "auto eth0")
	assert.Contains(t, result, "iface eth0 inet manual")
	assert.Contains(t, result, "auto eth1")
	assert.Contains(t, result, "iface eth1 inet manual")
	assert.Contains(t, result, "ip link set $IFACE up")

	// Kernel-bond directives MUST NOT appear in OVS mode
	assert.NotContains(t, result, "bond-master")
	assert.NotContains(t, result, "bond-slaves")
	assert.NotContains(t, result, "bond-mode")
	assert.NotContains(t, result, "bond-miimon")
}

// TestAlpineInstaller_GenerateBondConfig_OVSExplicit verifies that explicit
// Type=ovs produces the same output as the unset default.
func TestAlpineInstaller_GenerateBondConfig_OVSExplicit(t *testing.T) {
	ai := &alpineInstaller{
		config: &OSConfig{OS: OSAlpine},
	}

	bond := &BondConfig{
		Name:       "bond0",
		Type:       BondTypeOVS,
		Mode:       "802.3ad",
		Interfaces: []string{"eth0", "eth1"},
		AutoStart:  true,
	}

	result := ai.generateBondConfig(bond)

	assert.Contains(t, result, "OVS")
	assert.Contains(t, result, "iface eth0 inet manual")
	assert.NotContains(t, result, "bond-slaves")
}

// TestAlpineInstaller_GenerateBondConfig_DHCP exercises the Linux kernel
// bonding DHCP path. OVS bonds don't have a DHCP-on-the-bond concept
// (DHCP runs on the OVS-owned bridge port at runtime), so this test pins
// Type=linux explicitly.
func TestAlpineInstaller_GenerateBondConfig_DHCP(t *testing.T) {
	ai := &alpineInstaller{
		config: &OSConfig{OS: OSAlpine},
	}

	bond := &BondConfig{
		Name:       "bond0",
		Type:       BondTypeLinux,
		Mode:       "active-backup",
		Interfaces: []string{"eth0", "eth1"},
		DHCP:       true,
		Primary:    "eth0",
		AutoStart:  true,
	}

	result := ai.generateBondConfig(bond)

	assert.Contains(t, result, "iface bond0 inet dhcp")
	assert.Contains(t, result, "bond-primary eth0")
	assert.Contains(t, result, "bond-slaves eth0 eth1")
}

// TestAlpineInstaller_GenerateBondConfig_Manual exercises the Linux kernel
// bonding manual path (no address, no DHCP). Pinned to Type=linux because
// OVS mode never emits an iface-bond stanza at install time.
func TestAlpineInstaller_GenerateBondConfig_Manual(t *testing.T) {
	ai := &alpineInstaller{
		config: &OSConfig{OS: OSAlpine},
	}

	bond := &BondConfig{
		Name:       "bond0",
		Type:       BondTypeLinux,
		Mode:       "802.3ad",
		Interfaces: []string{"eth0", "eth1"},
		AutoStart:  true,
	}

	result := ai.generateBondConfig(bond)

	// No address and no DHCP = manual
	assert.Contains(t, result, "iface bond0 inet manual")
}
