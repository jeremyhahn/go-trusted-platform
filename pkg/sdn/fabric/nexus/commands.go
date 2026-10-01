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

package nexus

import (
	"fmt"
	"strconv"
	"strings"
)

// showVLANCommand returns the NX-OS command to display a specific VLAN.
func showVLANCommand(vlan uint16) string {
	return fmt.Sprintf("show vlan id %d", vlan)
}

// createVLANCommands returns the NX-OS commands to create a VLAN with the
// given name. The commands are wrapped in configure terminal / end.
func createVLANCommands(vlan uint16, name string) []string {
	cmds := []string{
		"configure terminal",
		fmt.Sprintf("vlan %d", vlan),
	}
	if name != "" {
		cmds = append(cmds, fmt.Sprintf("  name %s", name))
	}
	cmds = append(cmds, "end")
	return cmds
}

// port-channel summary information.
func showPortChannelSummaryCommand() string {
	return "show port-channel summary"
}

// createLAGCommands returns the NX-OS commands to create a port-channel
// with the given members. It supports vPC (MC-LAG) configuration.
func createLAGCommands(portChannelID uint16, memberPorts []string, lacpMode string, vpc bool) []string {
	cmds := []string{"configure terminal"}

	// Create port-channel interface.
	cmds = append(cmds, fmt.Sprintf("interface port-channel%d", portChannelID))
	cmds = append(cmds, "  switchport")
	if vpc {
		cmds = append(cmds, fmt.Sprintf("  vpc %d", portChannelID))
	}

	// Add member interfaces.
	for _, port := range memberPorts {
		cmds = append(cmds, fmt.Sprintf("interface %s", port))
		cmds = append(cmds, fmt.Sprintf("  channel-group %d", portChannelID))
		if lacpMode != "" {
			cmds[len(cmds)-1] = fmt.Sprintf("  channel-group %d mode %s", portChannelID, lacpMode)
		}
	}

	cmds = append(cmds, "end")
	return cmds
}

// setPortAccessCommands returns the NX-OS commands to configure a port
// setPortAccessCommands puts port in access mode on vlan, with mtu when
// non-zero, and brings it up.
func setPortAccessCommands(port string, vlan uint16, mtu int) []string {
	cmds := []string{
		"configure terminal",
		fmt.Sprintf("interface %s", port),
		"  switchport",
		"  switchport mode access",
		fmt.Sprintf("  switchport access vlan %d", vlan),
	}
	cmds = appendMTU(cmds, mtu)
	return append(cmds, "  no shutdown", "end")
}

// setPortTrunkCommands puts port in trunk mode carrying allowed, with native
// as the native VLAN (none clears it back to the default), mtu when
// non-zero, and brings it up.
func setPortTrunkCommands(port string, allowed []uint16, native uint16, mtu int) []string {
	cmds := []string{
		"configure terminal",
		fmt.Sprintf("interface %s", port),
		"  switchport",
		"  switchport mode trunk",
	}
	if len(allowed) > 0 {
		cmds = append(cmds, fmt.Sprintf("  switchport trunk allowed vlan %s", joinUint16s(allowed, ",")))
	} else {
		cmds = append(cmds, "  switchport trunk allowed vlan none")
	}
	if native > 0 {
		cmds = append(cmds, fmt.Sprintf("  switchport trunk native vlan %d", native))
	} else {
		cmds = append(cmds, "  no switchport trunk native vlan")
	}
	cmds = appendMTU(cmds, mtu)
	return append(cmds, "  no shutdown", "end")
}

// disablePortCommands administratively shuts port down.
func disablePortCommands(port string) []string {
	return []string{
		"configure terminal",
		fmt.Sprintf("interface %s", port),
		"  shutdown",
		"end",
	}
}

// appendMTU adds the interface MTU command when mtu is non-zero.
func appendMTU(cmds []string, mtu int) []string {
	if mtu > 0 {
		cmds = append(cmds, fmt.Sprintf("  mtu %d", mtu))
	}
	return cmds
}

// running configuration for a specific interface.
func showRunningInterfaceCommand(port string) string {
	return fmt.Sprintf("show running-config interface %s", port)
}

// joinUint16s joins a slice of uint16 values with the given separator.
func joinUint16s(vals []uint16, sep string) string {
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(strs, sep)
}
