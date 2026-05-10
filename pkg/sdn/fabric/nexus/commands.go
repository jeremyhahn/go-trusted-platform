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

// showNVEVNICommand returns the NX-OS command to display NVE VNI mappings.
func showNVEVNICommand() string {
	return "show nve vni"
}

// createVNICommands returns the NX-OS commands to map a VNI to a VLAN on
// the NVE interface.
func createVNICommands(vni uint32, vlan uint16) []string {
	return []string{
		"configure terminal",
		"interface nve1",
		fmt.Sprintf("  member vni %d associate-vlan %d", vni, vlan),
		"end",
	}
}

// showPortChannelSummaryCommand returns the NX-OS command to display
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
// in access mode with the specified VLAN.
func setPortAccessCommands(port string, vlan uint16) []string {
	return []string{
		"configure terminal",
		fmt.Sprintf("interface %s", port),
		"  switchport",
		"  switchport mode access",
		fmt.Sprintf("  switchport access vlan %d", vlan),
		"  no shutdown",
		"end",
	}
}

// setPortTrunkCommands returns the NX-OS commands to configure a port
// in trunk mode with the allowed VLANs and an optional native VLAN.
func setPortTrunkCommands(port string, allowed []uint16, native uint16) []string {
	cmds := []string{
		"configure terminal",
		fmt.Sprintf("interface %s", port),
		"  switchport",
		"  switchport mode trunk",
	}

	if len(allowed) > 0 {
		vlanList := joinUint16s(allowed, ",")
		cmds = append(cmds, fmt.Sprintf("  switchport trunk allowed vlan %s", vlanList))
	}

	if native > 0 {
		cmds = append(cmds, fmt.Sprintf("  switchport trunk native vlan %d", native))
	}

	cmds = append(cmds, "  no shutdown")
	cmds = append(cmds, "end")
	return cmds
}

// showRunningInterfaceCommand returns the NX-OS command to display the
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
