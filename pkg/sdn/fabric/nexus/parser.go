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

// vlanInfo holds parsed information about a VLAN from show output.
type vlanInfo struct {
	ID     uint16
	Name   string
	Status string
}

// parseShowVLAN parses the output of "show vlan id X" to determine if a
// VLAN exists. Returns the vlanInfo and true if found, nil and false otherwise.
func parseShowVLAN(output string, vlanID uint16) (*vlanInfo, bool) {
	lines := strings.Split(output, "\n")
	vlanStr := strconv.FormatUint(uint64(vlanID), 10)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// NX-OS "show vlan id X" output format:
		// VLAN Name                             Status    Ports
		// ---- -------------------------------- --------- -----------
		// 200  production                       active    Eth1/1, ...
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}

		if fields[0] == vlanStr {
			return &vlanInfo{
				ID:     vlanID,
				Name:   fields[1],
				Status: fields[2],
			}, true
		}
	}

	return nil, false
}

// parseShowNVEVNI checks whether a VNI mapping exists in "show nve vni" output.
// Returns true if the VNI is already configured.
func parseShowNVEVNI(output string, vni uint32) bool {
	lines := strings.Split(output, "\n")
	vniStr := strconv.FormatUint(uint64(vni), 10)

	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		for _, f := range fields {
			if f == vniStr {
				return true
			}
		}
	}
	return false
}

// parseShowPortChannelSummary checks whether a port-channel exists in
// "show port-channel summary" output. Returns true if the port-channel
// number is found.
func parseShowPortChannelSummary(output string, portChannelID uint16) bool {
	lines := strings.Split(output, "\n")
	pcStr := fmt.Sprintf("Po%d", portChannelID)

	for _, line := range lines {
		if strings.Contains(line, pcStr) {
			return true
		}
	}
	return false
}

// parseShowRunningInterface extracts the access VLAN from a running-config
// interface output. Returns 0 if not found.
func parseShowRunningInterface(output string) uint16 {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "switchport access vlan ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 4 {
				val, err := strconv.ParseUint(parts[3], 10, 16)
				if err == nil {
					return uint16(val)
				}
			}
		}
	}
	return 0
}

// containsError checks if NX-OS output contains an error indicator.
func containsError(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "error") ||
		strings.Contains(lower, "invalid") ||
		strings.Contains(lower, "% ")
}
