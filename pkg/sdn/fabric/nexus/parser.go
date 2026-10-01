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
	"slices"
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

// interfaceConfig is the part of an interface's running configuration the
// driver converges: mode, VLANs, MTU and admin state.
type interfaceConfig struct {
	mode       string
	accessVLAN uint16
	allowed    []uint16
	native     uint16
	mtu        int
	shutdown   bool
}

// modeRouted marks a port configured "no switchport" (a layer-3 port).
const modeRouted = "routed"

// parseInterfaceConfig reads "show running-config interface <port>" output.
// Ranges in the allowed VLAN list ("400-402") are expanded; "add" lines
// extend the list. Unparseable values are ignored, which only makes the
// driver reconfigure the port.
func parseInterfaceConfig(output string) interfaceConfig {
	var cfg interfaceConfig
	layer2 := false
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) > 0 && f[0] == "switchport" {
			layer2 = true
		}
		switch {
		case len(f) == 3 && f[0] == "switchport" && f[1] == "mode":
			cfg.mode = f[2]
		case len(f) == 4 && f[0] == "switchport" && f[1] == "access" && f[2] == "vlan":
			cfg.accessVLAN = parseUint16(f[3])
		case len(f) == 5 && f[0] == "switchport" && f[1] == "trunk" && f[2] == "native" && f[3] == "vlan":
			cfg.native = parseUint16(f[4])
		case len(f) >= 5 && f[0] == "switchport" && f[1] == "trunk" && f[2] == "allowed" && f[3] == "vlan":
			list := f[4]
			if list == "add" && len(f) == 6 {
				list = f[5]
			} else {
				cfg.allowed = nil
			}
			cfg.allowed = append(cfg.allowed, parseVLANList(list)...)
		case len(f) == 2 && f[0] == "mtu":
			if v, err := strconv.Atoi(f[1]); err == nil {
				cfg.mtu = v
			}
		case len(f) == 1 && f[0] == "shutdown":
			cfg.shutdown = true
		case len(f) == 2 && f[0] == "no" && f[1] == "switchport":
			cfg.mode = modeRouted
		}
	}
	// NX-OS omits the default "switchport mode access" from running-config,
	// so a layer-2 port with no mode line is an access port. Output with no
	// switchport line at all says nothing about the mode.
	if cfg.mode == "" && layer2 {
		cfg.mode = "access"
	}
	slices.Sort(cfg.allowed)
	return cfg
}

// parseVLANList expands an NX-OS VLAN list such as "400-402,405".
func parseVLANList(list string) []uint16 {
	var out []uint16
	for _, part := range strings.Split(list, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		start, end := parseUint16(lo), parseUint16(lo)
		if isRange {
			end = parseUint16(hi)
		}
		if start == 0 || end < start {
			continue
		}
		for v := uint32(start); v <= uint32(end); v++ {
			out = append(out, uint16(v))
		}
	}
	return out
}

// parseUint16 parses a decimal VLAN ID, returning 0 on failure.
func parseUint16(s string) uint16 {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(v)
}

// containsError checks if NX-OS output contains an error indicator.
func containsError(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "error") ||
		strings.Contains(lower, "invalid") ||
		strings.Contains(lower, "% ")
}
