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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

const (
	// forwardingSysctlPath is the sysctl drop-in that pins a platform
	// host's forwarding setting.
	forwardingSysctlPath = "etc/sysctl.d/60-platform-forwarding.conf"

	// hostFirewallPath is the nftables drop-in that drops traffic between
	// the interfaces of a non-gateway platform host. Alpine's
	// /etc/nftables.nft includes /etc/nftables.d/*.nft.
	hostFirewallPath = "etc/nftables.d/60-platform-hostfw.nft"

	// nftablesService is the OpenRC service that loads the ruleset.
	nftablesService = "nftables"

	// PlatformVRFDummy is the dummy interface, enslaved to the platform VRF,
	// that carries the host's platform-VRF /32 until the platform overlay
	// attaches to the VRF (#709).
	PlatformVRFDummy = "pvrf0"
)

// forwardingSysctl renders the forwarding drop-in for a role: on for a
// gateway, off for every other platform host.
func forwardingSysctl(role HostRole) string {
	v := 0
	if role == HostRoleGateway {
		v = 1
	}
	return fmt.Sprintf(`# Written by the Trusted Platform installer (network.role: %s).
# Only a gateway forwards on the reference network; every other host keeps
# forwarding off (docs/architecture/reference-network.md, "Host addressing").
net.ipv4.ip_forward = %d
net.ipv6.conf.all.forwarding = %d
`, role, v, v)
}

// hostFirewallRuleset renders the nftables ruleset that drops every packet
// forwarded between a non-gateway host's interfaces.
func hostFirewallRuleset(role HostRole) string {
	return fmt.Sprintf(`# Written by the Trusted Platform installer (network.role: %s).
# A platform host other than a gateway never forwards between its
# interfaces (docs/architecture/reference-network.md, "Host addressing").
# OVS-switched frames do not traverse this hook.
table inet platform_hostfw {
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
`, role)
}

// configureHostIsolation writes the forwarding sysctl for any platform
// role and, for a non-gateway role, the forward-drop ruleset with the
// nftables service enabled in the default runlevel. A gateway gets no
// ruleset: gatewayd's host filter owns its packet filter. A host with no
// role is not on a platform network and gets neither.
func configureHostIsolation(rootPath string, nc *NetworkConfig) error {
	if nc == nil || nc.Role == "" {
		return nil
	}
	if err := writeRootFile(rootPath, forwardingSysctlPath, forwardingSysctl(nc.Role)); err != nil {
		return err
	}
	if nc.Role == HostRoleGateway {
		return nil
	}
	if err := writeRootFile(rootPath, hostFirewallPath, hostFirewallRuleset(nc.Role)); err != nil {
		return err
	}
	return enableOpenRCService(rootPath, nftablesService, "default")
}

// writeRootFile writes content to rel under rootPath, creating parents.
func writeRootFile(rootPath, rel, content string) error {
	path := filepath.Join(rootPath, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return &WrappedError{Msg: "failed to create " + filepath.Dir(rel), Err: err}
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return &WrappedError{Msg: "failed to write " + rel, Err: err}
	}
	return nil
}

// enableOpenRCService adds service to runlevel the way rc-update does: a
// symlink /etc/runlevels/<runlevel>/<service> → /etc/init.d/<service>. It is
// idempotent.
func enableOpenRCService(rootPath, service, runlevel string) error {
	dir := filepath.Join(rootPath, "etc", "runlevels", runlevel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return &WrappedError{Msg: "failed to create runlevel " + runlevel, Err: err}
	}
	link := filepath.Join(dir, service)
	err := os.Symlink("/etc/init.d/"+service, link)
	if err == nil || errors.Is(err, fs.ErrExist) {
		return nil
	}
	return &WrappedError{Msg: "failed to enable service " + service, Err: err}
}

// generatePlatformVRFConfig renders the ifupdown-ng stanzas of the platform
// VRF: the VRF device on its routing table, and a dummy interface enslaved
// to it holding the host's platform-VRF /32.
func generatePlatformVRFConfig(v *PlatformVRFConfig) string {
	if v == nil {
		return ""
	}
	var b strings.Builder
	name := v.EffectiveName()
	fmt.Fprintf(&b, "# Platform VRF %s (table %d); the platform overlay attaches to it (#709)\n", name, v.EffectiveTable())
	fmt.Fprintf(&b, "auto %s\niface %s\n    vrf-table %d\n\n", name, name, v.EffectiveTable())
	fmt.Fprintf(&b, "auto %s\niface %s\n    link-type dummy\n    vrf-member %s\n    address %s\n\n",
		PlatformVRFDummy, PlatformVRFDummy, name, v.Address)
	return b.String()
}

// generateBondVLANConfig renders an 802.1Q sub-interface of a Linux bond on
// a zone VLAN. The VLAN ID comes from the network plan. No gateway line is
// emitted: a platform host has one default route, not one per zone.
func generateBondVLANConfig(plan *netplan.Plan, bondName string, bv *BondVLANConfig) (string, error) {
	if plan == nil {
		return "", &ErrNetworkPlanRequired{Field: "network.bonds[" + bondName + "].vlans"}
	}
	n, ok := plan.Zone(zone.Zone(bv.Zone))
	if !ok {
		return "", &ErrBondZoneVLAN{Bond: bondName, Zone: bv.Zone, Reason: "the zone is not in the network plan"}
	}

	var config strings.Builder
	ifaceName := fmt.Sprintf("%s.%d", bondName, n.VLAN)
	fmt.Fprintf(&config, "# Bond VLAN: %s (zone %s, VLAN %d)\n", ifaceName, bv.Zone, n.VLAN)
	if bv.AutoStart {
		fmt.Fprintf(&config, "auto %s\n", ifaceName)
	}
	if bv.IPv4Address != "" {
		fmt.Fprintf(&config, "iface %s inet static\n", ifaceName)
		fmt.Fprintf(&config, "    address %s\n", bv.IPv4Address)
	} else {
		fmt.Fprintf(&config, "iface %s inet manual\n", ifaceName)
	}
	config.WriteString("\n")
	return config.String(), nil
}
