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
	"errors"
	"net/netip"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// installTargetKey is the merged-config key the installer reads its
// install target from.
const installTargetKey = "install-target"

// refuseDisklessImageTarget refuses a diskless node whose merged config
// keeps install-target: image. The role templates default to image
// because they double as factory SD images; a diskless node runs its
// installer on the node, which needs the disk target.
func refuseDisklessImageTarget(merged map[string]interface{}, node *NodeConfig) error {
	if node == nil || node.SkipInstall || !node.IsDiskless() {
		return nil
	}
	target, _ := merged[installTargetKey].(string)
	if installer.InstallTarget(target) != installer.InstallTargetImage {
		return nil
	}
	return ErrDisklessImageTarget{Hostname: node.Hostname, BootModel: node.EffectiveBootModel()}
}

// nodeAddress is one address a node's merged config assigns, and where.
type nodeAddress struct {
	hostname string
	where    string
	addr     netip.Addr
}

// mergedAddresses lists the static addresses a node's merged config
// assigns: on interfaces, bridges, bonds and their zone VLANs, VLANs and
// the platform VRF.
func mergedAddresses(hostname, merged string) ([]nodeAddress, error) {
	var doc struct {
		Network installer.NetworkConfig `yaml:"network"`
	}
	if err := yaml.Unmarshal([]byte(merged), &doc); err != nil {
		return nil, err
	}
	var out []nodeAddress
	add := func(where, value string) {
		if addr, ok := parseNodeAddress(value); ok {
			out = append(out, nodeAddress{hostname: hostname, where: where, addr: addr})
		}
	}
	network := doc.Network
	for _, iface := range network.Interfaces {
		add("interface "+iface.Name, iface.IPv4Address)
		add("interface "+iface.Name, iface.IPv6Address)
	}
	for _, bridge := range network.Bridges {
		add("bridge "+bridge.Name, bridge.IPv4Address)
	}
	for _, bond := range network.Bonds {
		add("bond "+bond.Name, bond.IPv4Address)
		for _, vlan := range bond.VLANs {
			add("bond "+bond.Name+" zone "+vlan.Zone, vlan.IPv4Address)
		}
	}
	for _, vlan := range network.VLANs {
		add("vlan "+vlan.Name, vlan.IPv4Address)
	}
	if network.PlatformVRF != nil {
		add("platform-vrf", network.PlatformVRF.Address)
	}
	return out, nil
}

// parseNodeAddress reads an address in CIDR notation or bare.
func parseNodeAddress(value string) (netip.Addr, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr(), true
	}
	addr, err := netip.ParseAddr(value)
	return addr, err == nil
}

// checkNodeConfigs resolves every node and refuses the configs the
// installer would take but the network cannot: a diskless node asking for
// the image target, and an address two nodes both claim. A node that does
// not resolve for any other reason is left to per-MAC staging's documented
// fall-back, as before.
func (o *Orchestrator) checkNodeConfigs() error {
	owners := map[netip.Addr]nodeAddress{}
	for _, n := range o.config.Nodes {
		merged, err := o.resolveNodeConfig(n.Hostname, n.Role, nil)
		var imageErr ErrDisklessImageTarget
		if errors.As(err, &imageErr) {
			return ErrNodeConfigResolveFailed{Hostname: n.Hostname, Cause: err}
		}
		if err != nil {
			continue
		}
		addresses, err := mergedAddresses(n.Hostname, merged)
		if err != nil {
			return ErrNodeConfigResolveFailed{Hostname: n.Hostname, Cause: err}
		}
		for _, a := range addresses {
			other, taken := owners[a.addr]
			if taken && other.hostname != a.hostname {
				return ErrDuplicateNodeAddress{
					Address:       a.addr.String(),
					Hostname:      a.hostname,
					Where:         a.where,
					OtherHostname: other.hostname,
					OtherWhere:    other.where,
				}
			}
			owners[a.addr] = a
		}
	}
	return nil
}
