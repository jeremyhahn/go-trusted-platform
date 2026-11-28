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

// Package zoneflows provides per-zone OpenFlow template generators and the
// inter-zone matrix rule compiler for the trusted-platform zone-based SDN
// policy model.
//
// Flow generation is zone-keyed, not VLAN-keyed. Generators are selected via
// map dispatch (map[zone.Zone]Generator) so user-defined zones with no built-in
// template fall through to generic matrix-driven rules only.
//
// Usage:
//
//	gen := zoneflows.NewGeneratorSet(config)
//	flows := gen.Generate(portID, z, network)
//
// See docs/architecture/reference-network.md for the per-zone rule sets and
// inter-zone matrix semantics that this package implements.
package zoneflows

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// FlowRule is a single OpenFlow rule ready for installation.
type FlowRule struct {
	// Table is the OpenFlow table number.
	Table int

	// Priority is the rule priority (higher wins).
	Priority int

	// Match is the OpenFlow match string.
	Match string

	// Actions is the OpenFlow actions string.
	Actions string

	// Cookie is an optional cookie value for the rule.
	Cookie string
}

// ZoneFlowConfig is the aggregate configuration for the zone flow generators.
// All IP slices default to "allow all" when empty, matching the provisioning
// and quarantine generator conventions.
type ZoneFlowConfig struct {
	// BridgeName is the OVS bridge that receives the flows.
	BridgeName string

	// Terminal is the action every generated allow rule ends in. Empty is
	// TerminalNormal, the platform's historical behaviour; on a bridge
	// whose base pipeline gatewayd owns it is TerminalGatewayPipeline, so
	// a platformd allow-rule hands the packet to the gateway's table-10
	// gates instead of punching straight through them (#567).
	Terminal Terminal

	// Provisioning configures the provisioning-zone template generator.
	Provisioning ProvisioningConfig

	// Quarantine configures the quarantine-zone template generator.
	Quarantine QuarantineConfig

	// Management configures the management-zone template generator.
	Management ManagementConfig
}

// ProvisioningConfig configures the provisioning zone flow generator.
type ProvisioningConfig struct {
	// ACMEServerIPs are the allowed ACME/CA server addresses. Empty = allow all.
	ACMEServerIPs []net.IP

	// DNSServerIPs are the allowed DNS server addresses. Empty = allow all.
	DNSServerIPs []net.IP

	// PackageRepoIPs are the allowed package repository addresses. Empty = allow all.
	PackageRepoIPs []net.IP

	// Gateway is the gateway for the provisioning network.
	Gateway net.IP

	// AllowICMP enables ICMP within the provisioning zone.
	AllowICMP bool
}

// QuarantineConfig configures the quarantine zone flow generator.
type QuarantineConfig struct {
	// ScanningServerIPs are the allowed security scanning server addresses.
	ScanningServerIPs []net.IP

	// RemediationServerIPs are the allowed remediation/patch server addresses.
	RemediationServerIPs []net.IP

	// DNSServerIP is the internal DNS server for the quarantine network.
	DNSServerIP net.IP

	// NotificationServerIP is the portal address for user-facing notifications.
	NotificationServerIP net.IP

	// Gateway is the gateway for the quarantine network.
	Gateway net.IP

	// AllowedPorts are additional TCP ports to permit to remediation servers.
	AllowedPorts []uint16
}

// ManagementConfig configures the management zone flow generator.
type ManagementConfig struct {
	// ManagementSubnet is the OOB subnet (used for isolation rules).
	ManagementSubnet string
}

// generator is the internal function type for a per-zone flow template.
type generator func(portID string, in Ingress) []FlowRule

// untaggedMatch matches a frame that carries no 802.1Q header: the VLAN
// CFI/present bit and the VID are all zero (OVS vlan_tci).
const untaggedMatch = "vlan_tci=0x0000/0x1fff"

// Ingress is how a zone's frames reach the OpenFlow tables on one port.
//
// OVS applies a port's VLAN configuration (tag, trunks, vlan_mode) only in
// the NORMAL action; the OpenFlow tables see each frame exactly as it was
// received (ovs-vswitchd.conf.db, Port "VLAN Configuration"; ovs-fields,
// vlan_tci). So a frame from an access port, and an untagged frame on a
// trunk's native VLAN, carries no 802.1Q header in the flow tables and
// never matches dl_vlan=<zone VLAN>. Only a trunk's tagged zones do.
type Ingress struct {
	// VLAN is the zone's VLAN ID.
	VLAN uint16
	// Tagged is true when the zone's frames arrive 802.1Q-tagged (a trunk's
	// non-native zones), false when they arrive untagged (an access port,
	// or a trunk's native zone).
	Tagged bool
}

// Untagged returns the ingress of a zone carried untagged: an access port's
// zone, or a trunk's native zone.
func Untagged(vlan uint16) Ingress { return Ingress{VLAN: vlan} }

// Tagged returns the ingress of a zone carried tagged on a trunk.
func Tagged(vlan uint16) Ingress { return Ingress{VLAN: vlan, Tagged: true} }

// Match returns the OpenFlow match for frames of this ingress: dl_vlan=N
// when tagged, an untagged-frame match otherwise.
func (in Ingress) Match() string {
	if in.Tagged {
		return fmt.Sprintf("dl_vlan=%d", in.VLAN)
	}
	return untaggedMatch
}

// NetworkSummary holds the VLAN and subnets for a zone's primary network.
// It is the value type for MatrixRuleConfig.NetworksByZone and is exported
// so callers (e.g. ZoneFlowManager) can build the map without reflection.
type NetworkSummary struct {
	// VLAN is the IEEE 802.1Q segment ID for this zone's primary network.
	VLAN uint16

	// Subnet is the CIDR-notation IPv4 prefix for the zone's primary subnet
	// (e.g. "10.4.6.0/24"). Used as nw_dst in OpenFlow match strings.
	Subnet string

	// Subnet6 is the CIDR-notation IPv6 prefix for the same network when it
	// is dual-stack (e.g. "fd12:3456:789a:406::/64"), used as ipv6_dst. Empty for
	// an IPv4-only network; the address-family-neutral rules still apply
	// to its IPv6 traffic (#554).
	Subnet6 string
}

// NewNetworkSummary builds a summary from a VLAN and up to two prefixes,
// filing each by address family so a caller that put an IPv6 prefix in the
// legacy single subnet field still gets an IPv6 rule set. An invalid prefix
// is left empty.
func NewNetworkSummary(vlan uint16, prefixes ...netip.Prefix) NetworkSummary {
	summary := NetworkSummary{VLAN: vlan}
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		if prefix.Addr().Is4() || prefix.Addr().Is4In6() {
			summary.Subnet = prefix.String()
			continue
		}
		summary.Subnet6 = prefix.String()
	}
	return summary
}

// MatrixRuleConfig is the input for the inter-zone matrix rule compiler.
type MatrixRuleConfig struct {
	// Matrix is the compiled inter-zone allow/deny matrix.
	Matrix zone.Matrix

	// Terminal is the action every allow rule CompileMatrixRules emits ends
	// in; see ZoneFlowConfig.Terminal. CompileStatefulMatrixRules ignores
	// it: its rules live inside the gateway's own pipeline.
	Terminal Terminal

	// Zones is the full resolved zone set.
	Zones []zone.ZoneConfig

	// NetworksByZone maps zone name → first network VLAN and subnet string.
	// Used to emit drop/allow rules for denied/allowed zone pairs.
	NetworksByZone map[zone.Zone]NetworkSummary

	// DefaultPolicy selects the conntrack verdict-table miss behavior for
	// CompileStatefulMatrixRules: "allow" continues the pipeline, anything
	// else (including the empty string) drops. CompileMatrixRules ignores
	// this field.
	DefaultPolicy string
}

// Terminal is the action a platformd allow rule terminates in.
type Terminal string

const (
	// TerminalNormal hands the packet to OVS's built-in L2 learning. It is
	// the default and the only correct terminal on a bridge no gatewayd
	// pipeline owns.
	TerminalNormal Terminal = "normal"

	// TerminalGatewayPipeline hands the packet to table 10, where the
	// gatewayd firewall, NAT and load-balancer gates live, so platformd's
	// per-port admission composes with gatewayd's inter-zone verdicts on a
	// shared bridge instead of bypassing them.
	TerminalGatewayPipeline Terminal = "goto_table:10"
)

// String returns the OpenFlow action for the terminal; empty is normal.
func (t Terminal) String() string {
	if t == "" {
		return string(TerminalNormal)
	}
	return string(t)
}

// ApplyTerminal rewrites every rule whose action is the bare `normal`
// terminal to t. Rules with a composite action ending in normal
// (`mod_vlan_vid:N,normal`) are rewritten at that suffix; drops and every
// other action are untouched. It returns rules for chaining.
func ApplyTerminal(rules []FlowRule, t Terminal) []FlowRule {
	if t == "" || t == TerminalNormal {
		return rules
	}
	for i := range rules {
		switch {
		case rules[i].Actions == string(TerminalNormal):
			rules[i].Actions = t.String()
		case strings.HasSuffix(rules[i].Actions, ","+string(TerminalNormal)):
			rules[i].Actions = strings.TrimSuffix(rules[i].Actions, string(TerminalNormal)) + t.String()
		}
	}
	return rules
}

// Bridge external_ids keys through which gatewayd records who owns a
// bridge's base pipeline (#567). They live here, in the lowest shared
// package, so platformd's compilers and gatewayd's runtime read one
// definition.
const (
	// PipelineOwnerKey holds "gatewayd:<gateway id>" while a gatewayd
	// pipeline is installed on the bridge; empty or absent means none.
	PipelineOwnerKey = "tp-pipeline-owner"

	// PipelineTerminalKey holds the gateway pipeline's own table-30
	// disposition ("normal" or "overlay").
	PipelineTerminalKey = "tp-pipeline-terminal"
)

// TerminalForBridge reads a bridge's external_ids and returns the terminal
// platformd's allow rules should end in on it: TerminalGatewayPipeline
// when a gatewayd pipeline owns the bridge (with the owner id), otherwise
// TerminalNormal.
func TerminalForBridge(externalIDs map[string]string) (Terminal, string) {
	owner := externalIDs[PipelineOwnerKey]
	if owner == "" {
		return TerminalNormal, ""
	}
	return TerminalGatewayPipeline, owner
}
