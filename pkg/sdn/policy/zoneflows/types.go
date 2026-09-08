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
	"net"
	"net/netip"

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

	// Provisioning configures the provisioning-zone template generator.
	Provisioning ProvisioningConfig

	// Quarantine configures the quarantine-zone template generator.
	Quarantine QuarantineConfig

	// Trusted configures the trusted-zone template generator.
	Trusted TrustedConfig

	// Public configures the public-zone template generator.
	Public PublicConfig

	// Storage configures the storage-zone template generator.
	Storage StorageConfig

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

// TrustedConfig configures the trusted zone flow generator.
type TrustedConfig struct {
	// TrustedSubnet is the subnet for the trusted zone (used for matrix rules).
	TrustedSubnet string
}

// PublicConfig configures the public zone flow generator.
type PublicConfig struct {
	// TrustedSubnet is the trusted zone IPv4 subnet used to generate the
	// public→trusted deny rule (defense-in-depth).
	TrustedSubnet string

	// TrustedSubnet6 is the trusted zone IPv6 subnet for the same deny
	// rule; empty when the trusted zone is IPv4-only.
	TrustedSubnet6 string
}

// StorageConfig configures the storage zone flow generator.
type StorageConfig struct {
	// StorageSubnet is the storage subnet (used for isolation rules).
	StorageSubnet string
}

// ManagementConfig configures the management zone flow generator.
type ManagementConfig struct {
	// ManagementSubnet is the OOB subnet (used for isolation rules).
	ManagementSubnet string
}

// generator is the internal function type for a per-zone flow template.
type generator func(portID string, vlanID uint16) []FlowRule

// NetworkSummary holds the VLAN and subnets for a zone's primary network.
// It is the value type for MatrixRuleConfig.NetworksByZone and is exported
// so callers (e.g. ZoneFlowManager) can build the map without reflection.
type NetworkSummary struct {
	// VLAN is the IEEE 802.1Q segment ID for this zone's primary network.
	VLAN uint16

	// Subnet is the CIDR-notation IPv4 prefix for the zone's primary subnet
	// (e.g. "198.18.0.0/24"). Used as nw_dst in OpenFlow match strings.
	Subnet string

	// Subnet6 is the CIDR-notation IPv6 prefix for the same network when it
	// is dual-stack (e.g. "2602:f5bb:1::/64"), used as ipv6_dst. Empty for
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
