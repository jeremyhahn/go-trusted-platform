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

package policy

import (
	"fmt"
	"net"
	"strings"
)

const (
	// Protocol numbers
	ProtoTCP  uint8 = 6
	ProtoUDP  uint8 = 17
	ProtoICMP uint8 = 1

	// Ethernet types
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeARP  uint16 = 0x0806

	// Well-known ports
	PortDHCPClient uint16 = 68
	PortDHCPServer uint16 = 67
	PortDNS        uint16 = 53
	PortDNSAlt1    uint16 = 8053
	PortDNSAlt2    uint16 = 9053
	PortHTTP       uint16 = 80
	PortHTTPS      uint16 = 443
	PortHTTPSAlt1  uint16 = 8443
	PortHTTPSAlt2  uint16 = 9443
)

// ProvisioningFlowConfig configures the provisioning flow generator
type ProvisioningFlowConfig struct {
	// ACMEServerIPs are IPs of the ACME/platform server
	ACMEServerIPs []net.IP

	// DNSServerIPs are IPs of DNS servers to allow
	DNSServerIPs []net.IP

	// ProvisioningVLAN is the VLAN for provisioning traffic
	ProvisioningVLAN uint16

	// PackageRepoIPs are IPs of package repository servers (optional)
	// If empty, all HTTP/HTTPS traffic is allowed (for public repos)
	PackageRepoIPs []net.IP

	// Gateway is the gateway IP for provisioning network
	Gateway net.IP

	// AllowICMP enables ICMP for debugging (default: false)
	AllowICMP bool
}

// ProvisioningFlowGenerator generates flows for ports in provisioning state
type ProvisioningFlowGenerator struct {
	config    *ProvisioningFlowConfig
	generator *RuleGenerator
}

// NewProvisioningFlowGenerator creates a new provisioning flow generator
func NewProvisioningFlowGenerator(config *ProvisioningFlowConfig) *ProvisioningFlowGenerator {
	if config == nil {
		config = &ProvisioningFlowConfig{}
	}

	return &ProvisioningFlowGenerator{
		config:    config,
		generator: NewRuleGenerator(),
	}
}

// GenerateFlows generates all provisioning flows for a port
func (g *ProvisioningFlowGenerator) GenerateFlows(portID string, portMAC string) []FlowRule {
	var flows []FlowRule

	// ARP must be allowed for address resolution
	flows = append(flows, g.generateARPRules(portID)...)

	// DHCP for IP assignment
	flows = append(flows, g.generateDHCPRules(portID)...)

	// DNS to configured servers
	flows = append(flows, g.generateDNSRules(portID)...)

	// HTTPS to ACME server for certificate enrollment
	flows = append(flows, g.generateACMERules(portID)...)

	// HTTP/HTTPS for package repositories
	flows = append(flows, g.generatePackageRepoRules(portID)...)

	// ICMP if configured
	if g.config.AllowICMP {
		flows = append(flows, g.generateICMPRules(portID)...)
	}

	// Default drop rule (lowest priority)
	flows = append(flows, g.generateDefaultDropRule(portID))

	return flows
}

// generateARPRules allows ARP for address resolution
func (g *ProvisioningFlowGenerator) generateARPRules(portID string) []FlowRule {
	match := FlowMatch{
		InPort:  portID,
		EthType: EtherTypeARP,
	}

	if g.config.ProvisioningVLAN > 0 {
		match.VLANVid = g.config.ProvisioningVLAN
	}

	return []FlowRule{
		{
			Table:    g.generator.DefaultTable,
			Priority: g.generator.BasePriority + 900,
			Match:    g.generator.buildMatch(match),
			Actions:  "normal",
		},
	}
}

// generateDHCPRules allows DHCP for IP assignment
func (g *ProvisioningFlowGenerator) generateDHCPRules(portID string) []FlowRule {
	var rules []FlowRule

	// Allow DHCP client to server (68 -> 67)
	clientToServer := FlowMatch{
		InPort:  portID,
		EthType: EtherTypeIPv4,
		IPProto: ProtoUDP,
		UDPSrc:  PortDHCPClient,
		UDPDst:  PortDHCPServer,
	}

	if g.config.ProvisioningVLAN > 0 {
		clientToServer.VLANVid = g.config.ProvisioningVLAN
	}

	rules = append(rules, FlowRule{
		Table:    g.generator.DefaultTable,
		Priority: g.generator.BasePriority + 850,
		Match:    g.generator.buildMatch(clientToServer),
		Actions:  "normal",
	})

	// Allow DHCP server to client (67 -> 68) - for responses
	serverToClient := FlowMatch{
		EthType: EtherTypeIPv4,
		IPProto: ProtoUDP,
		UDPSrc:  PortDHCPServer,
		UDPDst:  PortDHCPClient,
	}

	if g.config.ProvisioningVLAN > 0 {
		serverToClient.VLANVid = g.config.ProvisioningVLAN
	}

	rules = append(rules, FlowRule{
		Table:    g.generator.DefaultTable,
		Priority: g.generator.BasePriority + 850,
		Match:    g.generator.buildMatch(serverToClient),
		Actions:  "normal",
	})

	return rules
}

// generateDNSRules allows DNS to configured servers
func (g *ProvisioningFlowGenerator) generateDNSRules(portID string) []FlowRule {
	var rules []FlowRule

	dnsPorts := []uint16{PortDNS, PortDNSAlt1, PortDNSAlt2}

	// If no specific DNS servers configured, allow all DNS traffic
	if len(g.config.DNSServerIPs) == 0 {
		for _, port := range dnsPorts {
			// UDP DNS
			udpMatch := FlowMatch{
				InPort:  portID,
				EthType: EtherTypeIPv4,
				IPProto: ProtoUDP,
				UDPDst:  port,
			}

			if g.config.ProvisioningVLAN > 0 {
				udpMatch.VLANVid = g.config.ProvisioningVLAN
			}

			rules = append(rules, FlowRule{
				Table:    g.generator.DefaultTable,
				Priority: g.generator.BasePriority + 800,
				Match:    g.generator.buildMatch(udpMatch),
				Actions:  "normal",
			})

			// TCP DNS
			tcpMatch := FlowMatch{
				InPort:  portID,
				EthType: EtherTypeIPv4,
				IPProto: ProtoTCP,
				TCPDst:  port,
			}

			if g.config.ProvisioningVLAN > 0 {
				tcpMatch.VLANVid = g.config.ProvisioningVLAN
			}

			rules = append(rules, FlowRule{
				Table:    g.generator.DefaultTable,
				Priority: g.generator.BasePriority + 800,
				Match:    g.generator.buildMatch(tcpMatch),
				Actions:  "normal",
			})
		}
		return rules
	}

	// Allow DNS to specific servers
	for _, dnsIP := range g.config.DNSServerIPs {
		for _, port := range dnsPorts {
			// UDP DNS
			udpMatch := FlowMatch{
				InPort:  portID,
				EthType: EtherTypeIPv4,
				IPProto: ProtoUDP,
				IPv4Dst: dnsIP.String(),
				UDPDst:  port,
			}

			if g.config.ProvisioningVLAN > 0 {
				udpMatch.VLANVid = g.config.ProvisioningVLAN
			}

			rules = append(rules, FlowRule{
				Table:    g.generator.DefaultTable,
				Priority: g.generator.BasePriority + 800,
				Match:    g.generator.buildMatch(udpMatch),
				Actions:  "normal",
			})

			// TCP DNS
			tcpMatch := FlowMatch{
				InPort:  portID,
				EthType: EtherTypeIPv4,
				IPProto: ProtoTCP,
				IPv4Dst: dnsIP.String(),
				TCPDst:  port,
			}

			if g.config.ProvisioningVLAN > 0 {
				tcpMatch.VLANVid = g.config.ProvisioningVLAN
			}

			rules = append(rules, FlowRule{
				Table:    g.generator.DefaultTable,
				Priority: g.generator.BasePriority + 800,
				Match:    g.generator.buildMatch(tcpMatch),
				Actions:  "normal",
			})
		}
	}

	return rules
}

// generateACMERules allows HTTPS to ACME server
func (g *ProvisioningFlowGenerator) generateACMERules(portID string) []FlowRule {
	var rules []FlowRule

	httpsPorts := []uint16{PortHTTPS, PortHTTPSAlt1, PortHTTPSAlt2}

	// If no specific ACME servers configured, allow all HTTPS
	if len(g.config.ACMEServerIPs) == 0 {
		for _, port := range httpsPorts {
			match := FlowMatch{
				InPort:  portID,
				EthType: EtherTypeIPv4,
				IPProto: ProtoTCP,
				TCPDst:  port,
			}

			if g.config.ProvisioningVLAN > 0 {
				match.VLANVid = g.config.ProvisioningVLAN
			}

			rules = append(rules, FlowRule{
				Table:    g.generator.DefaultTable,
				Priority: g.generator.BasePriority + 750,
				Match:    g.generator.buildMatch(match),
				Actions:  "normal",
			})
		}
		return rules
	}

	// Allow HTTPS to specific ACME servers
	for _, acmeIP := range g.config.ACMEServerIPs {
		for _, port := range httpsPorts {
			match := FlowMatch{
				InPort:  portID,
				EthType: EtherTypeIPv4,
				IPProto: ProtoTCP,
				IPv4Dst: acmeIP.String(),
				TCPDst:  port,
			}

			if g.config.ProvisioningVLAN > 0 {
				match.VLANVid = g.config.ProvisioningVLAN
			}

			rules = append(rules, FlowRule{
				Table:    g.generator.DefaultTable,
				Priority: g.generator.BasePriority + 750,
				Match:    g.generator.buildMatch(match),
				Actions:  "normal",
			})
		}
	}

	return rules
}

// generatePackageRepoRules allows HTTP/HTTPS for package repos
func (g *ProvisioningFlowGenerator) generatePackageRepoRules(portID string) []FlowRule {
	var rules []FlowRule

	repoPorts := []uint16{PortHTTP, PortHTTPS}

	// If no specific package repos configured, allow all HTTP/HTTPS
	if len(g.config.PackageRepoIPs) == 0 {
		for _, port := range repoPorts {
			match := FlowMatch{
				InPort:  portID,
				EthType: EtherTypeIPv4,
				IPProto: ProtoTCP,
				TCPDst:  port,
			}

			if g.config.ProvisioningVLAN > 0 {
				match.VLANVid = g.config.ProvisioningVLAN
			}

			rules = append(rules, FlowRule{
				Table:    g.generator.DefaultTable,
				Priority: g.generator.BasePriority + 700,
				Match:    g.generator.buildMatch(match),
				Actions:  "normal",
			})
		}
		return rules
	}

	// Allow HTTP/HTTPS to specific package repositories
	for _, repoIP := range g.config.PackageRepoIPs {
		for _, port := range repoPorts {
			match := FlowMatch{
				InPort:  portID,
				EthType: EtherTypeIPv4,
				IPProto: ProtoTCP,
				IPv4Dst: repoIP.String(),
				TCPDst:  port,
			}

			if g.config.ProvisioningVLAN > 0 {
				match.VLANVid = g.config.ProvisioningVLAN
			}

			rules = append(rules, FlowRule{
				Table:    g.generator.DefaultTable,
				Priority: g.generator.BasePriority + 700,
				Match:    g.generator.buildMatch(match),
				Actions:  "normal",
			})
		}
	}

	return rules
}

// generateICMPRules allows ICMP if configured
func (g *ProvisioningFlowGenerator) generateICMPRules(portID string) []FlowRule {
	// ICMP egress (from port)
	egressMatch := FlowMatch{
		InPort:  portID,
		EthType: EtherTypeIPv4,
		IPProto: ProtoICMP,
	}

	if g.config.ProvisioningVLAN > 0 {
		egressMatch.VLANVid = g.config.ProvisioningVLAN
	}

	// ICMP ingress (to port) - for ping responses
	ingressMatch := FlowMatch{
		EthType: EtherTypeIPv4,
		IPProto: ProtoICMP,
	}

	if g.config.ProvisioningVLAN > 0 {
		ingressMatch.VLANVid = g.config.ProvisioningVLAN
	}

	return []FlowRule{
		{
			Table:    g.generator.DefaultTable,
			Priority: g.generator.BasePriority + 600,
			Match:    g.generator.buildMatch(egressMatch),
			Actions:  "normal",
		},
		{
			Table:    g.generator.DefaultTable,
			Priority: g.generator.BasePriority + 600,
			Match:    g.generator.buildMatch(ingressMatch),
			Actions:  "normal",
		},
	}
}

// generateDefaultDropRule creates the default drop rule (lowest priority)
func (g *ProvisioningFlowGenerator) generateDefaultDropRule(portID string) FlowRule {
	match := FlowMatch{
		InPort: portID,
	}

	if g.config.ProvisioningVLAN > 0 {
		match.VLANVid = g.config.ProvisioningVLAN
	}

	return FlowRule{
		Table:    g.generator.DefaultTable,
		Priority: g.generator.BasePriority - 100, // Lower than all other rules
		Match:    g.generator.buildMatch(match),
		Actions:  "drop",
	}
}

// ValidateConfig validates the provisioning flow configuration
func (config *ProvisioningFlowConfig) ValidateConfig() error {
	if config == nil {
		return ErrInvalidConfiguration
	}

	// Validate IP addresses
	for i, ip := range config.ACMEServerIPs {
		if ip == nil {
			return &MessageError{Msg: fmt.Sprintf("ACME server IP at index %d is nil", i)}
		}
	}

	for i, ip := range config.DNSServerIPs {
		if ip == nil {
			return &MessageError{Msg: fmt.Sprintf("DNS server IP at index %d is nil", i)}
		}
	}

	for i, ip := range config.PackageRepoIPs {
		if ip == nil {
			return &MessageError{Msg: fmt.Sprintf("package repo IP at index %d is nil", i)}
		}
	}

	if config.Gateway != nil && config.Gateway.IsUnspecified() {
		return &MessageError{Msg: "gateway IP is unspecified"}
	}

	return nil
}

// String returns a human-readable summary of the configuration
func (config *ProvisioningFlowConfig) String() string {
	var builder strings.Builder

	builder.WriteString("ProvisioningFlowConfig{\n")

	if len(config.ACMEServerIPs) > 0 {
		fmt.Fprintf(&builder, "  ACMEServerIPs: %v\n", config.ACMEServerIPs)
	}

	if len(config.DNSServerIPs) > 0 {
		fmt.Fprintf(&builder, "  DNSServerIPs: %v\n", config.DNSServerIPs)
	}

	if config.ProvisioningVLAN > 0 {
		fmt.Fprintf(&builder, "  ProvisioningVLAN: %d\n", config.ProvisioningVLAN)
	}

	if len(config.PackageRepoIPs) > 0 {
		fmt.Fprintf(&builder, "  PackageRepoIPs: %v\n", config.PackageRepoIPs)
	}

	if config.Gateway != nil {
		fmt.Fprintf(&builder, "  Gateway: %s\n", config.Gateway)
	}

	fmt.Fprintf(&builder, "  AllowICMP: %t\n", config.AllowICMP)
	builder.WriteString("}")

	return builder.String()
}
