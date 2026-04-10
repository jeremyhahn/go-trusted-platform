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

// Package policy provides network flow policy generators for SDN-based network access control.
// The quarantine flow generator creates OpenFlow rules that isolate devices in a restricted
// VLAN with limited connectivity for security scanning and remediation.
//
// # Quarantine Flow Generator
//
// The QuarantineFlowGenerator implements a network quarantine policy that allows:
//   - ARP for address resolution
//   - DHCP for IP assignment in the quarantine VLAN
//   - DNS queries to a specified internal DNS server
//   - Bidirectional communication with security scanning servers
//   - Port-specific access to patch/remediation servers
//   - HTTP/HTTPS access to a notification web server
//   - All other traffic is dropped by default
//
// # Example Usage
//
//	config := &QuarantineFlowConfig{
//	    QuarantineVLAN:       100,
//	    ScanningServerIPs:    []net.IP{net.ParseIP("10.0.0.10")},
//	    RemediationServerIPs: []net.IP{net.ParseIP("10.0.0.20")},
//	    DNSServerIP:          net.ParseIP("10.0.0.1"),
//	    NotificationServerIP: net.ParseIP("10.0.0.30"),
//	    Gateway:              net.ParseIP("10.0.0.254"),
//	    AllowedPorts:         []uint16{443, 8443},
//	}
//
//	generator := NewQuarantineFlowGenerator(config)
//	flows := generator.GenerateFlows("eth0", "00:11:22:33:44:55")
//
//	// Install flows using OpenFlow controller
//	for _, flow := range flows {
//	    controller.InstallFlow("br0", flow.Priority, flow.Match, flow.Actions)
//	}
//
// # Security Model
//
// The quarantine network isolates potentially compromised or non-compliant devices
// while allowing them to:
//   1. Receive security scans to identify vulnerabilities
//   2. Download patches from remediation servers
//   3. Access a notification portal to inform users
//   4. Perform basic network operations (ARP, DHCP, DNS)
//
// All other network access is denied, preventing lateral movement and data exfiltration.
//
// # Flow Priority
//
// Quarantine flows are prioritized to ensure correct packet handling:
//   - ARP (highest priority): Essential for network communication
//   - DHCP: Required for IP address assignment
//   - DNS: Controlled name resolution to internal server only
//   - Scanning Servers: Allow security assessments
//   - Remediation Servers: Allow patch downloads
//   - Notification Server: User awareness and self-service
//   - Default Drop (lowest priority): Catch-all deny rule

package policy

import (
	"fmt"
	"net"
)

const (
	// Ethernet protocol types
	etherTypeARP  = 0x0806
	etherTypeIPv4 = 0x0800

	// IP protocol numbers
	ipProtoTCP = 6
	ipProtoUDP = 17

	// Well-known ports
	portDHCPClient = 68
	portDHCPServer = 67
	portDNS        = 53
	portHTTP       = 80
	portHTTPS      = 443

	// Priority offsets for quarantine rules
	priorityARPOffset          = 900
	priorityDHCPOffset         = 850
	priorityDNSOffset          = 800
	priorityScanningOffset     = 700
	priorityRemediationOffset  = 650
	priorityNotificationOffset = 600
	priorityDropOffset         = 100
)

// QuarantineFlowConfig configures the quarantine flow generator
type QuarantineFlowConfig struct {
	// QuarantineVLAN is the isolated VLAN for quarantined devices
	QuarantineVLAN uint16

	// ScanningServerIPs are IPs of security scanning servers
	ScanningServerIPs []net.IP

	// RemediationServerIPs are IPs of patch/remediation servers
	RemediationServerIPs []net.IP

	// DNSServerIP is the internal DNS server IP
	DNSServerIP net.IP

	// NotificationServerIP is the quarantine notification web server
	NotificationServerIP net.IP

	// Gateway is the gateway IP for quarantine network
	Gateway net.IP

	// AllowedPorts are additional ports to allow to remediation servers
	AllowedPorts []uint16
}

// QuarantineFlowGenerator generates flows for ports in quarantine state
type QuarantineFlowGenerator struct {
	config    *QuarantineFlowConfig
	generator *RuleGenerator
}

// NewQuarantineFlowGenerator creates a new quarantine flow generator
func NewQuarantineFlowGenerator(config *QuarantineFlowConfig) *QuarantineFlowGenerator {
	return &QuarantineFlowGenerator{
		config:    config,
		generator: NewRuleGenerator(),
	}
}

// GenerateFlows generates all quarantine flows for a port
func (g *QuarantineFlowGenerator) GenerateFlows(portID string, portMAC string) []FlowRule {
	var flows []FlowRule

	// Allow ARP for address resolution
	flows = append(flows, g.generateARPRules(portID)...)

	// Allow DHCP for IP assignment in quarantine VLAN
	flows = append(flows, g.generateDHCPRules(portID)...)

	// Allow DNS to internal server only
	flows = append(flows, g.generateDNSRules(portID)...)

	// Allow access to scanning servers
	flows = append(flows, g.generateScanningRules(portID)...)

	// Allow access to remediation servers
	flows = append(flows, g.generateRemediationRules(portID)...)

	// Allow access to notification server (HTTP/HTTPS)
	flows = append(flows, g.generateNotificationRules(portID)...)

	// Default drop rule (lowest priority)
	flows = append(flows, g.generateDefaultDropRule(portID))

	return flows
}

// generateARPRules allows ARP for address resolution
func (g *QuarantineFlowGenerator) generateARPRules(portID string) []FlowRule {
	match := FlowMatch{
		InPort:  portID,
		EthType: etherTypeARP,
	}

	return []FlowRule{
		{
			Table:    g.generator.DefaultTable,
			Priority: g.generator.BasePriority + priorityARPOffset,
			Match:    g.generator.buildMatch(match),
			Actions:  "normal",
		},
	}
}

// generateDHCPRules allows DHCP for IP assignment in quarantine VLAN
func (g *QuarantineFlowGenerator) generateDHCPRules(portID string) []FlowRule {
	var rules []FlowRule

	// DHCP client request (68 -> 67)
	clientMatch := FlowMatch{
		InPort:  portID,
		EthType: etherTypeIPv4,
		IPProto: ipProtoUDP,
		UDPSrc:  portDHCPClient,
		UDPDst:  portDHCPServer,
	}

	rules = append(rules, FlowRule{
		Table:    g.generator.DefaultTable,
		Priority: g.generator.BasePriority + priorityDHCPOffset,
		Match:    g.generator.buildMatch(clientMatch),
		Actions:  "normal",
	})

	// DHCP server response (67 -> 68)
	serverMatch := FlowMatch{
		InPort:  portID,
		EthType: etherTypeIPv4,
		IPProto: ipProtoUDP,
		UDPSrc:  portDHCPServer,
		UDPDst:  portDHCPClient,
	}

	rules = append(rules, FlowRule{
		Table:    g.generator.DefaultTable,
		Priority: g.generator.BasePriority + priorityDHCPOffset,
		Match:    g.generator.buildMatch(serverMatch),
		Actions:  "normal",
	})

	return rules
}

// generateDNSRules allows DNS to internal server only
func (g *QuarantineFlowGenerator) generateDNSRules(portID string) []FlowRule {
	if g.config.DNSServerIP == nil {
		return nil
	}

	var rules []FlowRule

	// DNS query (UDP 53)
	queryMatch := FlowMatch{
		InPort:  portID,
		EthType: etherTypeIPv4,
		IPProto: ipProtoUDP,
		IPv4Dst: g.config.DNSServerIP.String(),
		UDPDst:  portDNS,
	}

	rules = append(rules, FlowRule{
		Table:    g.generator.DefaultTable,
		Priority: g.generator.BasePriority + priorityDNSOffset,
		Match:    g.generator.buildMatch(queryMatch),
		Actions:  "normal",
	})

	// DNS response
	responseMatch := FlowMatch{
		InPort:  portID,
		EthType: etherTypeIPv4,
		IPProto: ipProtoUDP,
		IPv4Src: g.config.DNSServerIP.String(),
		UDPSrc:  portDNS,
	}

	rules = append(rules, FlowRule{
		Table:    g.generator.DefaultTable,
		Priority: g.generator.BasePriority + priorityDNSOffset,
		Match:    g.generator.buildMatch(responseMatch),
		Actions:  "normal",
	})

	return rules
}

// generateScanningRules allows access to scanning servers
func (g *QuarantineFlowGenerator) generateScanningRules(portID string) []FlowRule {
	if len(g.config.ScanningServerIPs) == 0 {
		return nil
	}

	var rules []FlowRule

	for _, serverIP := range g.config.ScanningServerIPs {
		// Allow all traffic to/from scanning servers
		toServerMatch := FlowMatch{
			InPort:  portID,
			EthType: etherTypeIPv4,
			IPv4Dst: serverIP.String(),
		}

		rules = append(rules, FlowRule{
			Table:    g.generator.DefaultTable,
			Priority: g.generator.BasePriority + priorityScanningOffset,
			Match:    g.generator.buildMatch(toServerMatch),
			Actions:  "normal",
		})

		fromServerMatch := FlowMatch{
			InPort:  portID,
			EthType: etherTypeIPv4,
			IPv4Src: serverIP.String(),
		}

		rules = append(rules, FlowRule{
			Table:    g.generator.DefaultTable,
			Priority: g.generator.BasePriority + priorityScanningOffset,
			Match:    g.generator.buildMatch(fromServerMatch),
			Actions:  "normal",
		})
	}

	return rules
}

// generateRemediationRules allows access to remediation servers
func (g *QuarantineFlowGenerator) generateRemediationRules(portID string) []FlowRule {
	if len(g.config.RemediationServerIPs) == 0 {
		return nil
	}

	var rules []FlowRule

	// Default ports if none specified
	ports := g.config.AllowedPorts
	if len(ports) == 0 {
		ports = []uint16{portHTTPS} // Default to HTTPS only
	}

	for _, serverIP := range g.config.RemediationServerIPs {
		// Allow specific ports to remediation servers
		for _, port := range ports {
			// Outbound to remediation server
			outboundMatch := FlowMatch{
				InPort:  portID,
				EthType: etherTypeIPv4,
				IPProto: ipProtoTCP,
				IPv4Dst: serverIP.String(),
				TCPDst:  port,
			}

			rules = append(rules, FlowRule{
				Table:    g.generator.DefaultTable,
				Priority: g.generator.BasePriority + priorityRemediationOffset,
				Match:    g.generator.buildMatch(outboundMatch),
				Actions:  "normal",
			})

			// Inbound from remediation server
			inboundMatch := FlowMatch{
				InPort:  portID,
				EthType: etherTypeIPv4,
				IPProto: ipProtoTCP,
				IPv4Src: serverIP.String(),
				TCPSrc:  port,
			}

			rules = append(rules, FlowRule{
				Table:    g.generator.DefaultTable,
				Priority: g.generator.BasePriority + priorityRemediationOffset,
				Match:    g.generator.buildMatch(inboundMatch),
				Actions:  "normal",
			})
		}
	}

	return rules
}

// generateNotificationRules allows access to notification server (HTTP/HTTPS)
func (g *QuarantineFlowGenerator) generateNotificationRules(portID string) []FlowRule {
	if g.config.NotificationServerIP == nil {
		return nil
	}

	var rules []FlowRule
	notificationPorts := []uint16{portHTTP, portHTTPS}

	for _, port := range notificationPorts {
		// Outbound to notification server
		outboundMatch := FlowMatch{
			InPort:  portID,
			EthType: etherTypeIPv4,
			IPProto: ipProtoTCP,
			IPv4Dst: g.config.NotificationServerIP.String(),
			TCPDst:  port,
		}

		rules = append(rules, FlowRule{
			Table:    g.generator.DefaultTable,
			Priority: g.generator.BasePriority + priorityNotificationOffset,
			Match:    g.generator.buildMatch(outboundMatch),
			Actions:  "normal",
		})

		// Inbound from notification server
		inboundMatch := FlowMatch{
			InPort:  portID,
			EthType: etherTypeIPv4,
			IPProto: ipProtoTCP,
			IPv4Src: g.config.NotificationServerIP.String(),
			TCPSrc:  port,
		}

		rules = append(rules, FlowRule{
			Table:    g.generator.DefaultTable,
			Priority: g.generator.BasePriority + priorityNotificationOffset,
			Match:    g.generator.buildMatch(inboundMatch),
			Actions:  "normal",
		})
	}

	return rules
}

// generateDefaultDropRule creates the default drop rule with lowest priority
func (g *QuarantineFlowGenerator) generateDefaultDropRule(portID string) FlowRule {
	match := FlowMatch{
		InPort: portID,
	}

	return FlowRule{
		Table:    g.generator.DefaultTable,
		Priority: g.generator.BasePriority + priorityDropOffset,
		Match:    g.generator.buildMatch(match),
		Actions:  "drop",
		Cookie:   fmt.Sprintf("quarantine:%s", portID),
	}
}
