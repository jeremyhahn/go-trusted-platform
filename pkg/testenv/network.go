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

// Package testenv provides isolated test network environments for VM testing.
// It creates dedicated bridge networks with NAT for internet access, allowing
// multiple VMs to communicate in an isolated environment.
package testenv

import (
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// NetworkConfig holds the isolated test network configuration
type NetworkConfig struct {
	// BridgeName is the name of the bridge interface (e.g., "tp-br")
	BridgeName string

	// ServerTapName is the TAP device name for the server VM
	ServerTapName string

	// ClientTapName is the TAP device name for the client VM
	ClientTapName string

	// GatewayIP is the bridge gateway IP address (host side)
	GatewayIP net.IP

	// ServerIP is the server VM's internal/private IP address
	ServerIP net.IP

	// ServerPublicIP is the server VM's public/external IP address for DNS zones
	// In real deployments, this would be the internet-facing IP
	// For testing, we use TEST-NET-1 (192.0.2.0/24) addresses
	ServerPublicIP net.IP

	// ClientIP is the client VM's internal/private IP address
	ClientIP net.IP

	// ClientPublicIP is the client VM's public/external IP address for DNS zones
	ClientPublicIP net.IP

	// Subnet is the network subnet (e.g., 10.99.99.0/28)
	Subnet *net.IPNet

	// Domain is the internal DNS domain
	Domain string

	// ServerMAC is the MAC address for the server VM
	ServerMAC string

	// ClientMAC is the MAC address for the client VM
	ClientMAC string
}

// DefaultNetworkConfig returns the default isolated network configuration
// using the 10.99.99.0/28 subnet for client-server testing.
// Public IPs use TEST-NET-1 (192.0.2.0/24) for simulating internet-facing addresses.
func DefaultNetworkConfig() *NetworkConfig {
	_, subnet, _ := net.ParseCIDR("10.99.99.0/28")
	return &NetworkConfig{
		BridgeName:     "tp-br",
		ServerTapName:  "tap-tp-server",
		ClientTapName:  "tap-tp-client",
		GatewayIP:      net.ParseIP("10.99.99.1"),
		ServerIP:       net.ParseIP("10.99.99.2"),
		ServerPublicIP: net.ParseIP("192.0.2.2"), // TEST-NET-1 for public DNS zone
		ClientIP:       net.ParseIP("10.99.99.3"),
		ClientPublicIP: net.ParseIP("192.0.2.3"), // TEST-NET-1 for public DNS zone
		Subnet:         subnet,
		Domain:         "example.internal",
		ServerMAC:      "52:54:00:99:00:02",
		ClientMAC:      "52:54:00:99:00:03",
	}
}

// Validate validates the network configuration
func (c *NetworkConfig) Validate() error {
	if c.BridgeName == "" {
		return &MessageError{Msg: "bridge name is required"}
	}
	if c.ServerTapName == "" {
		return &MessageError{Msg: "server TAP name is required"}
	}
	if c.ClientTapName == "" {
		return &MessageError{Msg: "client TAP name is required"}
	}
	if c.GatewayIP == nil {
		return &MessageError{Msg: "gateway IP is required"}
	}
	if c.ServerIP == nil {
		return &MessageError{Msg: "server IP is required"}
	}
	if c.ClientIP == nil {
		return &MessageError{Msg: "client IP is required"}
	}
	if c.Subnet == nil {
		return &MessageError{Msg: "subnet is required"}
	}

	// Validate IPs are within subnet
	if !c.Subnet.Contains(c.GatewayIP) {
		return &MessageError{Msg: fmt.Sprintf("gateway IP %s is not within subnet %s", c.GatewayIP, c.Subnet)}
	}
	if !c.Subnet.Contains(c.ServerIP) {
		return &MessageError{Msg: fmt.Sprintf("server IP %s is not within subnet %s", c.ServerIP, c.Subnet)}
	}
	if !c.Subnet.Contains(c.ClientIP) {
		return &MessageError{Msg: fmt.Sprintf("client IP %s is not within subnet %s", c.ClientIP, c.Subnet)}
	}

	return nil
}

// SubnetMask returns the subnet mask as a dotted decimal string
func (c *NetworkConfig) SubnetMask() string {
	mask := c.Subnet.Mask
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

// SubnetCIDR returns the subnet in CIDR notation
func (c *NetworkConfig) SubnetCIDR() string {
	return c.Subnet.String()
}

// NetworkPhase represents the network access phase for a port.
type NetworkPhase int

const (
	// NetworkPhaseUnconnected indicates the port is not yet connected
	NetworkPhaseUnconnected NetworkPhase = iota

	// NetworkPhaseProvisioning indicates limited access for enrollment
	NetworkPhaseProvisioning

	// NetworkPhaseAdmitted indicates full access for an admitted device
	// (post-enrollment operational)
	NetworkPhaseAdmitted

	// NetworkPhaseQuarantine indicates isolated access for remediation
	NetworkPhaseQuarantine

	// NetworkPhaseBlocked indicates completely blocked access
	NetworkPhaseBlocked
)

// String returns the string representation of NetworkPhase
func (p NetworkPhase) String() string {
	switch p {
	case NetworkPhaseUnconnected:
		return "unconnected"
	case NetworkPhaseProvisioning:
		return "provisioning"
	case NetworkPhaseAdmitted:
		return "admitted"
	case NetworkPhaseQuarantine:
		return "quarantine"
	case NetworkPhaseBlocked:
		return "blocked"
	default:
		return fmt.Sprintf("unknown(%d)", p)
	}
}

// PortPhaseInfo tracks the phase of each port
type PortPhaseInfo struct {
	Phase       NetworkPhase
	VLAN        uint16
	Reason      string // For quarantine/blocked states
	Certificate *x509.Certificate
	LastChange  time.Time
}

// IsolatedNetwork defines the interface for managing isolated test networks
type IsolatedNetwork interface {
	// Setup creates the isolated network (bridge, TAPs, NAT)
	Setup() error

	// EnsureRules verifies and re-applies NAT/forwarding rules if needed.
	// This is used when reusing an existing network to ensure internet access works.
	EnsureRules() error

	// Cleanup removes all network resources
	Cleanup() error

	// Config returns the network configuration
	Config() *NetworkConfig

	// ServerTapName returns the TAP device name for the server VM
	ServerTapName() string

	// ClientTapName returns the TAP device name for the client VM
	ClientTapName() string

	// SetPhase transitions a port to a specific network phase
	SetPhase(portID string, phase NetworkPhase) error

	// GetPhase returns the current phase for a port
	GetPhase(portID string) NetworkPhase

	// TransitionToAdmitted moves a port from provisioning to the admitted phase
	TransitionToAdmitted(portID string, cert *x509.Certificate) error

	// QuarantinePort moves a port to quarantine VLAN
	QuarantinePort(portID string, reason string) error

	// UnquarantinePort moves a port back to the admitted phase
	UnquarantinePort(portID string) error

	// BlockPort completely blocks a port (DROP all traffic)
	BlockPort(portID string, reason string) error

	// UnblockPort unblocks a port and returns it to provisioning
	UnblockPort(portID string) error
}
