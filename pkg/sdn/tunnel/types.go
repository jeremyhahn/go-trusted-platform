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

package tunnel

import "net"

// Default tunnel configuration values.
const (
	// DefaultMTU is the default MTU for GRE tunnels (1500 - 20 IP - 4 GRE = 1476,
	// but 1400 provides headroom for encapsulation + optional GRE key).
	DefaultMTU = 1400

	// DefaultTTL is the default IP TTL for tunnel packets.
	DefaultTTL = 64

	// MinMTU is the minimum valid MTU.
	MinMTU = 68

	// MaxMTU is the maximum valid MTU.
	MaxMTU = 65535

	// MinTTL is the minimum valid TTL.
	MinTTL = 1

	// MaxTTL is the maximum valid TTL.
	MaxTTL = 255

	// TunnelTypeGRE is a GRE tunnel over IPv4.
	TunnelTypeGRE = "gre"

	// TunnelTypeGRE6 is a GRE tunnel over IPv6.
	TunnelTypeGRE6 = "gre6"

	// TunnelTypeIPIP is an IP-in-IP tunnel.
	TunnelTypeIPIP = "ipip"
)

// TunnelConfig holds the configuration for a GRE/IPIP tunnel.
type TunnelConfig struct {
	// Name is the tunnel interface name (max 15 chars).
	Name string `yaml:"name" json:"name"`

	// Type is the tunnel type: "gre", "gre6", or "ipip".
	Type string `yaml:"type" json:"type"`

	// Local is the local endpoint IP address.
	Local string `yaml:"local" json:"local"`

	// Remote is the remote endpoint IP address.
	Remote string `yaml:"remote" json:"remote"`

	// TunnelIP is the tunnel interface IPv4 address in CIDR notation.
	TunnelIP string `yaml:"tunnel-ip" json:"tunnel_ip"`

	// TunnelIPv6 is the tunnel interface IPv6 address in CIDR notation (optional).
	TunnelIPv6 string `yaml:"tunnel-ipv6,omitempty" json:"tunnel_ipv6,omitempty"`

	// MTU is the tunnel interface MTU (default 1400).
	MTU int `yaml:"mtu,omitempty" json:"mtu,omitempty"`

	// TTL is the IP TTL for tunnel packets (default 64).
	TTL int `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// Key is the optional GRE key for traffic isolation.
	Key uint32 `yaml:"key,omitempty" json:"key,omitempty"`
}

// Validate checks if the tunnel configuration is valid.
func (c *TunnelConfig) Validate() error {
	if c.Name == "" {
		return &ErrInvalidTunnelConfig{Reason: "name is required"}
	}
	if len(c.Name) > 15 {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "name exceeds 15 characters"}
	}
	if c.Type == "" {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "type is required"}
	}
	if c.Type != TunnelTypeGRE && c.Type != TunnelTypeGRE6 && c.Type != TunnelTypeIPIP {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "type must be gre, gre6, or ipip"}
	}
	if c.Local == "" {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "local endpoint is required"}
	}
	if net.ParseIP(c.Local) == nil {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "local is not a valid IP address"}
	}
	if c.Remote == "" {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "remote endpoint is required"}
	}
	if net.ParseIP(c.Remote) == nil {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "remote is not a valid IP address"}
	}
	if c.TunnelIP == "" {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "tunnel-ip is required"}
	}
	if _, _, err := net.ParseCIDR(c.TunnelIP); err != nil {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "tunnel-ip is not valid CIDR"}
	}
	if c.TunnelIPv6 != "" {
		if _, _, err := net.ParseCIDR(c.TunnelIPv6); err != nil {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "tunnel-ipv6 is not valid CIDR"}
		}
	}
	if c.MTU != 0 && (c.MTU < MinMTU || c.MTU > MaxMTU) {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "MTU out of range"}
	}
	if c.TTL != 0 && (c.TTL < MinTTL || c.TTL > MaxTTL) {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "TTL out of range"}
	}
	return nil
}

// effectiveMTU returns the configured MTU or the default.
func (c *TunnelConfig) effectiveMTU() int {
	if c.MTU > 0 {
		return c.MTU
	}
	return DefaultMTU
}

// effectiveTTL returns the configured TTL or the default.
func (c *TunnelConfig) effectiveTTL() int {
	if c.TTL > 0 {
		return c.TTL
	}
	return DefaultTTL
}

// TunnelState represents the operational state of a tunnel.
type TunnelState string

const (
	// TunnelStateUp indicates the tunnel interface is up.
	TunnelStateUp TunnelState = "up"

	// TunnelStateDown indicates the tunnel interface is down.
	TunnelStateDown TunnelState = "down"

	// TunnelStateUnknown indicates the tunnel state is unknown.
	TunnelStateUnknown TunnelState = "unknown"
)

// TunnelStatus holds the runtime status of a managed tunnel.
type TunnelStatus struct {
	// Name is the tunnel interface name.
	Name string

	// State is the operational state.
	State TunnelState

	// LocalIP is the local tunnel endpoint.
	LocalIP string

	// RemoteIP is the remote tunnel endpoint.
	RemoteIP string

	// TunnelIP is the tunnel interface address.
	TunnelIP string

	// RxBytes is the number of bytes received.
	RxBytes uint64

	// TxBytes is the number of bytes transmitted.
	TxBytes uint64

	// RxPackets is the number of packets received.
	RxPackets uint64

	// TxPackets is the number of packets transmitted.
	TxPackets uint64
}
