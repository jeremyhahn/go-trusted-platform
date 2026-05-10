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

// Package sdn provides software-defined networking configuration and
// orchestration for the trusted platform.
package sdn

import (
	"errors"
	"net/netip"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric"
)

var (
	// ErrInvalidConfig indicates the SDN configuration is nil or invalid.
	ErrInvalidConfig = errors.New("sdn: invalid configuration")

	// ErrInvalidOVSSocket indicates the OVS socket path is empty.
	ErrInvalidOVSSocket = errors.New("sdn: ovs socket path is required")

	// ErrInvalidBridge indicates the OVS bridge name is empty.
	ErrInvalidBridge = errors.New("sdn: ovs bridge name is required")

	// ErrInvalidPoolName indicates an IPAM pool has an empty name.
	ErrInvalidPoolName = errors.New("sdn: ipam pool name is required")

	// ErrInvalidPoolCIDR indicates an IPAM pool has an invalid CIDR.
	ErrInvalidPoolCIDR = errors.New("sdn: ipam pool cidr is invalid")

	// ErrInvalidNetworkPool indicates a network references a nonexistent pool.
	ErrInvalidNetworkPool = errors.New("sdn: network references unknown ipam pool")

	// ErrDuplicatePoolName indicates two IPAM pools share the same name.
	ErrDuplicatePoolName = errors.New("sdn: duplicate ipam pool name")

	// ErrDuplicateNetworkVLAN indicates two networks share the same VLAN ID.
	ErrDuplicateNetworkVLAN = errors.New("sdn: duplicate network vlan id")
)

// Config is the top-level SDN configuration.
type Config struct {
	// Enabled controls whether SDN functionality is active.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Controller enables this node as an SDN controller.
	Controller bool `yaml:"controller" json:"controller" mapstructure:"controller"`

	// OVS configures the Open vSwitch connection.
	OVS *OVSConfig `yaml:"ovs,omitempty" json:"ovs,omitempty" mapstructure:"ovs"`

	// IPAM configures IP address management.
	IPAM *IPAMConfig `yaml:"ipam,omitempty" json:"ipam,omitempty" mapstructure:"ipam"`

	// DHCP configures the DHCP server.
	DHCP *DHCPConfig `yaml:"dhcp,omitempty" json:"dhcp,omitempty" mapstructure:"dhcp"`

	// Networks defines named network segments with VLAN and pool bindings.
	Networks map[string]*NetworkConfig `yaml:"networks,omitempty" json:"networks,omitempty" mapstructure:"networks"`

	// Overlay configures VXLAN overlay networking.
	Overlay *OverlayConfig `yaml:"overlay,omitempty" json:"overlay,omitempty" mapstructure:"overlay"`

	// Gateway configures the SDN gateway node.
	Gateway *GatewayConfig `yaml:"gateway,omitempty" json:"gateway,omitempty" mapstructure:"gateway"`

	// Fabric configures the physical switch fabric for VLAN/VNI provisioning.
	Fabric *fabric.FabricConfig `yaml:"fabric,omitempty" json:"fabric,omitempty" mapstructure:"fabric"`
}

// Validate checks the SDN configuration for internal consistency.
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}
	if !c.Enabled {
		return nil
	}
	if c.OVS != nil {
		if err := c.OVS.Validate(); err != nil {
			return err
		}
	}
	if c.IPAM != nil {
		if err := c.IPAM.Validate(); err != nil {
			return err
		}
	}
	if c.Networks != nil {
		if err := c.validateNetworks(); err != nil {
			return err
		}
	}
	if c.Fabric != nil {
		if err := c.Fabric.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// validateNetworks checks that all network pool references are valid and
// that VLAN IDs are unique across networks.
func (c *Config) validateNetworks() error {
	poolNames := make(map[string]struct{})
	if c.IPAM != nil {
		for _, p := range c.IPAM.Pools {
			poolNames[p.Name] = struct{}{}
		}
	}
	vlans := make(map[uint16]string)
	for name, net := range c.Networks {
		if net.Pool != "" {
			if _, ok := poolNames[net.Pool]; !ok {
				return ErrInvalidNetworkPool
			}
		}
		if net.VLAN > 0 {
			if existing, ok := vlans[net.VLAN]; ok {
				_ = existing
				return ErrDuplicateNetworkVLAN
			}
			vlans[net.VLAN] = name
		}
	}
	return nil
}

// OVSConfig configures the Open vSwitch connection.
type OVSConfig struct {
	// Socket is the path to the OVSDB Unix socket.
	Socket string `yaml:"socket" json:"socket" mapstructure:"socket"`

	// Bridge is the OVS bridge name.
	Bridge string `yaml:"bridge" json:"bridge" mapstructure:"bridge"`

	// Datapath is the OVS datapath type (e.g., "system", "netdev").
	Datapath string `yaml:"datapath" json:"datapath" mapstructure:"datapath"`

	// Protocols is the list of OpenFlow protocol versions to enable.
	Protocols []string `yaml:"protocols,omitempty" json:"protocols,omitempty" mapstructure:"protocols"`
}

// Validate checks the OVS configuration.
func (c *OVSConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.Socket == "" {
		return ErrInvalidOVSSocket
	}
	if c.Bridge == "" {
		return ErrInvalidBridge
	}
	return nil
}

// IPAMConfig configures IP address management.
type IPAMConfig struct {
	// Backend is the IPAM storage backend ("memory", "quicbaas").
	Backend string `yaml:"backend" json:"backend" mapstructure:"backend"`

	// ASN is the Autonomous System Number for this platform (e.g., 401870).
	// Used by BGP and public subnet announcements.
	ASN uint32 `yaml:"asn,omitempty" json:"asn,omitempty" mapstructure:"asn"`

	// Pools is the list of IP address pools.
	Pools []PoolConfig `yaml:"pools,omitempty" json:"pools,omitempty" mapstructure:"pools"`
}

// Validate checks the IPAM configuration for correctness.
func (c *IPAMConfig) Validate() error {
	if c == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(c.Pools))
	for i := range c.Pools {
		if err := c.Pools[i].Validate(); err != nil {
			return err
		}
		if _, ok := seen[c.Pools[i].Name]; ok {
			return ErrDuplicatePoolName
		}
		seen[c.Pools[i].Name] = struct{}{}
	}
	return nil
}

// PoolConfig defines an IP address pool.
type PoolConfig struct {
	// Name is the unique name for this pool.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// CIDR is the network prefix for this pool.
	CIDR netip.Prefix `yaml:"cidr" json:"cidr" mapstructure:"cidr"`

	// Gateway is the default gateway address for this pool.
	Gateway netip.Addr `yaml:"gateway" json:"gateway" mapstructure:"gateway"`

	// DNS is the list of DNS server addresses.
	DNS []netip.Addr `yaml:"dns,omitempty" json:"dns,omitempty" mapstructure:"dns"`

	// RangeStart is the first allocatable address in the pool.
	RangeStart netip.Addr `yaml:"range-start,omitempty" json:"range_start,omitempty" mapstructure:"range-start"`

	// RangeEnd is the last allocatable address in the pool.
	RangeEnd netip.Addr `yaml:"range-end,omitempty" json:"range_end,omitempty" mapstructure:"range-end"`

	// LeaseDuration is the default DHCP lease duration for this pool.
	LeaseDuration time.Duration `yaml:"lease-duration,omitempty" json:"lease_duration,omitempty" mapstructure:"lease-duration"`

	// DHCP enables DHCP serving from this pool.
	DHCP bool `yaml:"dhcp" json:"dhcp" mapstructure:"dhcp"`
}

// Validate checks the pool configuration.
func (c *PoolConfig) Validate() error {
	if c.Name == "" {
		return ErrInvalidPoolName
	}
	if !c.CIDR.IsValid() {
		return ErrInvalidPoolCIDR
	}
	return nil
}

// DHCPConfig configures the DHCP server.
type DHCPConfig struct {
	// Enabled controls whether the DHCP server is active.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Interface is the network interface to bind the DHCP server to.
	Interface string `yaml:"interface" json:"interface" mapstructure:"interface"`
}

// NetworkConfig defines a named network segment.
type NetworkConfig struct {
	// VLAN is the IEEE 802.1Q VLAN identifier for this network.
	VLAN uint16 `yaml:"vlan" json:"vlan" mapstructure:"vlan"`

	// Pool is the name of the IPAM pool providing addresses for this network.
	Pool string `yaml:"pool" json:"pool" mapstructure:"pool"`
}

// OverlayConfig configures VXLAN overlay networking.
type OverlayConfig struct {
	// Enabled controls whether overlay networking is active.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// VXLANPort is the UDP port for VXLAN encapsulation.
	VXLANPort uint16 `yaml:"vxlan-port,omitempty" json:"vxlan_port,omitempty" mapstructure:"vxlan-port"`
}

// GatewayConfig configures the SDN gateway node.
type GatewayConfig struct {
	// Enabled controls whether gateway functionality is active.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
}
