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
	"fmt"
	"net/netip"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vlan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ErrInvalidConfig indicates the SDN configuration is nil or invalid.
type ErrInvalidConfig struct{}

// Error implements the error interface.
func (ErrInvalidConfig) Error() string { return "sdn: invalid configuration" }

// ErrInvalidOVSSocket indicates the OVS socket path is empty.
type ErrInvalidOVSSocket struct{}

// Error implements the error interface.
func (ErrInvalidOVSSocket) Error() string { return "sdn: ovs socket path is required" }

// ErrInvalidBridge indicates the OVS bridge name is empty.
type ErrInvalidBridge struct{}

// Error implements the error interface.
func (ErrInvalidBridge) Error() string { return "sdn: ovs bridge name is required" }

// ErrInvalidPoolName indicates an IPAM pool has an empty name.
type ErrInvalidPoolName struct{}

// Error implements the error interface.
func (ErrInvalidPoolName) Error() string { return "sdn: ipam pool name is required" }

// ErrInvalidPoolCIDR indicates an IPAM pool has an invalid CIDR.
type ErrInvalidPoolCIDR struct{}

// Error implements the error interface.
func (ErrInvalidPoolCIDR) Error() string { return "sdn: ipam pool cidr is invalid" }

// ErrInvalidNetworkPool indicates a network references a nonexistent pool.
type ErrInvalidNetworkPool struct {
	// Network is the name of the network with the bad pool reference.
	Network string
	// Pool is the nonexistent pool name.
	Pool string
}

// Error implements the error interface.
func (e ErrInvalidNetworkPool) Error() string {
	return fmt.Sprintf("sdn: network %q references unknown ipam pool %q", e.Network, e.Pool)
}

// ErrDuplicatePoolName indicates two IPAM pools share the same name.
type ErrDuplicatePoolName struct {
	// Name is the duplicated pool name.
	Name string
}

// Error implements the error interface.
func (e ErrDuplicatePoolName) Error() string {
	return fmt.Sprintf("sdn: duplicate ipam pool name %q", e.Name)
}

// ErrDuplicateNetworkVLAN indicates two networks share the same VLAN ID.
type ErrDuplicateNetworkVLAN struct {
	// VLAN is the duplicated VLAN identifier.
	VLAN uint16
	// Networks are the two network names sharing the VLAN.
	Networks [2]string
}

// Error implements the error interface.
func (e ErrDuplicateNetworkVLAN) Error() string {
	return fmt.Sprintf("sdn: duplicate network vlan id %d (networks %q and %q)", e.VLAN, e.Networks[0], e.Networks[1])
}

// ErrDuplicateNetworkName indicates two networks share the same name.
type ErrDuplicateNetworkName struct {
	// Name is the duplicated network name.
	Name string
}

// Error implements the error interface.
func (e ErrDuplicateNetworkName) Error() string {
	return fmt.Sprintf("sdn: duplicate network name %q", e.Name)
}

// ErrMissingNetworkZone indicates a network entry has no zone declared.
type ErrMissingNetworkZone struct {
	// Network is the name of the network missing a zone.
	Network string
}

// Error implements the error interface.
func (e ErrMissingNetworkZone) Error() string {
	return fmt.Sprintf("sdn: network %q has no zone declared", e.Network)
}

// ErrUnknownNetworkZone indicates a network entry references a zone not in
// the resolved zone set.
type ErrUnknownNetworkZone struct {
	// Network is the name of the network with the bad zone reference.
	Network string
	// Zone is the unknown zone value.
	Zone zone.Zone
}

// Error implements the error interface.
func (e ErrUnknownNetworkZone) Error() string {
	return fmt.Sprintf("sdn: network %q references unknown zone %q", e.Network, e.Zone)
}

// ErrInvalidNetworkVLAN indicates a network carries an out-of-range VLAN ID.
type ErrInvalidNetworkVLAN struct {
	// Network is the name of the network with the invalid VLAN.
	Network string
	// VLAN is the offending identifier.
	VLAN uint16
}

// Error implements the error interface.
func (e ErrInvalidNetworkVLAN) Error() string {
	return fmt.Sprintf("sdn: network %q has invalid vlan id %d", e.Network, e.VLAN)
}

// ErrDuplicateNetworkSubnet indicates two networks declare the same non-zero
// subnet prefix.
type ErrDuplicateNetworkSubnet struct {
	// Subnet is the duplicated prefix.
	Subnet netip.Prefix
	// Networks are the two network names sharing the subnet.
	Networks [2]string
}

// Error implements the error interface.
func (e ErrDuplicateNetworkSubnet) Error() string {
	return fmt.Sprintf("sdn: duplicate subnet %s (networks %q and %q)", e.Subnet, e.Networks[0], e.Networks[1])
}

// ErrSubnetPoolMismatch indicates a network's explicit Subnet does not match
// the CIDR of its referenced IPAM pool.
type ErrSubnetPoolMismatch struct {
	// Network is the network with the inconsistency.
	Network string
	// Subnet is the explicitly declared prefix.
	Subnet netip.Prefix
	// PoolCIDR is the CIDR reported by the pool.
	PoolCIDR netip.Prefix
}

// Error implements the error interface.
func (e ErrSubnetPoolMismatch) Error() string {
	return fmt.Sprintf("sdn: network %q subnet %s does not match pool cidr %s", e.Network, e.Subnet, e.PoolCIDR)
}

// ErrNetworkPoolZoneMismatch indicates a network and its referenced pool
// declare different, non-empty zone values.
type ErrNetworkPoolZoneMismatch struct {
	// Network is the network with the inconsistency.
	Network string
	// Pool is the pool name.
	Pool string
	// NetworkZone is the zone declared on the network.
	NetworkZone zone.Zone
	// PoolZone is the zone declared on the pool.
	PoolZone string
}

// Error implements the error interface.
func (e ErrNetworkPoolZoneMismatch) Error() string {
	return fmt.Sprintf("sdn: network %q zone %q conflicts with pool %q zone %q",
		e.Network, e.NetworkZone, e.Pool, e.PoolZone)
}

// ErrPoolZoneUndeclared indicates a pool's zone is not in the resolved zone set.
type ErrPoolZoneUndeclared struct {
	// Pool is the pool name with the bad zone.
	Pool string
	// Zone is the undeclared zone value.
	Zone string
}

// Error implements the error interface.
func (e ErrPoolZoneUndeclared) Error() string {
	return fmt.Sprintf("sdn: ipam pool %q zone %q is not declared in resolved zones", e.Pool, e.Zone)
}

// ErrIPAMBackendUnconfigured indicates the "quicbaas" backend was requested
// but no QuicBaaS SDK client is available.
type ErrIPAMBackendUnconfigured struct {
	// Backend is the requested backend name.
	Backend string
}

// Error implements the error interface.
func (e ErrIPAMBackendUnconfigured) Error() string {
	return fmt.Sprintf("sdn: ipam backend %q requires a configured quicbaas client", e.Backend)
}

// ErrIPAMBackendUnknown indicates an unrecognised IPAM backend name.
type ErrIPAMBackendUnknown struct {
	// Backend is the unrecognised backend name.
	Backend string
}

// Error implements the error interface.
func (e ErrIPAMBackendUnknown) Error() string {
	return fmt.Sprintf("sdn: unknown ipam backend %q", e.Backend)
}

// ErrIPAMBackendP2PRequired indicates the "dht" backend was requested but the
// binary was not compiled with the platform_p2p build tag.
type ErrIPAMBackendP2PRequired struct{}

// Error implements the error interface.
func (ErrIPAMBackendP2PRequired) Error() string {
	return "sdn: ipam backend \"dht\" requires build tag platform_p2p"
}

// ErrInvalidTransitVLAN indicates the transit VLAN is out of the IEEE 802.1Q
// valid range.
type ErrInvalidTransitVLAN struct {
	// VLAN is the offending transit VLAN identifier.
	VLAN uint16
}

// Error implements the error interface.
func (e ErrInvalidTransitVLAN) Error() string {
	return fmt.Sprintf("sdn: transit vlan %d is invalid: must be between 1 and 4094", e.VLAN)
}

// ErrManagementVPNUnknownZone indicates the management_vpn allow_to list
// contains a zone name that is not present in the resolved zone set.
type ErrManagementVPNUnknownZone struct {
	// Zone is the undeclared zone name.
	Zone string
}

// Error implements the error interface.
func (e ErrManagementVPNUnknownZone) Error() string {
	return fmt.Sprintf("sdn: management_vpn allow_to references undeclared zone %q", e.Zone)
}

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

	// Zones declares zone overrides merged on top of the built-in defaults.
	// When absent the full built-in set (trusted / public / provisioning /
	// quarantine / storage / tenant / management) is used unchanged.
	Zones []zone.ZoneConfig `yaml:"zones,omitempty" json:"zones,omitempty" mapstructure:"zones"`

	// Networks defines named network segments with VLAN, zone, and pool
	// bindings. The list form replaces the former map[string]*NetworkConfig.
	Networks []NetworkConfig `yaml:"networks,omitempty" json:"networks,omitempty" mapstructure:"networks"`

	// Overlay configures VXLAN overlay networking.
	Overlay *OverlayConfig `yaml:"overlay,omitempty" json:"overlay,omitempty" mapstructure:"overlay"`

	// Gateway configures the SDN gateway node.
	Gateway *GatewayConfig `yaml:"gateway,omitempty" json:"gateway,omitempty" mapstructure:"gateway"`

	// Fabric configures the physical switch fabric for VLAN/VNI provisioning.
	Fabric *fabric.FabricConfig `yaml:"fabric,omitempty" json:"fabric,omitempty" mapstructure:"fabric"`

	// Identity controls device-identity issuance behaviour (e.g. whether the
	// network zone is encoded into IDevID / ACME device-enrollment certificates).
	Identity *IdentityConfig `yaml:"identity,omitempty" json:"identity,omitempty" mapstructure:"identity"`

	// Transit configures gateway ↔ upstream/BGP point-to-point transit links.
	// The VLAN identifies the L2 segment used for /31 p2p links; the P2P
	// prefix is the pool from which /31 addresses are carved.
	// Default: vlan 10, p2p 172.16.0.0/24 (see docs/architecture/reference-network.md).
	Transit *TransitConfig `yaml:"transit,omitempty" json:"transit,omitempty" mapstructure:"transit"`

	// ManagementVPN configures the WireGuard admin VPN that provides
	// authenticated operator access to management endpoints on the gateway.
	// Gateways SHOULD expose this by default.
	ManagementVPN *ManagementVPNConfig `yaml:"management_vpn,omitempty" json:"management_vpn,omitempty" mapstructure:"management_vpn"`

	// Services holds per-zone control-plane service endpoint configuration.
	// Keys are zone names; the schema is defined per zone in ZoneServiceConfig.
	Services map[string]ZoneServiceConfig `yaml:"services,omitempty" json:"services,omitempty" mapstructure:"services"`

	// resolvedZones is the merged zone set populated by Validate. It is
	// unexported so only callers that successfully validated the config can
	// reach it via ResolvedZones().
	resolvedZones []zone.ZoneConfig
}

// ResolvedZones returns the merged zone set produced during Validate. It
// returns nil when Validate has not been called or failed.
func (c *Config) ResolvedZones() []zone.ZoneConfig {
	if c == nil {
		return nil
	}
	return c.resolvedZones
}

// ZoneIndex returns a map from zone name to ZoneConfig built from the
// resolved zone set. It returns an empty map when Validate has not been
// called or failed.
func (c *Config) ZoneIndex() map[zone.Zone]zone.ZoneConfig {
	if c == nil {
		return map[zone.Zone]zone.ZoneConfig{}
	}
	idx := make(map[zone.Zone]zone.ZoneConfig, len(c.resolvedZones))
	for _, z := range c.resolvedZones {
		idx[z.Name] = z
	}
	return idx
}

// Validate checks the SDN configuration for internal consistency. On success
// the resolved zone set is stored and retrievable via ResolvedZones().
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig{}
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

	// Resolve and validate zones first so network validation can check
	// zone references against the merged set.
	resolved, err := zone.Resolve(c.Zones)
	if err != nil {
		return err
	}
	if err := zone.Validate(resolved); err != nil {
		return err
	}
	c.resolvedZones = resolved

	if len(c.Networks) > 0 {
		if err := c.validateNetworks(resolved); err != nil {
			return err
		}
	}

	// Validate pool zones for pools not referenced by any network entry.
	// This covers standalone pools (no network referencing them) that carry an
	// explicit Zone that must exist in the resolved zone set.
	if c.IPAM != nil {
		zoneNames := make(map[zone.Zone]struct{}, len(resolved))
		for _, z := range resolved {
			zoneNames[z.Name] = struct{}{}
		}
		for _, p := range c.IPAM.Pools {
			if p.Zone == "" {
				continue
			}
			if _, ok := zoneNames[zone.Zone(p.Zone)]; !ok {
				return ErrPoolZoneUndeclared{Pool: p.Name, Zone: p.Zone}
			}
		}
	}

	if c.Fabric != nil {
		if err := c.Fabric.Validate(); err != nil {
			return err
		}
	}

	if c.Transit != nil {
		if err := c.Transit.Validate(); err != nil {
			return err
		}
	}

	if c.ManagementVPN != nil {
		if err := c.ManagementVPN.validate(c.resolvedZones); err != nil {
			return err
		}
	}

	return nil
}

// validateNetworks checks that all network entries are internally consistent:
//   - Names are unique across the list.
//   - Every network has a non-empty Zone that exists in the resolved zone set.
//   - VLAN IDs are valid (per vlan.Validate) and unique across networks.
//   - Non-zero Subnet prefixes are unique across networks.
//   - Pool references exist in IPAM.Pools.
//   - When both Subnet and Pool are set, their CIDRs must match.
//   - When a pool has a non-empty Zone, it must exist in the resolved zone set.
//   - When both network.Zone and pool.Zone are non-empty they must agree;
//     otherwise the pool's zone is inherited from the network (resolved in place).
func (c *Config) validateNetworks(resolved []zone.ZoneConfig) error {
	// Build a set of valid zone names from the resolved set.
	zoneNames := make(map[zone.Zone]struct{}, len(resolved))
	for _, z := range resolved {
		zoneNames[z.Name] = struct{}{}
	}

	// Build a map of IPAM pool configs for reference checking.
	// We use a pointer index so zone inheritance can be written back.
	type poolRef struct {
		cidr netip.Prefix
		idx  int // index into c.IPAM.Pools
	}
	poolRefs := make(map[string]poolRef)
	if c.IPAM != nil {
		for i, p := range c.IPAM.Pools {
			poolRefs[p.Name] = poolRef{cidr: p.CIDR, idx: i}
		}
	}

	names := make(map[string]struct{}, len(c.Networks))
	vlans := make(map[uint16]string, len(c.Networks))
	subnets := make(map[netip.Prefix]string, len(c.Networks))

	for _, net := range c.Networks {
		// Unique names.
		if _, dup := names[net.Name]; dup {
			return ErrDuplicateNetworkName{Name: net.Name}
		}
		names[net.Name] = struct{}{}

		// Zone must be declared.
		if net.Zone == "" {
			return ErrMissingNetworkZone{Network: net.Name}
		}
		if _, ok := zoneNames[net.Zone]; !ok {
			return ErrUnknownNetworkZone{Network: net.Name, Zone: net.Zone}
		}

		// VLAN must be valid when non-zero.
		if net.VLAN > 0 {
			if err := vlan.Validate(net.VLAN); err != nil {
				return ErrInvalidNetworkVLAN{Network: net.Name, VLAN: net.VLAN}
			}
			if existing, ok := vlans[net.VLAN]; ok {
				return ErrDuplicateNetworkVLAN{VLAN: net.VLAN, Networks: [2]string{existing, net.Name}}
			}
			vlans[net.VLAN] = net.Name
		}

		// Non-zero subnets must be unique.
		if net.Subnet.IsValid() {
			if existing, ok := subnets[net.Subnet]; ok {
				return ErrDuplicateNetworkSubnet{Subnet: net.Subnet, Networks: [2]string{existing, net.Name}}
			}
			subnets[net.Subnet] = net.Name
		}

		// Pool reference checks and zone inheritance/mismatch detection.
		if net.Pool != "" {
			ref, ok := poolRefs[net.Pool]
			if !ok {
				return ErrInvalidNetworkPool{Network: net.Name, Pool: net.Pool}
			}
			// When both Subnet and Pool are set, the CIDRs must agree.
			if net.Subnet.IsValid() && ref.cidr.IsValid() && net.Subnet != ref.cidr {
				return ErrSubnetPoolMismatch{
					Network:  net.Name,
					Subnet:   net.Subnet,
					PoolCIDR: ref.cidr,
				}
			}
			// Zone agreement / inheritance.
			poolZone := c.IPAM.Pools[ref.idx].Zone
			if poolZone != "" {
				// Pool has an explicit zone — validate it is declared.
				if _, ok := zoneNames[zone.Zone(poolZone)]; !ok {
					return ErrPoolZoneUndeclared{Pool: net.Pool, Zone: poolZone}
				}
				// Both network and pool have zones; they must agree.
				if poolZone != string(net.Zone) {
					return ErrNetworkPoolZoneMismatch{
						Network:     net.Name,
						Pool:        net.Pool,
						NetworkZone: net.Zone,
						PoolZone:    poolZone,
					}
				}
			} else {
				// Pool has no explicit zone — inherit from network.
				c.IPAM.Pools[ref.idx].Zone = string(net.Zone)
			}
		}
	}

	return nil
}

// poolEntry holds pool metadata needed during network validation.
type poolEntry struct {
	cidr netip.Prefix
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

	// HWOffload enables hardware flow offload (tc-flower) in
	// ovs-vswitchd via the Open_vSwitch other_config:hw-offload key.
	// Changing this value requires an ovs-vswitchd restart to take effect.
	HWOffload bool `yaml:"hw-offload,omitempty" json:"hw_offload,omitempty" mapstructure:"hw-offload"`

	// TCPolicy selects the tc offload policy ("none", "skip_sw",
	// "skip_hw"). Only meaningful when HWOffload is enabled.
	TCPolicy string `yaml:"tc-policy,omitempty" json:"tc_policy,omitempty" mapstructure:"tc-policy"`

	// DPDK configures the DPDK userspace datapath. Requires
	// Datapath == "netdev".
	DPDK *DPDKConfig `yaml:"dpdk,omitempty" json:"dpdk,omitempty" mapstructure:"dpdk"`
}

// DPDKConfig configures DPDK initialization for the OVS userspace
// ("netdev") datapath. The keys map onto Open_vSwitch
// other_config:dpdk-* entries.
type DPDKConfig struct {
	// Init enables DPDK initialization (other_config:dpdk-init).
	// Changing this value requires an ovs-vswitchd restart to take effect.
	Init bool `yaml:"init" json:"init" mapstructure:"init"`

	// SocketMem is the hugepage memory to preallocate per NUMA socket,
	// in MB (other_config:dpdk-socket-mem, e.g. "1024,1024").
	SocketMem string `yaml:"socket-mem,omitempty" json:"socket_mem,omitempty" mapstructure:"socket-mem"`

	// LCoreMask is the CPU core bitmask for DPDK lcore threads
	// (other_config:dpdk-lcore-mask, e.g. "0x1").
	LCoreMask string `yaml:"lcore-mask,omitempty" json:"lcore_mask,omitempty" mapstructure:"lcore-mask"`

	// PMDCPUMask is the CPU core bitmask for DPDK poll-mode-driver
	// threads (other_config:pmd-cpu-mask, e.g. "0x6").
	PMDCPUMask string `yaml:"pmd-cpu-mask,omitempty" json:"pmd_cpu_mask,omitempty" mapstructure:"pmd-cpu-mask"`

	// NRxq is the number of receive queues for DPDK ports. Applied
	// per-interface (options:n_rxq) when DPDK ports are created.
	NRxq int `yaml:"n-rxq,omitempty" json:"n_rxq,omitempty" mapstructure:"n-rxq"`

	// Extra holds additional Open_vSwitch other_config keys merged
	// verbatim after the derived dpdk-* keys.
	Extra map[string]string `yaml:"extra,omitempty" json:"extra,omitempty" mapstructure:"extra"`
}

// Validate checks the OVS configuration.
func (c *OVSConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.Socket == "" {
		return ErrInvalidOVSSocket{}
	}
	if c.Bridge == "" {
		return ErrInvalidBridge{}
	}
	switch c.TCPolicy {
	case "", "none", "skip_sw", "skip_hw":
	default:
		return ErrInvalidTCPolicy{Policy: c.TCPolicy}
	}
	if c.TCPolicy != "" && !c.HWOffload {
		return ErrTCPolicyWithoutHWOffload{}
	}
	if c.DPDK != nil && c.Datapath != "netdev" {
		return ErrDPDKRequiresNetdev{Datapath: c.Datapath}
	}
	return nil
}

// IPAMConfig configures IP address management.
type IPAMConfig struct {
	// Backend is the IPAM storage backend ("memory", "quicbaas", "dht").
	// Defaults to "memory" when empty.
	// "quicbaas" requires the platform QuicBaaS SDK client to be configured.
	// "dht" requires the platform_p2p build tag.
	Backend string `yaml:"backend" json:"backend" mapstructure:"backend"`

	// ASN is the Autonomous System Number for this platform (e.g., 401870).
	// Used by BGP and public subnet announcements.
	ASN uint32 `yaml:"asn,omitempty" json:"asn,omitempty" mapstructure:"asn"`

	// Pools is the list of IP address pools.
	// These are seed-only: at CP startup, pools are created if they do not
	// exist in the backend. Existing pools are never deleted or mutated.
	// Explicit pool entries (by name) take precedence over auto-seeds derived
	// from the networks[] list.
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
			return ErrDuplicatePoolName{Name: c.Pools[i].Name}
		}
		seen[c.Pools[i].Name] = struct{}{}
	}
	return nil
}

// PoolConfig defines an IP address pool seed entry.
// Config entries are seed-only: the pool is created in the backend if it does
// not already exist. An existing pool with the same name is left untouched.
// Zone is inherited from the network entry that references this pool when not
// set explicitly here; at validation time the field is written in place.
type PoolConfig struct {
	// Name is the unique name for this pool.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// CIDR is the network prefix for this pool.
	CIDR netip.Prefix `yaml:"cidr" json:"cidr" mapstructure:"cidr"`

	// Gateway is the default gateway address for this pool.
	Gateway netip.Addr `yaml:"gateway" json:"gateway" mapstructure:"gateway"`

	// Zone is the trust/exposure zone for this pool.
	// When empty and this pool is referenced by a networks[] entry, the
	// network's zone is inherited here at validation time.
	// When set explicitly it must match the referencing network's zone.
	Zone string `yaml:"zone,omitempty" json:"zone,omitempty" mapstructure:"zone"`

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
		return ErrInvalidPoolName{}
	}
	if !c.CIDR.IsValid() {
		return ErrInvalidPoolCIDR{}
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
	// Name is the unique identifier for this network segment.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// Subnet is the IP prefix for this network segment. When set it must
	// match the CIDR of the referenced IPAM pool (if any).
	Subnet netip.Prefix `yaml:"subnet,omitempty" json:"subnet,omitempty" mapstructure:"subnet"`

	// VLAN is the IEEE 802.1Q VLAN identifier for this network.
	VLAN uint16 `yaml:"vlan" json:"vlan" mapstructure:"vlan"`

	// Zone is the trust/exposure classification for this network. Must
	// match a zone name in the resolved zone set.
	Zone zone.Zone `yaml:"zone" json:"zone" mapstructure:"zone"`

	// Pool is the name of the IPAM pool providing addresses for this network.
	Pool string `yaml:"pool,omitempty" json:"pool,omitempty" mapstructure:"pool"`
}

// OverlayConfig configures VXLAN overlay networking.
type OverlayConfig struct {
	// Enabled controls whether overlay networking is active.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// VXLANPort is the UDP port for VXLAN encapsulation.
	VXLANPort uint16 `yaml:"vxlan-port,omitempty" json:"vxlan_port,omitempty" mapstructure:"vxlan-port"`

	// UnderlayInterface is the physical network interface used for VXLAN underlay
	// traffic. When empty the daemon defaults to "lo" (loopback), which is always
	// present and sufficient for single-node and test environments. Production
	// deployments should set this to the uplink interface (e.g., "eth0", "bond0").
	UnderlayInterface string `yaml:"underlay-interface,omitempty" json:"underlay_interface,omitempty" mapstructure:"underlay-interface"`
}

// GatewayConfig configures the SDN gateway node.
type GatewayConfig struct {
	// Enabled controls whether gateway functionality is active.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
}

// TransitConfig configures gateway ↔ upstream/BGP point-to-point transit links.
// Transit carries no data-zone traffic; the VLAN is a plain L2 segment
// identifier and the P2P prefix provides addresses for /31 p2p links.
//
// Doc reference: docs/architecture/reference-network.md §Addressing
// YAML form:
//
//	transit: {vlan: 10, p2p: "172.16.0.0/24"}
type TransitConfig struct {
	// VLAN is the L2 segment identifier for transit links.
	// Defaults to vlan.DefaultTransit (10). Must be a valid IEEE 802.1Q ID.
	VLAN uint16 `yaml:"vlan,omitempty" json:"vlan,omitempty" mapstructure:"vlan"`

	// P2P is the IPv4 prefix from which /31 point-to-point link addresses are
	// carved. Defaults to 172.16.0.0/24.
	P2P string `yaml:"p2p,omitempty" json:"p2p,omitempty" mapstructure:"p2p"`
}

// Validate checks the transit configuration.
func (c *TransitConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.VLAN != 0 {
		if err := vlan.Validate(c.VLAN); err != nil {
			return ErrInvalidTransitVLAN{VLAN: c.VLAN}
		}
	}
	return nil
}

// EffectiveVLAN returns the transit VLAN, applying the default when zero.
func (c *TransitConfig) EffectiveVLAN() uint16 {
	if c == nil || c.VLAN == 0 {
		return vlan.DefaultTransit
	}
	return c.VLAN
}

// EffectiveP2P returns the transit P2P prefix, applying the default when empty.
func (c *TransitConfig) EffectiveP2P() string {
	if c == nil || c.P2P == "" {
		return "172.16.0.0/24"
	}
	return c.P2P
}

// ManagementVPNConfig configures the WireGuard admin VPN on the gateway.
// Admins access management/control endpoints through this authenticated tunnel;
// operator workstations are never dual-homed onto a data zone.
//
// Doc reference: docs/architecture/reference-network.md §Management access
// YAML form:
//
//	management_vpn: {enabled: true, type: wireguard, allow_to: [management]}
type ManagementVPNConfig struct {
	// Enabled controls whether the management VPN is active.
	// Gateways SHOULD expose this by default.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Type is the VPN protocol. Currently only "wireguard" is defined by the
	// reference architecture. The field is included for future extensibility.
	Type string `yaml:"type,omitempty" json:"type,omitempty" mapstructure:"type"`

	// AllowTo lists the zone names that this VPN admin subnet is permitted to
	// reach. The reference architecture restricts this to ["management"].
	// Each name must resolve to a declared zone.
	AllowTo []string `yaml:"allow_to,omitempty" json:"allow_to,omitempty" mapstructure:"allow_to"`
}

// validate checks the management VPN configuration against the resolved zone
// set. All zone names in AllowTo must be declared.
func (c *ManagementVPNConfig) validate(resolved []zone.ZoneConfig) error {
	if c == nil || !c.Enabled {
		return nil
	}
	zoneSet := make(map[string]struct{}, len(resolved))
	for _, z := range resolved {
		zoneSet[string(z.Name)] = struct{}{}
	}
	for _, name := range c.AllowTo {
		if _, ok := zoneSet[name]; !ok {
			return ErrManagementVPNUnknownZone{Zone: name}
		}
	}
	return nil
}

// ZoneServiceConfig holds per-zone control-plane service endpoint addresses.
// The provisioning zone typically needs acme_server, dns_server, and dhcp_range.
// The quarantine zone typically needs remediation_server and dns_server.
//
// Doc reference: docs/architecture/reference-network.md §Configuration
// YAML form (under services:):
//
//	provisioning: {acme_server: "172.16.201.10", dns_server: "172.16.201.1", dhcp_range: "172.16.201.100-172.16.201.200"}
//	quarantine:   {remediation_server: "172.16.202.10", dns_server: "172.16.202.1"}
type ZoneServiceConfig struct {
	// ACMEServer is the ACME server IP for device enrollment (provisioning zone).
	ACMEServer string `yaml:"acme_server,omitempty" json:"acme_server,omitempty" mapstructure:"acme_server"`

	// DNSServer is the authoritative DNS resolver IP for this zone.
	DNSServer string `yaml:"dns_server,omitempty" json:"dns_server,omitempty" mapstructure:"dns_server"`

	// DHCPRange is the allocatable DHCP address range in "start-end" notation.
	// Used by the provisioning zone DHCP server as a seed; the IPAM pool is
	// the canonical source of truth at runtime.
	DHCPRange string `yaml:"dhcp_range,omitempty" json:"dhcp_range,omitempty" mapstructure:"dhcp_range"`

	// RemediationServer is the remediation endpoint IP (quarantine zone).
	RemediationServer string `yaml:"remediation_server,omitempty" json:"remediation_server,omitempty" mapstructure:"remediation_server"`
}

// IdentityConfig controls device-identity certificate issuance behaviour.
type IdentityConfig struct {
	// EncodeZoneInCert, when true, instructs the IDevID issuance and ACME
	// device-enrollment paths to embed the network zone in the issued
	// certificate using the OIDTPNetworkZone extension
	// (1.3.6.1.4.1.29377.101.21). The zone value is taken from the device
	// profile's post-enrollment NetworkPhaseConfig.Zone, falling back to
	// DeviceProfile.Zone. For the platform's own self-IDevID, PlatformZone
	// is used. Certificate issuance fails with a typed error when this flag
	// is true and no zone can be resolved.
	EncodeZoneInCert bool `yaml:"encode_zone_in_cert" json:"encode_zone_in_cert" mapstructure:"encode_zone_in_cert"`

	// PlatformZone is the zone name embedded in the platform's own self-IDevID
	// certificate when EncodeZoneInCert is true. Defaults to "management" when
	// empty and EncodeZoneInCert is true.
	PlatformZone string `yaml:"platform_zone,omitempty" json:"platform_zone,omitempty" mapstructure:"platform_zone"`
}

// ResolvedPlatformZone returns the effective platform zone, applying the
// "management" default when PlatformZone is empty.
func (c *IdentityConfig) ResolvedPlatformZone() string {
	if c == nil {
		return ""
	}
	if c.PlatformZone != "" {
		return c.PlatformZone
	}
	return "management"
}
