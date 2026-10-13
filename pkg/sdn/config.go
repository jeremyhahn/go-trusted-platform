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
//
// The sdn section declares an environment (sdn.environment) and the zone
// policy (sdn.zones); every VLAN, subnet, IPAM pool and port-class VLAN list
// is derived from them by package netplan. Validate builds that plan.
package sdn

import (
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric"
	ipsecconfig "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
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

// ErrDuplicatePoolName indicates two IPAM pools share the same name.
type ErrDuplicatePoolName struct {
	// Name is the duplicated pool name.
	Name string
}

// Error implements the error interface.
func (e ErrDuplicatePoolName) Error() string {
	return fmt.Sprintf("sdn: duplicate ipam pool name %q", e.Name)
}

// ErrEnvironmentRequired indicates an enabled SDN section has no
// environment: nothing can be numbered without one.
type ErrEnvironmentRequired struct{}

// Error implements the error interface.
func (ErrEnvironmentRequired) Error() string {
	return "sdn: sdn.environment is required when sdn is enabled (the environment number E numbers every zone)"
}

// ErrPoolNameReserved indicates an explicit IPAM pool takes the name of a
// pool the network plan derives (a zone or an IPAM range).
type ErrPoolNameReserved struct {
	// Pool is the offending pool name.
	Pool string
}

// Error implements the error interface.
func (e ErrPoolNameReserved) Error() string {
	return fmt.Sprintf("sdn: ipam pool %q is derived from the network plan and cannot be declared", e.Pool)
}

// ErrPoolOverlap indicates an explicit IPAM pool overlaps a pool the network
// plan derives, or a reserved range.
type ErrPoolOverlap struct {
	// Pool is the explicit pool.
	Pool string
	// CIDR is its prefix.
	CIDR netip.Prefix
	// Other names what it overlaps.
	Other string
}

// Error implements the error interface.
func (e ErrPoolOverlap) Error() string {
	return fmt.Sprintf("sdn: ipam pool %q (%s) overlaps %s", e.Pool, e.CIDR, e.Other)
}

// ErrPoolZoneUndeclared indicates an IPAM pool carries a zone that is not in
// the resolved zone set.
type ErrPoolZoneUndeclared struct {
	// Pool is the pool name with the bad zone.
	Pool string
	// Zone is the undeclared zone name.
	Zone string
}

// Error implements the error interface.
func (e ErrPoolZoneUndeclared) Error() string {
	return fmt.Sprintf("sdn: ipam pool %q references undeclared zone %q", e.Pool, e.Zone)
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

// ErrManagementVPNUnknownZone indicates the management VPN allow_to list
// references a zone that is not declared in the resolved zone set.
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

	// Environment is the environment this node belongs to: its number, the
	// IPv4 base, the deployment ULA and any explicit numbering overrides.
	// Required when Enabled; every VLAN, subnet and pool is derived from it.
	Environment *netplan.Environment `yaml:"environment,omitempty" json:"environment,omitempty" mapstructure:"environment"`

	// Zones tunes the policy of the built-in underlay zones and declares
	// owner-defined zones (offsets 9-99). When absent the built-in set
	// (transit, fabric, management, hypervisor, quarantine, provisioning,
	// control-plane, storage, backup) is used unchanged.
	Zones []zone.ZoneConfig `yaml:"zones,omitempty" json:"zones,omitempty" mapstructure:"zones"`

	// OVS configures the Open vSwitch connection.
	OVS *OVSConfig `yaml:"ovs,omitempty" json:"ovs,omitempty" mapstructure:"ovs"`

	// IPAM configures IP address management. The plan's pools (one per
	// zone, plus the IPAM ranges) are seeded automatically; IPAM.Pools adds
	// explicit pools beside them.
	IPAM *IPAMConfig `yaml:"ipam,omitempty" json:"ipam,omitempty" mapstructure:"ipam"`

	// DHCP configures the DHCP server.
	DHCP *DHCPConfig `yaml:"dhcp,omitempty" json:"dhcp,omitempty" mapstructure:"dhcp"`

	// Overlay configures VXLAN overlay networking.
	Overlay *OverlayConfig `yaml:"overlay,omitempty" json:"overlay,omitempty" mapstructure:"overlay"`

	// Gateway configures the SDN gateway node.
	Gateway *GatewayConfig `yaml:"gateway,omitempty" json:"gateway,omitempty" mapstructure:"gateway"`

	// Fabric configures the physical switch fabric: the switches, their
	// peer links and LAGs, and the class of every platform port.
	Fabric *fabric.FabricConfig `yaml:"fabric,omitempty" json:"fabric,omitempty" mapstructure:"fabric"`

	// Identity controls device-identity issuance behaviour (e.g. whether the
	// network zone is encoded into IDevID / ACME device-enrollment certificates).
	Identity *IdentityConfig `yaml:"identity,omitempty" json:"identity,omitempty" mapstructure:"identity"`

	// ManagementVPN configures the admin VPN that provides authenticated
	// operator access to management endpoints on the gateway.
	ManagementVPN *ManagementVPNConfig `yaml:"management_vpn,omitempty" json:"management_vpn,omitempty" mapstructure:"management_vpn"`

	// resolvedZones and plan are populated by Validate. They are unexported
	// so only callers that successfully validated the config reach them.
	resolvedZones []zone.ZoneConfig
	plan          *netplan.Plan
}

// ResolvedZones returns the merged zone set produced during Validate. It
// returns nil when Validate has not been called or failed.
func (c *Config) ResolvedZones() []zone.ZoneConfig {
	if c == nil {
		return nil
	}
	return c.resolvedZones
}

// Plan returns the network plan derived during Validate, or nil when
// Validate has not been called, failed, or SDN is disabled.
func (c *Config) Plan() *netplan.Plan {
	if c == nil {
		return nil
	}
	return c.plan
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

// Validate checks the SDN configuration for internal consistency and derives
// the network plan. On success ResolvedZones() and Plan() are populated.
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
	if c.Environment == nil {
		return ErrEnvironmentRequired{}
	}

	resolved, err := zone.Resolve(c.Zones)
	if err != nil {
		return err
	}
	if err := zone.Validate(resolved); err != nil {
		return err
	}
	plan, err := netplan.New(*c.Environment, resolved)
	if err != nil {
		return err
	}

	if c.IPAM != nil {
		if err := c.IPAM.validateAgainstPlan(plan, resolved); err != nil {
			return err
		}
	}

	if c.Fabric != nil {
		if err := c.Fabric.Validate(); err != nil {
			return err
		}
	}

	if c.ManagementVPN != nil {
		if err := c.ManagementVPN.validate(resolved); err != nil {
			return err
		}
	}

	if c.Overlay != nil {
		if err := c.Overlay.IPsec.Validate(); err != nil {
			return err
		}
	}

	c.resolvedZones = resolved
	c.plan = plan
	return nil
}

// LogPrivilegedPaths writes one audit record for every zone path into
// control-plane or management that goes beyond the reference defaults,
// naming the override that permits it. Callers invoke it after Validate,
// every time the SDN configuration is loaded.
func (c *Config) LogPrivilegedPaths(logger *slog.Logger) {
	if c == nil || logger == nil {
		return
	}
	for _, p := range zone.PrivilegedPaths(c.resolvedZones) {
		logger.Warn("sdn: privileged zone path opened by an audited override",
			slog.Bool("audit", true),
			slog.String("from", string(p.From)),
			slog.String("to", string(p.To)),
			slog.Any("services", p.Services),
			slog.String("reason", p.Access.Reason),
			slog.String("approved_by", p.Access.ApprovedBy))
	}
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

	// ASN is the Autonomous System Number for this platform. Used by BGP
	// and public subnet announcements.
	ASN uint32 `yaml:"asn,omitempty" json:"asn,omitempty" mapstructure:"asn"`

	// Pools lists explicit pools beside the ones the network plan derives
	// (for example a public block or an overlay subnet carved from the
	// tenant default range). They are seed-only: at control-plane startup a
	// pool is created if it does not exist in the backend, and an existing
	// pool is never deleted or mutated.
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

// validateAgainstPlan checks the explicit pools against the network plan:
// no explicit pool takes a derived pool's name or overlaps a derived pool
// or a reserved range, and every explicit zone is declared.
func (c *IPAMConfig) validateAgainstPlan(plan *netplan.Plan, resolved []zone.ZoneConfig) error {
	declared := make(map[zone.Zone]struct{}, len(resolved))
	for _, z := range resolved {
		declared[z.Name] = struct{}{}
	}
	derived := plan.Pools()
	for _, p := range c.Pools {
		if p.Zone != "" {
			if _, ok := declared[zone.Zone(p.Zone)]; !ok {
				return ErrPoolZoneUndeclared{Pool: p.Name, Zone: p.Zone}
			}
		}
		for _, d := range derived {
			if p.Name == d.Name {
				return ErrPoolNameReserved{Pool: p.Name}
			}
			if p.CIDR.Overlaps(d.Prefix) {
				return ErrPoolOverlap{Pool: p.Name, CIDR: p.CIDR, Other: "derived pool " + d.Name + " " + d.Prefix.String()}
			}
		}
		for _, r := range plan.Reserved() {
			if p.CIDR.Overlaps(r) {
				return ErrPoolOverlap{Pool: p.Name, CIDR: p.CIDR, Other: "reserved range " + r.String()}
			}
		}
	}
	return nil
}

// PoolConfig defines an explicit IP address pool seed entry. The entry is
// seed-only: the pool is created in the backend if it does not already
// exist, and an existing pool with the same name is left untouched.
type PoolConfig struct {
	// Name is the unique name for this pool.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// CIDR is the network prefix for this pool.
	CIDR netip.Prefix `yaml:"cidr" json:"cidr" mapstructure:"cidr"`

	// Gateway is the default gateway address for this pool.
	Gateway netip.Addr `yaml:"gateway" json:"gateway" mapstructure:"gateway"`

	// Zone optionally classifies the pool under a declared zone. Overlay
	// pools carry none: overlays are not zones.
	Zone string `yaml:"zone,omitempty" json:"zone,omitempty" mapstructure:"zone"`

	// DNS is the list of DNS server addresses.
	DNS []netip.Addr `yaml:"dns,omitempty" json:"dns,omitempty" mapstructure:"dns"`

	// RangeStart is the first dynamically allocatable address in the pool.
	RangeStart netip.Addr `yaml:"range-start,omitempty" json:"range_start,omitempty" mapstructure:"range-start"`

	// RangeEnd is the last dynamically allocatable address in the pool.
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

// OverlayConfig configures VXLAN overlay networking.
type OverlayConfig struct {
	// Enabled controls whether overlay networking is active.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// VXLANPort is the UDP port for VXLAN encapsulation.
	VXLANPort uint16 `yaml:"vxlan-port,omitempty" json:"vxlan_port,omitempty" mapstructure:"vxlan-port"`

	// UnderlayInterface is the network interface VXLAN underlay traffic leaves
	// by (e.g. "eth0", "bond0"; "lo" for a loopback VTEP). Required without
	// IPsec: there is no default, and an enabled overlay without it refuses to
	// start. With IPsec it may be unset or name the fabric interface.
	UnderlayInterface string `yaml:"underlay-interface,omitempty" json:"underlay_interface,omitempty" mapstructure:"underlay-interface"`

	// VTEPAddress is the address this node registers as its VTEP and sources
	// VXLAN from when IPsec is off. Empty uses the node's detected public IPv4;
	// with neither, an enabled overlay refuses to start. A single-node or test
	// overlay sets 127.0.0.1 explicitly. With IPsec the VTEP is always
	// ipsec.local-address and this field is ignored.
	VTEPAddress string `yaml:"vtep-address,omitempty" json:"vtep_address,omitempty" mapstructure:"vtep-address"`

	// IPsec protects the underlay with host-to-host transport SAs between
	// VTEPs and fails closed without them (docs/sdn/overlay/).
	IPsec *ipsecconfig.Config `yaml:"ipsec,omitempty" json:"ipsec,omitempty" mapstructure:"ipsec"`
}

// GatewayConfig configures the SDN gateway node.
type GatewayConfig struct {
	// Enabled controls whether gateway functionality is active.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
}

// ManagementVPNConfig configures the admin VPN on the gateway.
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
	// certificate when EncodeZoneInCert is true. Defaults to "control-plane"
	// when empty and EncodeZoneInCert is true: the platform lives in the
	// control-plane zone, and management carries BMCs only.
	PlatformZone string `yaml:"platform_zone,omitempty" json:"platform_zone,omitempty" mapstructure:"platform_zone"`
}

// ResolvedPlatformZone returns the effective platform zone, applying the
// "control-plane" default when PlatformZone is empty.
func (c *IdentityConfig) ResolvedPlatformZone() string {
	if c == nil {
		return ""
	}
	if c.PlatformZone != "" {
		return c.PlatformZone
	}
	return string(zone.ZoneControlPlane)
}
