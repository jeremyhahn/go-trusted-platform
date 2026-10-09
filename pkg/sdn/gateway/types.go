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

// Package gateway provides gateway node management for SDN overlay networking.
// Services are loaded via config-driven activation: if a config section exists
// and is enabled, the corresponding service starts automatically.
package gateway

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

// Gateway requirement constants.
const (
	// MinReputation is the minimum reputation score required to be a gateway.
	MinReputation float64 = 0.85

	// MinAgeDays is the minimum node age in days required to be a gateway.
	MinAgeDays int = 175

	// MinUptimePct is the minimum uptime percentage required to be a gateway.
	MinUptimePct float64 = 95.0

	// MinBandwidthBps is the minimum bandwidth in bits per second required.
	MinBandwidthBps uint64 = 100_000_000 // 100 Mbps

	// DefaultMaxVNIs is the default maximum number of VNIs a gateway can handle.
	DefaultMaxVNIs int = 16384

	// DefaultMaxPeers is the default maximum number of BGP peers.
	DefaultMaxPeers int = 256

	// DefaultMaxServices is the default maximum number of services.
	DefaultMaxServices int = 4096
)

// ServiceHandler defines the interface for gateway service handlers.
// Each service (overlay, edge, firewall, NAT, etc.) implements this interface
// and is activated based on its config section presence and enabled flag.
type ServiceHandler interface {
	// Name returns the service handler name.
	Name() string

	// Start starts the service handler.
	Start(ctx context.Context) error

	// Stop stops the service handler.
	Stop(ctx context.Context) error

	// IsActive returns true if the service handler is currently active.
	IsActive() bool

	// Health returns nil if the service handler is healthy, or an error describing the issue.
	Health() error
}

// PortState represents the operational state of an uplink port.
type PortState uint8

const (
	// PortStateUnknown indicates the port state is unknown.
	PortStateUnknown PortState = iota

	// PortStateUp indicates the port is operational.
	PortStateUp

	// PortStateDown indicates the port is not operational.
	PortStateDown

	// PortStateError indicates the port is in an error state.
	PortStateError
)

// String returns a human-readable representation of the port state.
func (s PortState) String() string {
	switch s {
	case PortStateUp:
		return "up"
	case PortStateDown:
		return "down"
	case PortStateError:
		return "error"
	default:
		return "unknown"
	}
}

// Valid returns true if the port state is a valid value.
func (s PortState) Valid() bool {
	return s <= PortStateError
}

// IsUp returns true if the port is operational.
func (s PortState) IsUp() bool {
	return s == PortStateUp
}

// GatewayState represents the operational state of a gateway.
type GatewayState uint8

const (
	// GatewayStateUnknown indicates the gateway state is unknown.
	GatewayStateUnknown GatewayState = iota

	// GatewayStateInitializing indicates the gateway is initializing.
	GatewayStateInitializing

	// GatewayStateRunning indicates the gateway is running normally.
	GatewayStateRunning

	// GatewayStateDegraded indicates the gateway is running with reduced capacity.
	GatewayStateDegraded

	// GatewayStateStopping indicates the gateway is shutting down.
	GatewayStateStopping

	// GatewayStateStopped indicates the gateway is stopped.
	GatewayStateStopped

	// GatewayStateError indicates the gateway is in an error state.
	GatewayStateError
)

// String returns a human-readable representation of the gateway state.
func (s GatewayState) String() string {
	switch s {
	case GatewayStateInitializing:
		return "initializing"
	case GatewayStateRunning:
		return "running"
	case GatewayStateDegraded:
		return "degraded"
	case GatewayStateStopping:
		return "stopping"
	case GatewayStateStopped:
		return "stopped"
	case GatewayStateError:
		return "error"
	default:
		return "unknown"
	}
}

// Valid returns true if the gateway state is a valid value.
func (s GatewayState) Valid() bool {
	return s >= GatewayStateUnknown && s <= GatewayStateError
}

// IsHealthy returns true if the gateway is in a healthy operational state.
func (s GatewayState) IsHealthy() bool {
	return s == GatewayStateRunning
}

// IsOperational returns true if the gateway is operational (running or degraded).
func (s GatewayState) IsOperational() bool {
	return s == GatewayStateRunning || s == GatewayStateDegraded
}

// UplinkPort represents a physical network uplink for the gateway.
type UplinkPort struct {
	// Name is the interface name (e.g., "eth0", "ens192").
	Name string

	// VLAN is the VLAN ID for this uplink (0 for untagged).
	VLAN uint16

	// Speed is the link speed in bits per second.
	Speed uint64

	// MTU is the Maximum Transmission Unit size.
	MTU int

	// State is the current operational state of the port.
	State PortState

	// IPAddresses are the IP addresses assigned to this uplink.
	IPAddresses []netip.Addr

	// MACAddress is the hardware MAC address of the interface.
	MACAddress net.HardwareAddr
}

// Valid returns true if the uplink port configuration is valid.
func (p *UplinkPort) Valid() bool {
	return p.Name != "" && p.MTU > 0 && p.Speed > 0
}

// OverlayGatewayState holds state specific to the overlay service.
type OverlayGatewayState struct {
	// ActiveVNIs is the number of active VNIs being served.
	ActiveVNIs int

	// TunnelCount is the number of active VXLAN tunnels.
	TunnelCount int

	// RemoteVTEPs is the list of remote VTEP addresses.
	RemoteVTEPs []netip.Addr

	// EVPNRoutesReceived is the count of EVPN routes received.
	EVPNRoutesReceived int

	// EVPNRoutesAdvertised is the count of EVPN routes advertised.
	EVPNRoutesAdvertised int

	// LastBGPUpdate is the timestamp of the last BGP update.
	LastBGPUpdate time.Time
}

// EdgeGatewayState holds state specific to the edge service.
type EdgeGatewayState struct {
	// ConnectedDevices is the number of connected IoT/P2P devices.
	ConnectedDevices int

	// ActiveServices is the number of active edge services.
	ActiveServices int

	// NATSessionCount is the number of active NAT sessions.
	NATSessionCount int

	// LoadBalancedConnections is the count of load-balanced connections.
	LoadBalancedConnections int

	// LastHealthCheck is the timestamp of the last health check.
	LastHealthCheck time.Time
}

// TransitGatewayState holds state specific to the transit service.
type TransitGatewayState struct {
	// AnnouncedPrefixes is the number of prefixes being announced.
	AnnouncedPrefixes int

	// ReceivedPrefixes is the number of prefixes received from peers.
	ReceivedPrefixes int

	// BGPPeersEstablished is the number of established BGP peer sessions.
	BGPPeersEstablished int

	// IPv6PrefixesAnnounced is the count of IPv6 prefixes announced.
	IPv6PrefixesAnnounced int

	// IPv4PrefixesAnnounced is the count of IPv4 prefixes announced.
	IPv4PrefixesAnnounced int

	// LastRouteUpdate is the timestamp of the last route update.
	LastRouteUpdate time.Time
}

// GatewayNode represents a gateway node in the SDN overlay network.
type GatewayNode struct {
	// ID is a unique identifier for the gateway node.
	ID string

	// NodeID is the DHT node identifier.
	NodeID uint64

	// Tier is the BGP speaker tier (backbone, datacenter, coordinator).
	Tier bgp.SpeakerTier

	// ActiveServices is the set of currently active service handler names.
	ActiveServices map[string]bool

	// Reputation is the node's reputation score (must be >= 0.85).
	Reputation float64

	// Age is how long the node has been active (must be >= 175 days).
	Age time.Duration

	// Uptime is the node's uptime percentage (must be >= 95%).
	Uptime float64

	// UplinkPorts are the physical network uplinks.
	UplinkPorts []UplinkPort

	// AnycastIP is the shared anycast gateway IP address.
	AnycastIP net.IP

	// IPv6Pool is the allocatable IPv6 address range.
	IPv6Pool net.IPNet

	// IPv4Pool is the allocatable IPv4 address range (for transit mode).
	IPv4Pool net.IPNet

	// BGPConfig is the BGP configuration for this gateway.
	BGPConfig *bgp.BGPConfig

	// OverlayState holds overlay service specific state.
	OverlayState *OverlayGatewayState

	// EdgeState holds edge service specific state.
	EdgeState *EdgeGatewayState

	// TransitState holds transit service specific state.
	TransitState *TransitGatewayState

	// CreatedAt is when this gateway node was created.
	CreatedAt time.Time

	// UpdatedAt is when this gateway node was last updated.
	UpdatedAt time.Time
}

// MeetsMinReputation returns true if the node meets the minimum reputation requirement.
func (n *GatewayNode) MeetsMinReputation() bool {
	return n.Reputation >= MinReputation
}

// MeetsMinAge returns true if the node meets the minimum age requirement.
func (n *GatewayNode) MeetsMinAge() bool {
	minAge := time.Duration(MinAgeDays) * 24 * time.Hour
	return n.Age >= minAge
}

// MeetsMinUptime returns true if the node meets the minimum uptime requirement.
func (n *GatewayNode) MeetsMinUptime() bool {
	return n.Uptime >= MinUptimePct
}

// MeetsAllRequirements returns true if the node meets all gateway requirements.
func (n *GatewayNode) MeetsAllRequirements() bool {
	return n.MeetsMinReputation() && n.MeetsMinAge() && n.MeetsMinUptime()
}

// HasService returns true if the specified service is active.
func (n *GatewayNode) HasService(name string) bool {
	if n.ActiveServices == nil {
		return false
	}
	return n.ActiveServices[name]
}

// GatewayCapabilities defines what functionality a gateway supports.
type GatewayCapabilities struct {
	// OverlaySupported indicates if overlay service is supported.
	OverlaySupported bool

	// EdgeSupported indicates if edge service is supported.
	EdgeSupported bool

	// TransitSupported indicates if transit service is supported.
	TransitSupported bool

	// MaxVNIs is the maximum number of VNIs this gateway can handle.
	MaxVNIs int

	// MaxPeers is the maximum number of BGP peers.
	MaxPeers int

	// MaxServices is the maximum number of edge services.
	MaxServices int

	// MaxBandwidthBps is the maximum bandwidth in bits per second.
	MaxBandwidthBps uint64

	// IPv6Supported indicates if IPv6 is supported.
	IPv6Supported bool

	// IPv4Supported indicates if IPv4 is supported.
	IPv4Supported bool

	// NATSupported indicates if NAT is supported.
	NATSupported bool

	// LoadBalancingSupported indicates if load balancing is supported.
	LoadBalancingSupported bool
}

// DefaultCapabilities returns default gateway capabilities.
func DefaultCapabilities() GatewayCapabilities {
	return GatewayCapabilities{
		OverlaySupported:       true,
		EdgeSupported:          true,
		TransitSupported:       false, // Requires additional setup
		MaxVNIs:                DefaultMaxVNIs,
		MaxPeers:               DefaultMaxPeers,
		MaxServices:            DefaultMaxServices,
		MaxBandwidthBps:        MinBandwidthBps,
		IPv6Supported:          true,
		IPv4Supported:          true,
		NATSupported:           true,
		LoadBalancingSupported: true,
	}
}

// UplinkConfig holds configuration for an uplink port.
type UplinkConfig struct {
	// Name is the interface name.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// VLAN is the VLAN ID (0 for untagged).
	VLAN uint16 `yaml:"vlan,omitempty" json:"vlan,omitempty" mapstructure:"vlan"`

	// MTU is the MTU size.
	MTU int `yaml:"mtu" json:"mtu" mapstructure:"mtu"`

	// IPAddresses are the IP addresses to assign.
	IPAddresses []string `yaml:"ip-addresses,omitempty" json:"ip_addresses,omitempty" mapstructure:"ip-addresses"`

	// PCIAddress is the PCI address of the uplink NIC (e.g.
	// "0000:03:00.0"), used for DPDK uplink ports on the netdev datapath.
	PCIAddress string `yaml:"pci-address,omitempty" json:"pci_address,omitempty" mapstructure:"pci-address"`
}

// Validate checks if the uplink configuration is valid.
func (c *UplinkConfig) Validate() error {
	if c.Name == "" {
		return ErrUplinkNotFound
	}
	if c.MTU <= 0 {
		return ErrConfigurationInvalid
	}
	return nil
}

// OverlayServiceConfig holds overlay gateway specific configuration.
const (
	// MaxOverlayVNI is the largest VXLAN Network Identifier (24 bits).
	MaxOverlayVNI uint32 = 0xFFFFFF

	// MaxOverlayVLAN is the largest access VLAN an L2VNI can be carried on.
	MaxOverlayVLAN uint16 = 4094
)

// OverlayVNIConfig is one L2VNI the overlay joins, and the access VLAN that
// carries it on the access port.
type OverlayVNIConfig struct {
	VNI  uint32 `yaml:"vni" json:"vni" mapstructure:"vni"`
	VLAN uint16 `yaml:"vlan" json:"vlan" mapstructure:"vlan"`
}

type OverlayServiceConfig struct {
	// Enabled indicates if the overlay service is enabled.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// LocalVTEP is the gateway's VTEP address on the fabric VLAN.
	LocalVTEP netip.Addr `yaml:"local-vtep,omitempty" json:"local_vtep,omitempty" mapstructure:"local-vtep"`

	// UnderlayInterface is the host interface carrying fabric VTEP traffic.
	UnderlayInterface string `yaml:"underlay-interface,omitempty" json:"underlay_interface,omitempty" mapstructure:"underlay-interface"`

	// UnderlayMTU is the MTU of the fabric underlay interface. Zero defaults
	// to the overlay handler's minimum VXLAN-safe MTU.
	UnderlayMTU int `yaml:"underlay-mtu,omitempty" json:"underlay_mtu,omitempty" mapstructure:"underlay-mtu"`

	// AccessPort is the OVS port that carries local workload VLANs into the overlay.
	AccessPort string `yaml:"access-port,omitempty" json:"access_port,omitempty" mapstructure:"access-port"`

	// OverlayASN is the EVPN overlay ASN used for route targets and RR sessions.
	OverlayASN uint32 `yaml:"overlay-asn,omitempty" json:"overlay_asn,omitempty" mapstructure:"overlay-asn"`

	// RRPeers are route-reflector peers for the EVPN address family. The schema
	// is the same BGP peer shape used by the gateway transit service.
	RRPeers []bgp.NeighborConfig `yaml:"rr-peers,omitempty" json:"rr_peers,omitempty" mapstructure:"rr-peers"`

	// VXLANPort is the UDP port for VXLAN encapsulation.
	VXLANPort uint16 `yaml:"vxlan-port,omitempty" json:"vxlan_port,omitempty" mapstructure:"vxlan-port"`

	// VNIs are the L2VNIs the gateway joins when the overlay starts, each
	// carried on its own access VLAN. The overlay is not healthy until every
	// one is joined.
	VNIs []OverlayVNIConfig `yaml:"vnis,omitempty" json:"vnis,omitempty" mapstructure:"vnis"`

	// DefaultVNI is the default VXLAN Network Identifier. When set it must
	// name one of VNIs.
	DefaultVNI uint32 `yaml:"default-vni,omitempty" json:"default_vni,omitempty" mapstructure:"default-vni"`

	// MaxVNIs is the maximum number of VNIs.
	MaxVNIs int `yaml:"max-vnis,omitempty" json:"max_vnis,omitempty" mapstructure:"max-vnis"`

	// VerdictMaxAge bounds the age of the latest signed attestation verdict
	// accepted for remote VTEP admission. Zero defaults to
	// DefaultOverlayVerdictMaxAge.
	VerdictMaxAge time.Duration `yaml:"verdict-max-age,omitempty" json:"verdict_max_age,omitempty" mapstructure:"verdict-max-age"`

	// VerdictClockSkew bounds how far past the gateway's clock a verdict's
	// attestation time may lie and still admit a VTEP. Zero defaults to
	// DefaultOverlayVerdictClockSkew.
	VerdictClockSkew time.Duration `yaml:"verdict-clock-skew,omitempty" json:"verdict_clock_skew,omitempty" mapstructure:"verdict-clock-skew"`

	// AdmissionSweepInterval is how often every installed remote VTEP is
	// re-judged against the admission policy. Zero defaults to
	// DefaultOverlayAdmissionSweepInterval.
	AdmissionSweepInterval time.Duration `yaml:"admission-sweep-interval,omitempty" json:"admission_sweep_interval,omitempty" mapstructure:"admission-sweep-interval"`
}

// Validate checks if the overlay service configuration is valid.
func (c *OverlayServiceConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if !c.LocalVTEP.IsValid() || !c.LocalVTEP.Is4() || c.LocalVTEP.IsUnspecified() {
		return &ErrOverlayConfigInvalid{Field: "local-vtep", Reason: "must be a specified IPv4 address"}
	}
	if c.UnderlayInterface == "" {
		return &ErrOverlayConfigInvalid{Field: "underlay-interface", Reason: "is required"}
	}
	if c.UnderlayMTU == 0 {
		c.UnderlayMTU = vxlan.MinimumUnderlayMTU
	}
	if c.UnderlayMTU < vxlan.MinimumUnderlayMTU {
		return &ErrOverlayConfigInvalid{Field: "underlay-mtu", Reason: fmt.Sprintf("must be at least %d", vxlan.MinimumUnderlayMTU)}
	}
	if c.AccessPort == "" {
		return &ErrOverlayConfigInvalid{Field: "access-port", Reason: "is required"}
	}
	// EVPN route targets carry the ASN in a 2-octet field, so only the
	// private 2-octet range the route-target derivation accepts can run.
	if c.OverlayASN < uint32(bgp.MinOverlayASN) || c.OverlayASN > uint32(bgp.MaxOverlayASN) {
		return &ErrOverlayConfigInvalid{
			Field:  "overlay-asn",
			Reason: fmt.Sprintf("must be a private 2-octet ASN (%d-%d)", bgp.MinOverlayASN, bgp.MaxOverlayASN),
		}
	}
	// The overlay speaker only dials its route reflectors (it shares the
	// host with the transit speaker's listener), so a peer waiting to be
	// dialled would never come up.
	for _, peer := range c.RRPeers {
		if peer.PassiveMode {
			return &ErrOverlayConfigInvalid{Field: "rr-peers", Reason: fmt.Sprintf("peer %s is passive; the overlay speaker only dials", peer.Address)}
		}
	}
	if c.VXLANPort == 0 {
		return &ErrOverlayConfigInvalid{Field: "vxlan-port", Reason: "is required"}
	}
	if c.MaxVNIs < 0 {
		return &ErrOverlayConfigInvalid{Field: "max-vnis", Reason: "must not be negative"}
	}
	if err := c.validateVNIs(); err != nil {
		return err
	}
	if c.VerdictMaxAge < 0 {
		return &ErrOverlayConfigInvalid{Field: "verdict-max-age", Reason: "must not be negative"}
	}
	if c.VerdictClockSkew < 0 {
		return &ErrOverlayConfigInvalid{Field: "verdict-clock-skew", Reason: "must not be negative"}
	}
	if c.AdmissionSweepInterval < 0 {
		return &ErrOverlayConfigInvalid{Field: "admission-sweep-interval", Reason: "must not be negative"}
	}
	if c.VerdictMaxAge == 0 {
		c.VerdictMaxAge = DefaultOverlayVerdictMaxAge
	}
	return nil
}

// validateVNIs checks the VNIs the overlay joins at start: at least one, each
// a 24-bit VNI on its own access VLAN, within max-vnis, and default-vni among
// them. An overlay with no VNI would report running while forwarding nothing.
func (c *OverlayServiceConfig) validateVNIs() error {
	if len(c.VNIs) == 0 {
		return &ErrOverlayConfigInvalid{Field: "vnis", Reason: "at least one VNI is required"}
	}
	if c.MaxVNIs > 0 && len(c.VNIs) > c.MaxVNIs {
		return &ErrOverlayConfigInvalid{Field: "vnis", Reason: fmt.Sprintf("%d VNIs exceed max-vnis %d", len(c.VNIs), c.MaxVNIs)}
	}
	vnis := make(map[uint32]struct{}, len(c.VNIs))
	vlans := make(map[uint16]struct{}, len(c.VNIs))
	for _, v := range c.VNIs {
		if v.VNI == 0 || v.VNI > MaxOverlayVNI {
			return &ErrOverlayConfigInvalid{Field: "vnis", Reason: fmt.Sprintf("VNI %d is outside 1-%d", v.VNI, MaxOverlayVNI)}
		}
		if v.VLAN == 0 || v.VLAN > MaxOverlayVLAN {
			return &ErrOverlayConfigInvalid{Field: "vnis", Reason: fmt.Sprintf("VNI %d: VLAN %d is outside 1-%d", v.VNI, v.VLAN, MaxOverlayVLAN)}
		}
		if _, dup := vnis[v.VNI]; dup {
			return &ErrOverlayConfigInvalid{Field: "vnis", Reason: fmt.Sprintf("VNI %d is listed twice", v.VNI)}
		}
		if _, dup := vlans[v.VLAN]; dup {
			return &ErrOverlayConfigInvalid{Field: "vnis", Reason: fmt.Sprintf("VLAN %d carries two VNIs", v.VLAN)}
		}
		vnis[v.VNI] = struct{}{}
		vlans[v.VLAN] = struct{}{}
	}
	if _, listed := vnis[c.DefaultVNI]; c.DefaultVNI != 0 && !listed {
		return &ErrOverlayConfigInvalid{Field: "default-vni", Reason: fmt.Sprintf("VNI %d is not one of vnis", c.DefaultVNI)}
	}
	return nil
}

// admissionSweepInterval is how often installed VTEPs are re-admitted: the
// configured interval, or DefaultOverlayAdmissionSweepInterval when unset.
func (c *OverlayServiceConfig) admissionSweepInterval() time.Duration {
	if c.AdmissionSweepInterval <= 0 {
		return DefaultOverlayAdmissionSweepInterval
	}
	return c.AdmissionSweepInterval
}

// EdgeConfig holds edge gateway specific configuration.
type EdgeConfig struct {
	// Enabled indicates if edge service is enabled.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// MaxDevices is the maximum number of connected devices.
	MaxDevices int `yaml:"max-devices" json:"max_devices" mapstructure:"max-devices"`

	// MaxServices is the maximum number of edge services.
	MaxServices int `yaml:"max-services" json:"max_services" mapstructure:"max-services"`

	// ServiceDiscoveryEnabled enables service discovery.
	ServiceDiscoveryEnabled bool `yaml:"service-discovery" json:"service_discovery" mapstructure:"service-discovery"`

	// P2PEnabled enables peer-to-peer connectivity.
	P2PEnabled bool `yaml:"p2p" json:"p2p" mapstructure:"p2p"`
}

// Validate checks if the edge configuration is valid.
func (c *EdgeConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.MaxDevices <= 0 {
		return ErrConfigurationInvalid
	}
	if c.MaxServices <= 0 {
		return ErrConfigurationInvalid
	}
	return nil
}

// FirewallConfig holds stateful firewall configuration.
type FirewallConfig struct {
	// Enabled indicates if the firewall service is enabled.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// DefaultPolicy is the default firewall policy ("allow" or "deny").
	DefaultPolicy string `yaml:"default-policy" json:"default_policy" mapstructure:"default-policy"`

	// Bridge optionally overrides the runtime-injected OVS bridge that
	// carries the conntrack pipeline.
	Bridge string `yaml:"bridge,omitempty" json:"bridge,omitempty" mapstructure:"bridge"`
}

// Validate checks if the firewall configuration is valid.
func (c *FirewallConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.DefaultPolicy != "allow" && c.DefaultPolicy != "deny" {
		return ErrConfigurationInvalid
	}
	return nil
}

// TunnelConfig is the tunnel package's own configuration, not a copy of it:
// the `tunnels:` section decodes straight into the type the manager
// consumes, so a field added to pkg/sdn/tunnel is reachable from a gatewayd
// YAML file the moment it exists, and nothing here can drop one. Validation
// is the tunnel package's too (typed *tunnel.ErrInvalidTunnelConfig,
// *tunnel.ErrTransportUnavailable for wireguard under the fips build tag).
type TunnelConfig = tunnel.TunnelConfig

// RoutingUplinkConfig is a WAN uplink's policy-routing table, which tunnels
// name through `uplink:` to pin their outer packets to one ISP. It is not
// the NAT/NIC UplinkConfig above: that one describes a physical port the NAT
// and load-balancer services bind to.
type RoutingUplinkConfig = tunnel.UplinkConfig

// validateTunnels checks the routing uplinks and the tunnels that reference
// them. An uplink name or table used twice, and a tunnel naming an uplink the
// section does not declare, are refused here at load time rather than as a
// half-programmed routing state at Start.
func (c *GatewayConfig) validateTunnels() error {
	declared := make(map[string]struct{}, len(c.RoutingUplinks))
	tables := make(map[int]string, len(c.RoutingUplinks))
	for i := range c.RoutingUplinks {
		up := &c.RoutingUplinks[i]
		if err := up.Validate(); err != nil {
			return err
		}
		if _, dup := declared[up.Name]; dup {
			return &tunnel.ErrInvalidUplinkConfig{Name: up.Name, Reason: "name is declared more than once"}
		}
		if other, dup := tables[up.Table]; dup {
			return &tunnel.ErrInvalidUplinkConfig{Name: up.Name, Reason: "table " + strconv.Itoa(up.Table) + " is already used by uplink " + other}
		}
		declared[up.Name] = struct{}{}
		tables[up.Table] = up.Name
	}
	for i := range c.Tunnels {
		if err := c.Tunnels[i].Validate(); err != nil {
			return err
		}
		if name := c.Tunnels[i].Uplink; name != "" {
			if _, ok := declared[name]; !ok {
				return &tunnel.ErrUplinkUnknown{Name: c.Tunnels[i].Name, Uplink: name}
			}
		}
	}
	return nil
}

// DHCPServiceConfig holds DHCP server configuration for the gateway.
type DHCPServiceConfig struct {
	// Enabled indicates if the DHCP service is enabled.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Interface is the network interface to bind.
	Interface string `yaml:"interface" json:"interface" mapstructure:"interface"`

	// Zone is the zone name used to resolve the IPAM pool for this DHCP service.
	// The gateway selects a pool by calling Allocator.ListPoolsByZone with this
	// value. Explicit PoolStart/PoolEnd values take precedence over zone-derived
	// selection (explicit beats derived).
	//
	// Precedence (highest first): PoolStart+PoolEnd → Zone.
	Zone string `yaml:"zone,omitempty" json:"zone,omitempty" mapstructure:"zone"`

	// PoolStart is the start of the DHCP address pool.
	PoolStart string `yaml:"pool-start,omitempty" json:"pool_start,omitempty" mapstructure:"pool-start"`

	// PoolEnd is the end of the DHCP address pool.
	PoolEnd string `yaml:"pool-end,omitempty" json:"pool_end,omitempty" mapstructure:"pool-end"`

	// LeaseDuration is the DHCP lease duration.
	LeaseDuration time.Duration `yaml:"lease-duration,omitempty" json:"lease_duration,omitempty" mapstructure:"lease-duration"`
}

// Validate checks if the DHCP service configuration is valid.
func (c *DHCPServiceConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Interface == "" {
		return ErrConfigurationInvalid
	}
	return nil
}

// PXEServiceConfig holds PXE boot server configuration for the gateway.
type PXEServiceConfig struct {
	// Enabled indicates if the PXE service is enabled.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// HTTPPort is the HTTP server port for boot scripts and files.
	HTTPPort int `yaml:"http-port,omitempty" json:"http_port,omitempty" mapstructure:"http-port"`

	// TFTPPort is the TFTP server port for firmware delivery.
	TFTPPort int `yaml:"tftp-port,omitempty" json:"tftp_port,omitempty" mapstructure:"tftp-port"`

	// KernelPath is the local filesystem path to the kernel image.
	KernelPath string `yaml:"kernel-path,omitempty" json:"kernel_path,omitempty" mapstructure:"kernel-path"`

	// InitrdPath is the local filesystem path to the initrd image.
	InitrdPath string `yaml:"initrd-path,omitempty" json:"initrd_path,omitempty" mapstructure:"initrd-path"`

	// ConfigServerURL is the control plane address for config delivery.
	ConfigServerURL string `yaml:"config-server-url,omitempty" json:"config_server_url,omitempty" mapstructure:"config-server-url"`

	// BootstrapStrategy is the default bootstrap trust strategy.
	BootstrapStrategy string `yaml:"bootstrap-strategy,omitempty" json:"bootstrap_strategy,omitempty" mapstructure:"bootstrap-strategy"`
}

// Validate checks if the PXE service configuration is valid.
func (c *PXEServiceConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.HTTPPort <= 0 {
		return ErrConfigurationInvalid
	}
	return nil
}

// NATConfig holds NAT gateway configuration.
type NATConfig struct {
	// Enabled indicates if NAT is enabled.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// ExternalIP is the external NAT IP address.
	ExternalIP string `yaml:"external-ip" json:"external_ip" mapstructure:"external-ip"`

	// PortRangeStart is the start of the NAT port range.
	PortRangeStart uint16 `yaml:"port-range-start" json:"port_range_start" mapstructure:"port-range-start"`

	// PortRangeEnd is the end of the NAT port range.
	PortRangeEnd uint16 `yaml:"port-range-end" json:"port_range_end" mapstructure:"port-range-end"`

	// MaxSessions is the maximum number of NAT sessions.
	MaxSessions int `yaml:"max-sessions" json:"max_sessions" mapstructure:"max-sessions"`

	// InternalCIDR is the IPv4 prefix whose egress traffic is source-NATed
	// to ExternalIP. Empty disables automatic SNAT at service start.
	InternalCIDR string `yaml:"internal-cidr,omitempty" json:"internal_cidr,omitempty" mapstructure:"internal-cidr"`

	// UplinkPort is the OVS port name of the uplink used for DNAT ingress
	// matching. When empty, the first configured gateway uplink is used.
	UplinkPort string `yaml:"uplink-port,omitempty" json:"uplink_port,omitempty" mapstructure:"uplink-port"`

	// Bridge optionally overrides the runtime-injected OVS bridge that
	// carries the NAT tables.
	Bridge string `yaml:"bridge,omitempty" json:"bridge,omitempty" mapstructure:"bridge"`

	// Uplinks, when set, gives NAT one SNAT pool per uplink instead of the
	// single ExternalIP (#586): egress is translated to the pool of the
	// uplink it leaves through — the default uplink unless another uplink's
	// destination prefix matches. ExternalIP is then optional.
	Uplinks []NATUplinkConfig `yaml:"uplinks,omitempty" json:"uplinks,omitempty" mapstructure:"uplinks"`

	// Static are 1:1 address translations, each bound to an uplink (the
	// default when unnamed), translated in both directions with hairpin
	// for internal clients addressing the external address (#586).
	Static []NATStaticConfig `yaml:"static,omitempty" json:"static,omitempty" mapstructure:"static"`
}

// NATUplinkConfig is one SNAT pool bound to a gateway uplink.
type NATUplinkConfig struct {
	// Name matches a gateway UplinkConfig.Name.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// Port is the OVS port name of the uplink; empty means Name.
	Port string `yaml:"port,omitempty" json:"port,omitempty" mapstructure:"port"`

	// Addresses is the IPv4 pool: single addresses or inclusive ranges
	// ("192.0.2.4-192.0.2.5").
	Addresses []string `yaml:"addresses" json:"addresses" mapstructure:"addresses"`

	// PortRangeStart and PortRangeEnd override the NAT-wide port range for
	// this uplink; zero inherits it.
	PortRangeStart uint16 `yaml:"port-range-start,omitempty" json:"port_range_start,omitempty" mapstructure:"port-range-start"`
	PortRangeEnd   uint16 `yaml:"port-range-end,omitempty" json:"port_range_end,omitempty" mapstructure:"port-range-end"`

	// Destinations are IPv4 prefixes whose egress leaves through this
	// uplink regardless of the default.
	Destinations []string `yaml:"destinations,omitempty" json:"destinations,omitempty" mapstructure:"destinations"`

	// Default marks the uplink carrying every destination no other uplink
	// claims; the first uplink is the default when none is marked.
	Default bool `yaml:"default,omitempty" json:"default,omitempty" mapstructure:"default"`
}

// NATStaticConfig is one 1:1 translation.
type NATStaticConfig struct {
	// Internal is the inside IPv4 address.
	Internal string `yaml:"internal" json:"internal" mapstructure:"internal"`

	// External is the public IPv4 address on Uplink.
	External string `yaml:"external" json:"external" mapstructure:"external"`

	// Uplink names the NAT uplink; empty means the default.
	Uplink string `yaml:"uplink,omitempty" json:"uplink,omitempty" mapstructure:"uplink"`
}

// Validate checks if the NAT configuration is valid. The detailed pool,
// destination and static validation is the NAT service's (#586); this
// checks what the gateway can decide without a datapath.
func (c *NATConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.ExternalIP == "" && len(c.Uplinks) == 0 {
		return ErrConfigurationInvalid
	}
	if c.PortRangeStart >= c.PortRangeEnd {
		return ErrConfigurationInvalid
	}
	if c.MaxSessions <= 0 {
		return ErrConfigurationInvalid
	}
	if len(c.Static) > 0 && len(c.Uplinks) == 0 {
		return ErrConfigurationInvalid
	}
	seen := make(map[string]struct{}, len(c.Uplinks))
	for _, u := range c.Uplinks {
		if u.Name == "" || len(u.Addresses) == 0 {
			return ErrConfigurationInvalid
		}
		if _, dup := seen[u.Name]; dup {
			return ErrConfigurationInvalid
		}
		seen[u.Name] = struct{}{}
	}
	for _, st := range c.Static {
		if st.Internal == "" || st.External == "" {
			return ErrConfigurationInvalid
		}
		if st.Uplink != "" {
			if _, ok := seen[st.Uplink]; !ok {
				return ErrConfigurationInvalid
			}
		}
	}
	return nil
}

// NAT64Config holds the stateful NAT64 translator configuration (#601,
// ruling R6). The gateway owns a Jool kernel instance the way it owns the
// nftables table: it renders the instance, applies it, verifies it and
// refuses to start when the kernel cannot carry it. The packet path is in
// docs/gateway/engineering.md §"IPv6-only clients"; the decision and its
// alternatives are in docs/gateway/architecture.md.
type NAT64Config struct {
	// Enabled indicates whether the translator runs on this gateway.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Prefix is the RFC 6052 translation prefix (pool6). Empty takes the
	// well-known 64:ff9b::/96.
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty" mapstructure:"prefix"`

	// Instance is the kernel instance name. Empty takes a platform default.
	Instance string `yaml:"instance,omitempty" json:"instance,omitempty" mapstructure:"instance"`

	// TranslatorPort is the OVS port the table-27 gate outputs to: the
	// internal port whose host side the translator's netfilter hooks see.
	// There is no default; a wrong guess is a black hole.
	TranslatorPort string `yaml:"translator-port" json:"translator_port" mapstructure:"translator-port"`

	// Bridge overrides the runtime bridge carrying the gate flows.
	Bridge string `yaml:"bridge,omitempty" json:"bridge,omitempty" mapstructure:"bridge"`

	// Pool4 is the IPv4 pool the translator allocates from.
	Pool4 NAT64Pool4Config `yaml:"pool4" json:"pool4" mapstructure:"pool4"`

	// SessionTimeouts are the RFC 6146 §3.5 session lifetimes; a zero
	// field takes its RFC default.
	SessionTimeouts NAT64TimeoutsConfig `yaml:"session-timeouts,omitempty" json:"session_timeouts,omitempty" mapstructure:"session-timeouts"`

	// ClientZones names the zones whose traffic to the prefix is diverted.
	// Empty diverts every frame addressed to the prefix. Naming zones is
	// how the operator keeps the divert a policy decision: it outranks the
	// firewall's zone gate, so an unnamed zone gets no translation.
	ClientZones []NAT64ClientZoneConfig `yaml:"client-zones,omitempty" json:"client_zones,omitempty" mapstructure:"client-zones"`
}

// NAT64Pool4Config is the translator's IPv4 pool. It reuses the NAT
// service's pool model rather than inventing a second one, and its ranges
// must not overlap any NAT44 pool or static external address: two
// allocators handing out one address:port pair produce a collision no
// capture explains.
type NAT64Pool4Config struct {
	// Uplink names the nat.uplinks entry the pool's addresses belong to.
	// Optional. When set it must name a configured NAT uplink, which is
	// checked at validation; it is reported in status. It does not steer
	// egress: Jool emits the translated packet into the host stack, which
	// routes it by destination like any host-originated packet.
	Uplink string `yaml:"uplink,omitempty" json:"uplink,omitempty" mapstructure:"uplink"`

	// Addresses are single addresses ("203.0.113.64") or inclusive ranges
	// ("203.0.113.64-203.0.113.71").
	Addresses []string `yaml:"addresses" json:"addresses" mapstructure:"addresses"`

	// PortRangeStart and PortRangeEnd bound the ports the translator
	// allocates on every address.
	PortRangeStart uint16 `yaml:"port-range-start" json:"port_range_start" mapstructure:"port-range-start"`
	PortRangeEnd   uint16 `yaml:"port-range-end" json:"port_range_end" mapstructure:"port-range-end"`
}

// NAT64TimeoutsConfig carries the RFC 6146 session lifetimes.
type NAT64TimeoutsConfig struct {
	// UDP is the UDP session lifetime (RFC 6146 default 5m, minimum 2m).
	UDP time.Duration `yaml:"udp,omitempty" json:"udp,omitempty" mapstructure:"udp"`

	// TCPEstablished is the established TCP lifetime (default and minimum
	// 2h4m).
	TCPEstablished time.Duration `yaml:"tcp-established,omitempty" json:"tcp_established,omitempty" mapstructure:"tcp-established"`

	// TCPTransitory is the transitory TCP lifetime (default and minimum 4m).
	TCPTransitory time.Duration `yaml:"tcp-transitory,omitempty" json:"tcp_transitory,omitempty" mapstructure:"tcp-transitory"`

	// ICMP is the ICMP query lifetime (default and minimum 60s).
	ICMP time.Duration `yaml:"icmp,omitempty" json:"icmp,omitempty" mapstructure:"icmp"`
}

// NAT64ClientZoneConfig names one zone whose frames are diverted.
type NAT64ClientZoneConfig struct {
	// Name is the zone name, for status and flow provenance.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// VLAN is the zone's VLAN ID; the divert matches it.
	VLAN uint16 `yaml:"vlan" json:"vlan" mapstructure:"vlan"`
}

// ServiceConfig maps the serialized section onto the nat64 package's own
// configuration type. The nat64 package owns its validation; this is the
// only place the two vocabularies meet.
func (c *NAT64Config) ServiceConfig(bridge string) nat64.Config {
	pool := make([]nat64.Pool4Range, 0, len(c.Pool4.Addresses))
	for _, addr := range c.Pool4.Addresses {
		pool = append(pool, nat64.Pool4Range{
			Addresses: addr,
			PortStart: c.Pool4.PortRangeStart,
			PortEnd:   c.Pool4.PortRangeEnd,
		})
	}
	zones := make([]nat64.ClientZone, 0, len(c.ClientZones))
	for _, z := range c.ClientZones {
		zones = append(zones, nat64.ClientZone{Name: z.Name, VLAN: z.VLAN})
	}
	if c.Bridge != "" {
		bridge = c.Bridge
	}
	return nat64.Config{
		Prefix:         c.Prefix,
		Instance:       c.Instance,
		TranslatorPort: c.TranslatorPort,
		Bridge:         bridge,
		Pool4:          pool,
		Timeouts: nat64.SessionTimeouts{
			UDP:            c.SessionTimeouts.UDP,
			TCPEstablished: c.SessionTimeouts.TCPEstablished,
			TCPTransitory:  c.SessionTimeouts.TCPTransitory,
			ICMP:           c.SessionTimeouts.ICMP,
		},
		ClientZones: zones,
	}
}

// Validate checks the NAT64 section. The prefix, pool and timeout rules are
// the nat64 service's own, so a disabled section validates trivially and an
// enabled one is held to the whole contract before any datapath exists.
func (c *NAT64Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	// A placeholder bridge keeps this a section check: the real bridge
	// arrives from the runtime at build time, and its absence is not a
	// configuration error the operator can fix here.
	cfg := c.ServiceConfig("validate")
	if err := cfg.Validate(); err != nil {
		return &ErrNAT64ConfigInvalid{Cause: err}
	}
	return nil
}

// validateUplink refuses a pool4.uplink that names no configured NAT
// uplink. A name that resolves to nothing would otherwise be reported in
// status as if it meant something.
func (c *NAT64Config) validateUplink(nat *NATConfig) error {
	if !c.Enabled || c.Pool4.Uplink == "" {
		return nil
	}
	if nat != nil && nat.Enabled {
		for _, u := range nat.Uplinks {
			if u.Name == c.Pool4.Uplink {
				return nil
			}
		}
	}
	return &ErrNAT64ConfigInvalid{Cause: &ErrNAT64UplinkUnknown{Uplink: c.Pool4.Uplink}}
}

// LoadBalancerConfig holds load balancer configuration.
type LoadBalancerConfig struct {
	// Enabled indicates if load balancing is enabled.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Algorithm is the default load balancing algorithm ("hash" or
	// "round-robin"; both are hash-based select-group balancing).
	Algorithm string `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`

	// HealthCheckInterval is the interval between health checks.
	HealthCheckInterval time.Duration `yaml:"health-check-interval" json:"health_check_interval" mapstructure:"health-check-interval"`

	// HealthCheckTimeout is the timeout for health checks.
	HealthCheckTimeout time.Duration `yaml:"health-check-timeout" json:"health_check_timeout" mapstructure:"health-check-timeout"`

	// HealthCheckRise is the consecutive probe successes required to mark
	// a backend healthy. Zero defaults to 2.
	HealthCheckRise int `yaml:"health-check-rise,omitempty" json:"health_check_rise,omitempty" mapstructure:"health-check-rise"`

	// HealthCheckFall is the consecutive probe failures required to mark
	// a backend unhealthy. Zero defaults to 3.
	HealthCheckFall int `yaml:"health-check-fall,omitempty" json:"health_check_fall,omitempty" mapstructure:"health-check-fall"`

	// MaxBackends is the maximum number of backend servers per VIP.
	MaxBackends int `yaml:"max-backends" json:"max_backends" mapstructure:"max-backends"`

	// Bridge optionally overrides the runtime-injected OVS bridge that
	// carries the load balancer tables.
	Bridge string `yaml:"bridge,omitempty" json:"bridge,omitempty" mapstructure:"bridge"`

	// HairpinPrefixes are the IPv4 client networks that share a segment
	// with the backends. A connection from one of them to a VIP is
	// source-NATed to the VIP as well, so the backend replies through the
	// gateway instead of straight to the client (which would drop a reply
	// from an address it never connected to).
	HairpinPrefixes []string `yaml:"hairpin-prefixes,omitempty" json:"hairpin_prefixes,omitempty" mapstructure:"hairpin-prefixes"`

	// VIPs are the config-driven virtual IPs installed at service start.
	VIPs []VIPConfig `yaml:"vips,omitempty" json:"vips,omitempty" mapstructure:"vips"`
}

// ServiceHairpinPrefixes parses the configured hairpin prefixes.
func (c *LoadBalancerConfig) ServiceHairpinPrefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.HairpinPrefixes))
	for _, raw := range c.HairpinPrefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() {
			return nil, loadbalancer.ErrInvalidHairpinPrefix
		}
		out = append(out, prefix)
	}
	return out, nil
}

// VIPConfig defines one load-balanced virtual IP.
type VIPConfig struct {
	// Address is the virtual IPv4 address.
	Address string `yaml:"address" json:"address" mapstructure:"address"`

	// Port is the virtual L4 port.
	Port uint16 `yaml:"port" json:"port" mapstructure:"port"`

	// Protocol is "tcp" or "udp".
	Protocol string `yaml:"protocol" json:"protocol" mapstructure:"protocol"`

	// Algorithm optionally overrides the load balancer default algorithm.
	Algorithm string `yaml:"algorithm,omitempty" json:"algorithm,omitempty" mapstructure:"algorithm"`

	// Backends are the load-balanced endpoints.
	Backends []BackendConfig `yaml:"backends" json:"backends" mapstructure:"backends"`
}

// BackendConfig defines one backend endpoint of a VIP.
type BackendConfig struct {
	// Address is the backend IPv4 address.
	Address string `yaml:"address" json:"address" mapstructure:"address"`

	// Port is the backend L4 port.
	Port uint16 `yaml:"port" json:"port" mapstructure:"port"`

	// Weight is the relative selection weight (zero means 1).
	Weight uint16 `yaml:"weight,omitempty" json:"weight,omitempty" mapstructure:"weight"`
}

// ServiceVIP converts the config entry to the load balancer service VIP
// type, parsing the configured addresses.
func (v *VIPConfig) ServiceVIP() (loadbalancer.VIP, error) {
	addr, err := netip.ParseAddr(v.Address)
	if err != nil {
		return loadbalancer.VIP{}, loadbalancer.ErrInvalidVIPAddress
	}
	vip := loadbalancer.VIP{
		Address:   addr,
		Port:      v.Port,
		Protocol:  v.Protocol,
		Algorithm: v.Algorithm,
		Backends:  make([]loadbalancer.Backend, 0, len(v.Backends)),
	}
	for _, b := range v.Backends {
		backendAddr, parseErr := netip.ParseAddr(b.Address)
		if parseErr != nil {
			return loadbalancer.VIP{}, loadbalancer.ErrInvalidBackend
		}
		vip.Backends = append(vip.Backends, loadbalancer.Backend{
			Address: backendAddr,
			Port:    b.Port,
			Weight:  b.Weight,
		})
	}
	return vip, nil
}

// Validate checks if the load balancer configuration is valid.
func (c *LoadBalancerConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Algorithm == "" {
		return ErrConfigurationInvalid
	}
	if c.HealthCheckInterval <= 0 {
		return ErrConfigurationInvalid
	}
	if c.HealthCheckTimeout <= 0 || c.HealthCheckTimeout >= c.HealthCheckInterval {
		return ErrConfigurationInvalid
	}
	if c.HealthCheckRise < 0 || c.HealthCheckFall < 0 {
		return ErrConfigurationInvalid
	}
	if c.MaxBackends <= 0 {
		return ErrConfigurationInvalid
	}
	if _, err := c.ServiceHairpinPrefixes(); err != nil {
		return ErrConfigurationInvalid
	}
	vips := make([]loadbalancer.VIP, 0, len(c.VIPs))
	for i := range c.VIPs {
		vip, err := c.VIPs[i].ServiceVIP()
		if err != nil {
			return ErrConfigurationInvalid
		}
		vips = append(vips, vip)
	}
	// The set as a whole: a duplicate VIP or a shared backend refused here
	// is refused before gatewayd programs any of it.
	if err := loadbalancer.ValidateVIPSet(vips, c.MaxBackends); err != nil {
		return ErrConfigurationInvalid
	}
	return nil
}

// GatewayConfig holds the complete configuration for a gateway node.
// Services are config-driven: if a config section is present and enabled,
// the corresponding service loads automatically. No mode flags needed.
type GatewayConfig struct {
	// Enabled indicates if the gateway is enabled.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// ID is the gateway identifier.
	ID string `yaml:"id" json:"id" mapstructure:"id"`

	// NodeID is the DHT node identifier.
	NodeID uint64 `yaml:"node-id,omitempty" json:"node_id,omitempty" mapstructure:"node-id"`

	// Tier is the BGP speaker tier name.
	Tier string `yaml:"tier,omitempty" json:"tier,omitempty" mapstructure:"tier"`

	// MinReputation is the minimum reputation required.
	MinReputation float64 `yaml:"min-reputation,omitempty" json:"min_reputation,omitempty" mapstructure:"min-reputation"`

	// MinAgeDays is the minimum node age in days.
	MinAgeDays int `yaml:"min-age-days,omitempty" json:"min_age_days,omitempty" mapstructure:"min-age-days"`

	// MinUptimePct is the minimum uptime percentage.
	MinUptimePct float64 `yaml:"min-uptime-pct,omitempty" json:"min_uptime_pct,omitempty" mapstructure:"min-uptime-pct"`

	// AnycastIP is the shared anycast gateway IP address.
	AnycastIP string `yaml:"anycast-ip,omitempty" json:"anycast_ip,omitempty" mapstructure:"anycast-ip"`

	// IPv6Pool is the IPv6 address pool CIDR.
	IPv6Pool string `yaml:"ipv6-pool,omitempty" json:"ipv6_pool,omitempty" mapstructure:"ipv6-pool"`

	// IPv4Pool is the IPv4 address pool CIDR.
	IPv4Pool string `yaml:"ipv4-pool,omitempty" json:"ipv4_pool,omitempty" mapstructure:"ipv4-pool"`

	// Uplinks are the uplink port configurations.
	Uplinks []UplinkConfig `yaml:"uplinks,omitempty" json:"uplinks,omitempty" mapstructure:"uplinks"`

	// Service configs -- each is optional. If present with enabled:true, the service loads.

	// Overlay is the overlay (VXLAN/EVPN) service configuration.
	Overlay *OverlayServiceConfig `yaml:"overlay,omitempty" json:"overlay,omitempty" mapstructure:"overlay"`

	// Edge is the edge (IoT/P2P) service configuration.
	Edge *EdgeConfig `yaml:"edge,omitempty" json:"edge,omitempty" mapstructure:"edge"`

	// Firewall is the stateful firewall service configuration.
	Firewall *FirewallConfig `yaml:"firewall,omitempty" json:"firewall,omitempty" mapstructure:"firewall"`

	// BGP is the BGP speaker configuration.
	BGP *bgp.BGPConfig `yaml:"bgp,omitempty" json:"bgp,omitempty" mapstructure:"bgp"`

	// DHCP is the DHCP server configuration.
	DHCP *DHCPServiceConfig `yaml:"dhcp,omitempty" json:"dhcp,omitempty" mapstructure:"dhcp"`

	// PXE is the PXE boot server configuration.
	PXE *PXEServiceConfig `yaml:"pxe,omitempty" json:"pxe,omitempty" mapstructure:"pxe"`

	// LoadBalancer is the load balancer configuration.
	LoadBalancer *LoadBalancerConfig `yaml:"load-balancer,omitempty" json:"load_balancer,omitempty" mapstructure:"load-balancer"`

	// NAT is the NAT gateway configuration.
	NAT *NATConfig `yaml:"nat,omitempty" json:"nat,omitempty" mapstructure:"nat"`

	// NAT64 is the stateful NAT64 translator configuration (#601): the
	// IPv6-only client path onto the IPv4 internet.
	NAT64 *NAT64Config `yaml:"nat64,omitempty" json:"nat64,omitempty" mapstructure:"nat64"`

	// Transit is the transit (gateway ↔ upstream/BGP) service configuration.
	// When present and enabled, the gateway activates its transit BGP/p2p
	// service for point-to-point link management on the transit VLAN.
	Transit *TransitServiceConfig `yaml:"transit,omitempty" json:"transit,omitempty" mapstructure:"transit"`

	// ManagementVPN is the WireGuard admin VPN service configuration.
	// When present and enabled, the gateway exposes the WireGuard endpoint
	// for authenticated operator access to management zone endpoints.
	ManagementVPN *ManagementVPNServiceConfig `yaml:"management_vpn,omitempty" json:"management_vpn,omitempty" mapstructure:"management_vpn"`

	// Tunnels are the GRE, IPsec and WireGuard tunnel configurations.
	Tunnels []TunnelConfig `yaml:"tunnels,omitempty" json:"tunnels,omitempty" mapstructure:"tunnels"`

	// RoutingUplinks declare the WAN uplinks (routing table, next hops,
	// source rules) that Tunnels pin their outer packets to through their
	// `uplink:` key. Distinct from Uplinks, which are the NAT/NIC ports.
	RoutingUplinks []RoutingUplinkConfig `yaml:"routing-uplinks,omitempty" json:"routing_uplinks,omitempty" mapstructure:"routing-uplinks"`

	// HostFW is the nftables host packet filter configuration (#569): the
	// operator-declared listeners, WAN peer allowances and tunnel
	// interfaces; the daemon's own listeners come from HostRuntime.
	HostFW *hostfw.Config `yaml:"hostfw,omitempty" json:"hostfw,omitempty" mapstructure:"hostfw"`

	// Runtime carries daemon-injected runtime dependencies (OVS client,
	// flow controller, zone providers). Never serialized; nil when the
	// gateway is constructed from configuration alone.
	Runtime *GatewayRuntime `yaml:"-" json:"-" mapstructure:"-"`

	// Host carries the daemon-injected dependencies of the host-programming
	// services (host filter, tunnels, BGP). Never serialized; nil means the
	// real netlink implementations.
	Host *HostRuntime `yaml:"-" json:"-" mapstructure:"-"`

	// Supervisor, when set, runs every enabled service in a supervised child
	// process instead of this one (#557): the handlers registered for the
	// sections relay start, stop and health to it, Runtime stays nil here
	// because the datapath child owns the OVS pipeline, and Apply forwards
	// the desired configuration to it. Never serialized.
	Supervisor ServiceSupervisor `yaml:"-" json:"-" mapstructure:"-"`
}

// Validate checks if the gateway configuration is valid.
func (c *GatewayConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.ID == "" {
		return ErrConfigurationInvalid
	}
	if c.MinReputation <= 0 || c.MinReputation > 1.0 {
		c.MinReputation = MinReputation
	}
	if c.MinAgeDays <= 0 {
		c.MinAgeDays = MinAgeDays
	}
	if c.MinUptimePct <= 0 || c.MinUptimePct > 100 {
		c.MinUptimePct = MinUptimePct
	}
	for i := range c.Uplinks {
		if err := c.Uplinks[i].Validate(); err != nil {
			return err
		}
	}
	if c.Overlay != nil {
		if err := c.Overlay.Validate(); err != nil {
			return err
		}
		if err := c.validateOverlayExclusive(); err != nil {
			return err
		}
	}
	if c.Edge != nil {
		if err := c.Edge.Validate(); err != nil {
			return err
		}
	}
	if c.Firewall != nil {
		if err := c.Firewall.Validate(); err != nil {
			return err
		}
	}
	if c.DHCP != nil {
		if err := c.DHCP.Validate(); err != nil {
			return err
		}
	}
	if c.PXE != nil {
		if err := c.PXE.Validate(); err != nil {
			return err
		}
	}
	if c.NAT != nil {
		if err := c.NAT.Validate(); err != nil {
			return err
		}
	}
	if c.NAT64 != nil {
		if err := c.NAT64.Validate(); err != nil {
			return err
		}
		if err := c.NAT64.validateUplink(c.NAT); err != nil {
			return err
		}
	}
	if c.LoadBalancer != nil {
		if err := c.LoadBalancer.Validate(); err != nil {
			return err
		}
	}
	if c.Transit != nil {
		if err := c.Transit.Validate(); err != nil {
			return err
		}
	}
	if c.ManagementVPN != nil {
		if err := c.ManagementVPN.Validate(); err != nil {
			return err
		}
	}
	if c.HostFW != nil && c.HostFW.Enabled {
		if err := c.HostFW.Validate(); err != nil {
			return &ErrHostFWConfigInvalid{Cause: err}
		}
	}
	return c.validateTunnels()
}

// validateOverlayExclusive refuses an enabled overlay beside the firewall,
// NAT or load balancer. Those services lay their flows out for the NORMAL
// terminal (NAT, for one, installs a table-10 miss to table 20), while under
// the overlay terminal table 10 is decap authorisation, whose miss drops
// unadmitted tunnelled frames: a service miss there would forward frames from
// revoked VTEPs.
func (c *GatewayConfig) validateOverlayExclusive() error {
	if !c.Overlay.Enabled {
		return nil
	}
	switch {
	case c.Firewall != nil && c.Firewall.Enabled:
		return &ErrOverlayServiceConflict{Service: ServiceFirewall}
	case c.NAT != nil && c.NAT.Enabled:
		return &ErrOverlayServiceConflict{Service: ServiceNAT}
	case c.LoadBalancer != nil && c.LoadBalancer.Enabled:
		return &ErrOverlayServiceConflict{Service: ServiceLoadBalancer}
	}
	return nil
}

// HasEnabledServices returns true if at least one service section is present and enabled.
// needsPipeline reports whether this gateway programs the datapath and so
// must own the base pipeline before its services start (#567). A gateway
// with no datapath service — proxy-only, telemetry-only — installs nothing
// and leaves the bridge exactly as it found it. When overlay is enabled the
// pipeline records the overlay terminal, but the overlay handler owns the
// OpenFlow table defaults itself.
func (c *GatewayConfig) needsPipeline() bool {
	if c.Runtime == nil {
		return false
	}
	return (c.Overlay != nil && c.Overlay.Enabled) ||
		(c.Firewall != nil && c.Firewall.Enabled) ||
		(c.NAT != nil && c.NAT.Enabled) ||
		(c.NAT64 != nil && c.NAT64.Enabled) ||
		(c.LoadBalancer != nil && c.LoadBalancer.Enabled)
}

// pipelineTerminal is the table-30 disposition this gateway asks for. The
// overlay terminal means modes.OverlayModeHandler owns the MAC-learning and
// downstream overlay tables, so the base pipeline installs no default flows.
func (c *GatewayConfig) pipelineTerminal() PipelineTerminal {
	if c.Overlay != nil && c.Overlay.Enabled {
		return TerminalOverlay
	}
	return TerminalNormal
}

func (c *GatewayConfig) HasEnabledServices() bool {
	return len(c.EnabledServices()) > 0
}

// EnabledServices lists the service sections this configuration enables,
// in a fixed order: the OVS datapath services first (they gate out of the
// base pipeline), then the host-programming services, then the sections
// the gateway has no builder for. The registry keys off this list, so the
// list and the builder table (handlers.go) are the two halves of one
// contract: a section here without a builder is a typed refusal at Start.
// It is exported so the process model's class table can be checked
// against it: a section here with no process is one the supervisor cannot
// start (#631 review).
func (c *GatewayConfig) EnabledServices() []string {
	var out []string
	add := func(on bool, name string) {
		if on {
			out = append(out, name)
		}
	}
	add(c.Firewall != nil && c.Firewall.Enabled, ServiceFirewall)
	add(c.NAT != nil && c.NAT.Enabled, ServiceNAT)
	add(c.LoadBalancer != nil && c.LoadBalancer.Enabled, ServiceLoadBalancer)
	add(c.NAT64 != nil && c.NAT64.Enabled, ServiceNAT64)
	add(c.HostFW != nil && c.HostFW.Enabled, ServiceHostFW)
	add(len(c.Tunnels) > 0 || len(c.RoutingUplinks) > 0, ServiceTunnels)
	add(c.BGP != nil || (c.Transit != nil && c.Transit.Enabled), ServiceTransit)
	add(c.Overlay != nil && c.Overlay.Enabled, ServiceOverlay)
	add(c.Edge != nil && c.Edge.Enabled, ServiceEdge)
	add(c.DHCP != nil && c.DHCP.Enabled, ServiceDHCP)
	add(c.PXE != nil && c.PXE.Enabled, ServicePXE)
	add(c.ManagementVPN != nil && c.ManagementVPN.Enabled, ServiceManagementVPN)
	return out
}

// TransitServiceConfig holds gateway transit service configuration.
// The transit service manages point-to-point BGP/upstream links on the
// transit VLAN. The VLAN and p2p prefix are typically set at the sdn.transit
// level; this service block controls gateway-side activation.
//
// Doc reference: docs/architecture/reference-network.md §Configuration
type TransitServiceConfig struct {
	// Enabled controls whether the transit service is active.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
}

// Validate checks the transit service configuration.
func (c *TransitServiceConfig) Validate() error {
	return nil
}

// ManagementVPNServiceConfig holds the WireGuard admin VPN gateway service
// configuration. The platform WireGuard endpoint exposes access to management
// zone endpoints only; operator workstations authenticate through this tunnel
// and are never dual-homed onto a data zone.
//
// The runtime-undefined aspects (WireGuard key management, peer enrollment,
// IP assignment within the admin subnet) are handled by go-xkms WireGuard
// support reached via the quicbaas SDK; this struct holds only the gateway
// service activation flag.
//
// Doc reference: docs/architecture/reference-network.md §Management access
type ManagementVPNServiceConfig struct {
	// Enabled controls whether the management VPN service is active.
	// Gateways SHOULD expose this by default.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
}

// Validate checks the management VPN service configuration.
func (c *ManagementVPNServiceConfig) Validate() error {
	return nil
}

// GatewayStatus represents the current status of a gateway.
type GatewayStatus struct {
	// ID is the gateway identifier.
	ID string

	// State is the current operational state.
	State GatewayState

	// ActiveModes is the bitmask of active gateway modes.
	//
	// Deprecated: Use ActiveServiceNames instead.
	ActiveModes GatewayMode

	// ActiveServiceNames are the names of currently active services.
	ActiveServiceNames []string

	// Uptime is how long the gateway has been running.
	Uptime time.Duration

	// StartedAt is when the gateway was started.
	StartedAt time.Time

	// LastHealthCheck is when the last health check occurred.
	LastHealthCheck time.Time

	// HealthCheckPassed indicates if the last health check passed.
	HealthCheckPassed bool

	// ErrorMessage contains any error message if in error state.
	ErrorMessage string

	// OverlayState is the overlay service state.
	OverlayState *OverlayGatewayState

	// EdgeState is the edge service state.
	EdgeState *EdgeGatewayState

	// TransitState is the transit service state.
	TransitState *TransitGatewayState
}

// IsHealthy returns true if the gateway status indicates a healthy state.
func (s *GatewayStatus) IsHealthy() bool {
	return s.State.IsHealthy() && s.HealthCheckPassed
}
