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
	"net"
	"net/netip"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
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
type OverlayServiceConfig struct {
	// Enabled indicates if the overlay service is enabled.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// VXLANPort is the UDP port for VXLAN encapsulation.
	VXLANPort uint16 `yaml:"vxlan-port,omitempty" json:"vxlan_port,omitempty" mapstructure:"vxlan-port"`

	// DefaultVNI is the default VXLAN Network Identifier.
	DefaultVNI uint32 `yaml:"default-vni,omitempty" json:"default_vni,omitempty" mapstructure:"default-vni"`

	// MaxVNIs is the maximum number of VNIs.
	MaxVNIs int `yaml:"max-vnis,omitempty" json:"max_vnis,omitempty" mapstructure:"max-vnis"`
}

// Validate checks if the overlay service configuration is valid.
func (c *OverlayServiceConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	return nil
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

// TunnelConfig holds configuration for a network tunnel (GRE, VXLAN, etc.).
type TunnelConfig struct {
	// Name is the tunnel interface name.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// Type is the tunnel type ("gre", "vxlan", etc.).
	Type string `yaml:"type" json:"type" mapstructure:"type"`

	// Transport wraps the tunnel: empty or "gre" is plain, "ipsec" is ESP
	// with keys from IPsec, "wireguard" is WireGuard with keys from
	// WireGuard (not available in FIPS builds). See pkg/sdn/tunnel.
	Transport string `yaml:"transport,omitempty" json:"transport,omitempty" mapstructure:"transport"`

	// Local is the local endpoint IP address.
	Local string `yaml:"local" json:"local" mapstructure:"local"`

	// Remote is the remote endpoint IP address.
	Remote string `yaml:"remote" json:"remote" mapstructure:"remote"`

	// TunnelIP is the IP address assigned to the tunnel interface.
	TunnelIP string `yaml:"tunnel-ip" json:"tunnel_ip" mapstructure:"tunnel-ip"`

	// TunnelIPv6 is the optional IPv6 address assigned to the tunnel interface.
	TunnelIPv6 string `yaml:"tunnel-ipv6,omitempty" json:"tunnel_ipv6,omitempty" mapstructure:"tunnel-ipv6"`

	// IPsec carries the ESP parameters for transport "ipsec"; its keys are
	// references (kms://, secret://) resolved through HostRuntime's secret
	// resolver at start, never values.
	IPsec *tunnel.IPsecConfig `yaml:"ipsec,omitempty" json:"ipsec,omitempty" mapstructure:"ipsec"`

	// WireGuard carries the parameters for transport "wireguard"; its
	// private key is a reference resolved the same way.
	WireGuard *tunnel.WireGuardConfig `yaml:"wireguard,omitempty" json:"wireguard,omitempty" mapstructure:"wireguard"`
}

// Validate checks if the tunnel configuration is valid.
func (c *TunnelConfig) Validate() error {
	if c.Name == "" {
		return ErrConfigurationInvalid
	}
	// A wireguard tunnel has no carrier type: its interface is the
	// WireGuard device itself, and ValidateTransport below refuses a type
	// that is set anyway.
	if c.Type == "" && c.Transport != tunnel.TransportWireGuard {
		return ErrConfigurationInvalid
	}
	if c.Local == "" {
		return ErrConfigurationInvalid
	}
	if c.Remote == "" {
		return ErrConfigurationInvalid
	}
	if c.TunnelIP == "" {
		return ErrConfigurationInvalid
	}
	// The transport sections belong to pkg/sdn/tunnel, which states their
	// rules once — a key reference per SA, wireguard refused under the fips
	// build tag — and reports them as its own typed errors.
	mapped := c.tunnelConfig()
	return mapped.ValidateTransport()
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

	// Transit is the transit (gateway ↔ upstream/BGP) service configuration.
	// When present and enabled, the gateway activates its transit BGP/p2p
	// service for point-to-point link management on the transit VLAN.
	Transit *TransitServiceConfig `yaml:"transit,omitempty" json:"transit,omitempty" mapstructure:"transit"`

	// ManagementVPN is the WireGuard admin VPN service configuration.
	// When present and enabled, the gateway exposes the WireGuard endpoint
	// for authenticated operator access to management zone endpoints.
	ManagementVPN *ManagementVPNServiceConfig `yaml:"management_vpn,omitempty" json:"management_vpn,omitempty" mapstructure:"management_vpn"`

	// Tunnels are GRE/VXLAN tunnel configurations.
	Tunnels []TunnelConfig `yaml:"tunnels,omitempty" json:"tunnels,omitempty" mapstructure:"tunnels"`

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
	for i := range c.Tunnels {
		if err := c.Tunnels[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// HasEnabledServices returns true if at least one service section is present and enabled.
// needsPipeline reports whether this gateway programs the datapath and so
// must own the base pipeline before its services start (#567). A gateway
// with no datapath service — proxy-only, telemetry-only — installs nothing
// and leaves the bridge exactly as it found it. The overlay service is
// deliberately absent from this list: its handler programs no flows and
// gates nothing out of table 10 today, so it needs no pipeline, and asking
// for the overlay terminal would refuse a start that used to succeed. When
// the overlay service owns egress it joins this list with TerminalOverlay.
func (c *GatewayConfig) needsPipeline() bool {
	if c.Runtime == nil {
		return false
	}
	return (c.Firewall != nil && c.Firewall.Enabled) ||
		(c.NAT != nil && c.NAT.Enabled) ||
		(c.LoadBalancer != nil && c.LoadBalancer.Enabled)
}

// pipelineTerminal is the table-30 disposition this gateway asks for.
// Today that is always NORMAL: the overlay terminal exists in the type
// vocabulary and is refused by BasePipelineRules until the overlay service
// owns egress (its encap flow has no output action yet).
func (c *GatewayConfig) pipelineTerminal() PipelineTerminal {
	return TerminalNormal
}

func (c *GatewayConfig) HasEnabledServices() bool {
	return len(c.enabledServices()) > 0
}

// enabledServices lists the service sections this configuration enables,
// in a fixed order: the OVS datapath services first (they gate out of the
// base pipeline), then the host-programming services, then the sections
// the gateway has no builder for. The registry keys off this list, so the
// list and the builder table (handlers.go) are the two halves of one
// contract: a section here without a builder is a typed refusal at Start.
func (c *GatewayConfig) enabledServices() []string {
	var out []string
	add := func(on bool, name string) {
		if on {
			out = append(out, name)
		}
	}
	add(c.Firewall != nil && c.Firewall.Enabled, ServiceFirewall)
	add(c.NAT != nil && c.NAT.Enabled, ServiceNAT)
	add(c.LoadBalancer != nil && c.LoadBalancer.Enabled, ServiceLoadBalancer)
	add(c.HostFW != nil && c.HostFW.Enabled, ServiceHostFW)
	add(len(c.Tunnels) > 0, ServiceTunnels)
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
