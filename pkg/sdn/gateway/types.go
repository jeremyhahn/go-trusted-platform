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
// It supports multiple gateway modes including overlay (VXLAN/EVPN), edge (IoT/P2P),
// and transit (BGP IP blocks) with reputation-based eligibility requirements.
package gateway

import (
	"net"
	"net/netip"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
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

// GatewayMode represents the operational mode of a gateway node.
// Multiple modes can be active simultaneously using bitmask operations.
type GatewayMode uint8

const (
	// GatewayModeOverlay enables SDN overlay functionality (VXLAN/EVPN).
	GatewayModeOverlay GatewayMode = 1 << iota

	// GatewayModeEdge enables IoT/P2P edge gateway functionality.
	GatewayModeEdge

	// GatewayModeTransit enables BGP transit functionality for IP blocks.
	GatewayModeTransit
)

// String returns a human-readable representation of the gateway mode.
func (m GatewayMode) String() string {
	switch m {
	case GatewayModeOverlay:
		return "overlay"
	case GatewayModeEdge:
		return "edge"
	case GatewayModeTransit:
		return "transit"
	default:
		if m == 0 {
			return "none"
		}
		return "mixed"
	}
}

// Valid returns true if the gateway mode is a valid non-zero value.
func (m GatewayMode) Valid() bool {
	// Check if only valid bits are set
	validMask := GatewayModeOverlay | GatewayModeEdge | GatewayModeTransit
	return m != 0 && (m&^validMask) == 0
}

// HasMode returns true if the specified mode is active.
func (m GatewayMode) HasMode(mode GatewayMode) bool {
	return (m & mode) == mode
}

// Modes returns a slice of individual modes that are active.
func (m GatewayMode) Modes() []GatewayMode {
	var modes []GatewayMode
	if m.HasMode(GatewayModeOverlay) {
		modes = append(modes, GatewayModeOverlay)
	}
	if m.HasMode(GatewayModeEdge) {
		modes = append(modes, GatewayModeEdge)
	}
	if m.HasMode(GatewayModeTransit) {
		modes = append(modes, GatewayModeTransit)
	}
	return modes
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

// OverlayGatewayState holds state specific to overlay gateway mode.
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

// EdgeGatewayState holds state specific to edge gateway mode.
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

// TransitGatewayState holds state specific to transit gateway mode.
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

	// Modes is the bitmask of active gateway modes.
	Modes GatewayMode

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

	// OverlayState holds overlay mode specific state.
	OverlayState *OverlayGatewayState

	// EdgeState holds edge mode specific state.
	EdgeState *EdgeGatewayState

	// TransitState holds transit mode specific state.
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

// GatewayCapabilities defines what functionality a gateway supports.
type GatewayCapabilities struct {
	// OverlaySupported indicates if overlay mode is supported.
	OverlaySupported bool

	// EdgeSupported indicates if edge mode is supported.
	EdgeSupported bool

	// TransitSupported indicates if transit mode is supported.
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

// SupportsMode returns true if the specified mode is supported.
func (c *GatewayCapabilities) SupportsMode(mode GatewayMode) bool {
	switch mode {
	case GatewayModeOverlay:
		return c.OverlaySupported
	case GatewayModeEdge:
		return c.EdgeSupported
	case GatewayModeTransit:
		return c.TransitSupported
	default:
		return false
	}
}

// UplinkConfig holds configuration for an uplink port.
type UplinkConfig struct {
	// Name is the interface name.
	Name string

	// VLAN is the VLAN ID (0 for untagged).
	VLAN uint16

	// MTU is the MTU size.
	MTU int

	// IPAddresses are the IP addresses to assign.
	IPAddresses []string
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

// EdgeConfig holds edge gateway specific configuration.
type EdgeConfig struct {
	// Enabled indicates if edge mode is enabled.
	Enabled bool

	// MaxDevices is the maximum number of connected devices.
	MaxDevices int

	// MaxServices is the maximum number of edge services.
	MaxServices int

	// ServiceDiscoveryEnabled enables service discovery.
	ServiceDiscoveryEnabled bool

	// P2PEnabled enables peer-to-peer connectivity.
	P2PEnabled bool
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

// NATConfig holds NAT gateway configuration.
type NATConfig struct {
	// Enabled indicates if NAT is enabled.
	Enabled bool

	// ExternalIP is the external NAT IP address.
	ExternalIP string

	// PortRangeStart is the start of the NAT port range.
	PortRangeStart uint16

	// PortRangeEnd is the end of the NAT port range.
	PortRangeEnd uint16

	// MaxSessions is the maximum number of NAT sessions.
	MaxSessions int
}

// Validate checks if the NAT configuration is valid.
func (c *NATConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.ExternalIP == "" {
		return ErrConfigurationInvalid
	}
	if c.PortRangeStart >= c.PortRangeEnd {
		return ErrConfigurationInvalid
	}
	if c.MaxSessions <= 0 {
		return ErrConfigurationInvalid
	}
	return nil
}

// LoadBalancerConfig holds load balancer configuration.
type LoadBalancerConfig struct {
	// Enabled indicates if load balancing is enabled.
	Enabled bool

	// Algorithm is the load balancing algorithm (round-robin, least-conn, hash).
	Algorithm string

	// HealthCheckInterval is the interval between health checks.
	HealthCheckInterval time.Duration

	// HealthCheckTimeout is the timeout for health checks.
	HealthCheckTimeout time.Duration

	// MaxBackends is the maximum number of backend servers.
	MaxBackends int
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
	if c.MaxBackends <= 0 {
		return ErrConfigurationInvalid
	}
	return nil
}

// GatewayConfig holds the complete configuration for a gateway node.
type GatewayConfig struct {
	// Enabled indicates if the gateway is enabled.
	Enabled bool

	// ID is the gateway identifier.
	ID string

	// NodeID is the DHT node identifier.
	NodeID uint64

	// Modes are the gateway modes to enable.
	Modes []GatewayMode

	// Tier is the BGP speaker tier name.
	Tier string

	// MinReputation is the minimum reputation required.
	MinReputation float64

	// MinAgeDays is the minimum node age in days.
	MinAgeDays int

	// MinUptimePct is the minimum uptime percentage.
	MinUptimePct float64

	// AnycastIP is the shared anycast gateway IP address.
	AnycastIP string

	// IPv6Pool is the IPv6 address pool CIDR.
	IPv6Pool string

	// IPv4Pool is the IPv4 address pool CIDR.
	IPv4Pool string

	// Uplinks are the uplink port configurations.
	Uplinks []UplinkConfig

	// EdgeConfig is the edge gateway configuration.
	EdgeConfig *EdgeConfig

	// NATConfig is the NAT gateway configuration.
	NATConfig *NATConfig

	// LoadBalancerConfig is the load balancer configuration.
	LoadBalancerConfig *LoadBalancerConfig

	// BGPConfig is the BGP speaker configuration.
	BGPConfig *bgp.BGPConfig
}

// Validate checks if the gateway configuration is valid.
func (c *GatewayConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.ID == "" {
		return ErrConfigurationInvalid
	}
	if len(c.Modes) == 0 {
		return ErrConfigurationInvalid
	}
	for _, mode := range c.Modes {
		if !mode.Valid() {
			return &ErrModeNotSupported{Mode: mode}
		}
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
	if c.EdgeConfig != nil {
		if err := c.EdgeConfig.Validate(); err != nil {
			return err
		}
	}
	if c.NATConfig != nil {
		if err := c.NATConfig.Validate(); err != nil {
			return err
		}
	}
	if c.LoadBalancerConfig != nil {
		if err := c.LoadBalancerConfig.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// CombinedModes returns the combined bitmask of all configured modes.
func (c *GatewayConfig) CombinedModes() GatewayMode {
	var combined GatewayMode
	for _, mode := range c.Modes {
		combined |= mode
	}
	return combined
}

// GatewayStatus represents the current status of a gateway.
type GatewayStatus struct {
	// ID is the gateway identifier.
	ID string

	// State is the current operational state.
	State GatewayState

	// ActiveModes are the currently active gateway modes.
	ActiveModes GatewayMode

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

	// OverlayState is the overlay mode state.
	OverlayState *OverlayGatewayState

	// EdgeState is the edge mode state.
	EdgeState *EdgeGatewayState

	// TransitState is the transit mode state.
	TransitState *TransitGatewayState
}

// IsHealthy returns true if the gateway status indicates a healthy state.
func (s *GatewayStatus) IsHealthy() bool {
	return s.State.IsHealthy() && s.HealthCheckPassed
}
