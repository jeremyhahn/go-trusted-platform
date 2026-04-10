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

// Package bgp provides BGP (Border Gateway Protocol) speaker functionality
// for SDN overlay networking using the GoBGP library. It supports IPv4/IPv6
// unicast and EVPN address families for VXLAN integration.
package bgp

import (
	"net"
	"net/netip"
	"time"
)

// Default BGP configuration values.
const (
	// DefaultBGPPort is the standard BGP TCP port.
	DefaultBGPPort uint16 = 179

	// DefaultHoldTime is the default BGP hold timer in seconds.
	DefaultHoldTime uint16 = 90

	// DefaultKeepaliveInterval is the default keepalive interval in seconds.
	DefaultKeepaliveInterval uint16 = 30

	// DefaultConnectRetry is the default connect retry timer in seconds.
	DefaultConnectRetry uint16 = 120

	// MinHoldTime is the minimum BGP hold time in seconds.
	MinHoldTime uint16 = 3

	// MinASN is the minimum valid AS number.
	MinASN uint32 = 1

	// MaxASN is the maximum valid AS number for 4-byte ASNs.
	MaxASN uint32 = 4294967295

	// PrivateASNMin is the start of the private 16-bit ASN range.
	PrivateASNMin uint32 = 64512

	// PrivateASNMax is the end of the private 16-bit ASN range.
	PrivateASNMax uint32 = 65534

	// PrivateASN4Min is the start of the private 32-bit ASN range.
	PrivateASN4Min uint32 = 4200000000

	// PrivateASN4Max is the end of the private 32-bit ASN range.
	PrivateASN4Max uint32 = 4294967294
)

// SpeakerTier represents the tier of a BGP speaker in the hierarchy.
type SpeakerTier uint8

const (
	// SpeakerTierUnknown indicates an unknown speaker tier.
	SpeakerTierUnknown SpeakerTier = iota

	// SpeakerTierBackbone represents backbone speakers that announce aggregate prefixes.
	SpeakerTierBackbone

	// SpeakerTierDatacenter represents datacenter speakers for regional prefixes.
	SpeakerTierDatacenter

	// SpeakerTierCoordinator represents coordinator nodes for route signing.
	SpeakerTierCoordinator
)

// String returns a human-readable representation of the speaker tier.
func (t SpeakerTier) String() string {
	switch t {
	case SpeakerTierBackbone:
		return "backbone"
	case SpeakerTierDatacenter:
		return "datacenter"
	case SpeakerTierCoordinator:
		return "coordinator"
	default:
		return "unknown"
	}
}

// Valid returns true if the speaker tier is a valid non-unknown value.
func (t SpeakerTier) Valid() bool {
	return t >= SpeakerTierBackbone && t <= SpeakerTierCoordinator
}

// PeerState represents the state of a BGP peer session.
type PeerState uint8

const (
	// PeerStateIdle indicates the peer is idle and not attempting to connect.
	PeerStateIdle PeerState = iota

	// PeerStateConnect indicates the peer is attempting to connect.
	PeerStateConnect

	// PeerStateActive indicates the peer is actively trying to establish a session.
	PeerStateActive

	// PeerStateOpenSent indicates an OPEN message has been sent.
	PeerStateOpenSent

	// PeerStateOpenConfirm indicates waiting for KEEPALIVE or NOTIFICATION.
	PeerStateOpenConfirm

	// PeerStateEstablished indicates the peer session is established.
	PeerStateEstablished
)

// String returns a human-readable representation of the peer state.
func (s PeerState) String() string {
	switch s {
	case PeerStateIdle:
		return "Idle"
	case PeerStateConnect:
		return "Connect"
	case PeerStateActive:
		return "Active"
	case PeerStateOpenSent:
		return "OpenSent"
	case PeerStateOpenConfirm:
		return "OpenConfirm"
	case PeerStateEstablished:
		return "Established"
	default:
		return "Unknown"
	}
}

// Valid returns true if the peer state is a valid value.
func (s PeerState) Valid() bool {
	return s <= PeerStateEstablished
}

// IsUp returns true if the peer session is established.
func (s PeerState) IsUp() bool {
	return s == PeerStateEstablished
}

// AuthType defines the BGP session authentication type.
type AuthType uint8

const (
	// AuthTypeNone indicates no authentication.
	AuthTypeNone AuthType = iota

	// AuthTypeMD5 indicates MD5 authentication.
	AuthTypeMD5

	// AuthTypeTCPAO indicates TCP-AO authentication.
	AuthTypeTCPAO
)

// String returns the string representation of the authentication type.
func (a AuthType) String() string {
	switch a {
	case AuthTypeNone:
		return "none"
	case AuthTypeMD5:
		return "md5"
	case AuthTypeTCPAO:
		return "tcp-ao"
	default:
		return "unknown"
	}
}

// Valid returns true if the authentication type is a valid value.
func (a AuthType) Valid() bool {
	return a <= AuthTypeTCPAO
}

// AddressFamily specifies the BGP address family.
type AddressFamily uint8

const (
	// AFamilyIPv4Unicast represents IPv4 unicast routes.
	AFamilyIPv4Unicast AddressFamily = iota

	// AFamilyIPv6Unicast represents IPv6 unicast routes.
	AFamilyIPv6Unicast

	// AFamilyEVPN represents Ethernet VPN routes for VXLAN.
	AFamilyEVPN
)

// String returns the string representation of the address family.
func (af AddressFamily) String() string {
	switch af {
	case AFamilyIPv4Unicast:
		return "ipv4-unicast"
	case AFamilyIPv6Unicast:
		return "ipv6-unicast"
	case AFamilyEVPN:
		return "evpn"
	default:
		return "unknown"
	}
}

// Valid returns true if the address family is a valid value.
func (af AddressFamily) Valid() bool {
	return af <= AFamilyEVPN
}

// RIBType specifies which RIB (Routing Information Base) to query.
type RIBType uint8

const (
	// RIBLocal is the local RIB containing best routes.
	RIBLocal RIBType = iota

	// RIBAdjIn is the Adj-RIB-In containing received routes.
	RIBAdjIn

	// RIBAdjOut is the Adj-RIB-Out containing advertised routes.
	RIBAdjOut
)

// String returns the string representation of the RIB type.
func (rt RIBType) String() string {
	switch rt {
	case RIBLocal:
		return "local"
	case RIBAdjIn:
		return "adj-in"
	case RIBAdjOut:
		return "adj-out"
	default:
		return "unknown"
	}
}

// Valid returns true if the RIB type is a valid value.
func (rt RIBType) Valid() bool {
	return rt <= RIBAdjOut
}

// OriginType specifies the origin of a BGP route.
type OriginType uint8

const (
	// OriginIGP indicates the route originated from an IGP.
	OriginIGP OriginType = iota

	// OriginEGP indicates the route originated from EGP.
	OriginEGP

	// OriginIncomplete indicates incomplete origin information.
	OriginIncomplete
)

// String returns the string representation of the origin type.
func (o OriginType) String() string {
	switch o {
	case OriginIGP:
		return "igp"
	case OriginEGP:
		return "egp"
	case OriginIncomplete:
		return "incomplete"
	default:
		return "unknown"
	}
}

// Valid returns true if the origin type is a valid value.
func (o OriginType) Valid() bool {
	return o <= OriginIncomplete
}

// EventType specifies the type of BGP event.
type EventType uint8

const (
	// EventPeerStateChange indicates a peer session state change.
	EventPeerStateChange EventType = iota

	// EventPathReceived indicates a new path was received.
	EventPathReceived

	// EventPathWithdrawn indicates a path was withdrawn.
	EventPathWithdrawn
)

// String returns the string representation of the event type.
func (et EventType) String() string {
	switch et {
	case EventPeerStateChange:
		return "peer-state-change"
	case EventPathReceived:
		return "path-received"
	case EventPathWithdrawn:
		return "path-withdrawn"
	default:
		return "unknown"
	}
}

// Valid returns true if the event type is a valid value.
func (et EventType) Valid() bool {
	return et <= EventPathWithdrawn
}

// RouteType identifies the type of BGP route.
type RouteType uint8

const (
	// RouteTypeUnknown indicates an unknown route type.
	RouteTypeUnknown RouteType = iota

	// RouteTypeEVPNType2 is a MAC/IP advertisement route.
	RouteTypeEVPNType2

	// RouteTypeEVPNType3 is an inclusive multicast route.
	RouteTypeEVPNType3

	// RouteTypeEVPNType5 is an IP prefix route.
	RouteTypeEVPNType5

	// RouteTypeIPv4Unicast is an IPv4 unicast route.
	RouteTypeIPv4Unicast

	// RouteTypeIPv6Unicast is an IPv6 unicast route.
	RouteTypeIPv6Unicast
)

// String returns the string representation of the route type.
func (r RouteType) String() string {
	switch r {
	case RouteTypeEVPNType2:
		return "evpn-type2"
	case RouteTypeEVPNType3:
		return "evpn-type3"
	case RouteTypeEVPNType5:
		return "evpn-type5"
	case RouteTypeIPv4Unicast:
		return "ipv4-unicast"
	case RouteTypeIPv6Unicast:
		return "ipv6-unicast"
	default:
		return "unknown"
	}
}

// Valid returns true if the route type is a valid value.
func (r RouteType) Valid() bool {
	return r >= RouteTypeEVPNType2 && r <= RouteTypeIPv6Unicast
}

// IsEVPN returns true if the route type is an EVPN route.
func (r RouteType) IsEVPN() bool {
	return r >= RouteTypeEVPNType2 && r <= RouteTypeEVPNType5
}

// EVPNRouteType specifies the type of EVPN route.
type EVPNRouteType uint8

const (
	// EVPNTypeEthernetAutoDiscovery is Type-1 Ethernet Auto-Discovery.
	EVPNTypeEthernetAutoDiscovery EVPNRouteType = 1

	// EVPNTypeMACIPAdvertisement is Type-2 MAC/IP Advertisement.
	EVPNTypeMACIPAdvertisement EVPNRouteType = 2

	// EVPNTypeInclusiveMulticast is Type-3 Inclusive Multicast Ethernet Tag.
	EVPNTypeInclusiveMulticast EVPNRouteType = 3

	// EVPNTypeEthernetSegment is Type-4 Ethernet Segment.
	EVPNTypeEthernetSegment EVPNRouteType = 4

	// EVPNTypeIPPrefix is Type-5 IP Prefix.
	EVPNTypeIPPrefix EVPNRouteType = 5
)

// String returns the string representation of the EVPN route type.
func (rt EVPNRouteType) String() string {
	switch rt {
	case EVPNTypeEthernetAutoDiscovery:
		return "ethernet-auto-discovery"
	case EVPNTypeMACIPAdvertisement:
		return "mac-ip-advertisement"
	case EVPNTypeInclusiveMulticast:
		return "inclusive-multicast"
	case EVPNTypeEthernetSegment:
		return "ethernet-segment"
	case EVPNTypeIPPrefix:
		return "ip-prefix"
	default:
		return "unknown"
	}
}

// Valid returns true if the EVPN route type is a valid value.
func (rt EVPNRouteType) Valid() bool {
	return rt >= EVPNTypeEthernetAutoDiscovery && rt <= EVPNTypeIPPrefix
}

// Note: RPKIValidationState is defined in rpki.go
// Note: DampeningState is defined in dampening.go

// BGPCapabilities defines what address families and features a speaker supports.
type BGPCapabilities struct {
	// EVPN indicates support for AFI 25, SAFI 70.
	EVPN bool

	// IPv4Unicast indicates support for AFI 1, SAFI 1.
	IPv4Unicast bool

	// IPv6Unicast indicates support for AFI 2, SAFI 1.
	IPv6Unicast bool

	// RPKIValidation indicates RPKI validation is enabled.
	RPKIValidation bool

	// AnnounceIPv6Block indicates announcement of 2602:F5BB::/36.
	AnnounceIPv6Block bool

	// AnnounceIPv4Block indicates announcement of 23.143.36.0/24.
	AnnounceIPv4Block bool
}

// HasAnyAFI returns true if at least one address family is enabled.
func (c *BGPCapabilities) HasAnyAFI() bool {
	return c.EVPN || c.IPv4Unicast || c.IPv6Unicast
}

// Validate checks if the BGPCapabilities configuration is valid.
func (c *BGPCapabilities) Validate() error {
	if !c.HasAnyAFI() {
		return ErrConfigurationInvalid
	}
	return nil
}

// BGPConfig holds the configuration for the BGP speaker.
type BGPConfig struct {
	// RouterID is the BGP router identifier (usually the loopback IP).
	RouterID netip.Addr

	// ASN is the local Autonomous System Number.
	ASN uint32

	// ListenPort is the TCP port to listen on (default: 179).
	ListenPort uint16

	// ListenAddresses specifies addresses to bind to.
	ListenAddresses []netip.Addr

	// Tier is the speaker tier in the hierarchy.
	Tier SpeakerTier

	// Capabilities defines supported address families and features.
	Capabilities BGPCapabilities

	// RouteDistinguisher for EVPN routes.
	RouteDistinguisher string

	// ImportRT is the list of import route targets.
	ImportRT []string

	// ExportRT is the list of export route targets.
	ExportRT []string

	// GracefulRestartEnabled enables BGP graceful restart.
	GracefulRestartEnabled bool

	// GracefulRestartTime is the restart time in seconds.
	GracefulRestartTime uint16

	// MultipathEnabled enables multipath routing.
	MultipathEnabled bool

	// EnabledFamilies specifies which address families to enable.
	EnabledFamilies []AddressFamily

	// DampeningEnabled indicates if route flap dampening is enabled.
	DampeningEnabled bool

	// DampeningHalfLife is the half-life for route dampening penalty decay.
	DampeningHalfLife time.Duration

	// DampeningMaxSuppress is the maximum suppression time for dampened routes.
	DampeningMaxSuppress time.Duration

	// IsRouteReflector indicates if this speaker is a route reflector.
	IsRouteReflector bool

	// ClusterID is the route reflector cluster ID.
	ClusterID string
}

// Validate checks if the BGP configuration is valid.
func (c *BGPConfig) Validate() error {
	if !c.RouterID.IsValid() || c.RouterID.IsUnspecified() {
		return ErrInvalidRouterID
	}
	if c.ASN < MinASN || c.ASN > MaxASN {
		return ErrInvalidASN
	}
	if c.ListenPort == 0 {
		c.ListenPort = DefaultBGPPort
	}
	if c.Tier != SpeakerTierUnknown && !c.Tier.Valid() {
		return ErrConfigurationInvalid
	}
	if c.Capabilities.EVPN && c.RouteDistinguisher == "" {
		return ErrConfigurationInvalid
	}
	if c.DampeningEnabled {
		if c.DampeningHalfLife <= 0 {
			return ErrConfigurationInvalid
		}
		if c.DampeningMaxSuppress <= 0 {
			return ErrConfigurationInvalid
		}
		if c.DampeningMaxSuppress < c.DampeningHalfLife {
			return ErrConfigurationInvalid
		}
	}
	if c.IsRouteReflector && c.ClusterID == "" {
		return ErrConfigurationInvalid
	}
	return nil
}

// IsPrivateASN returns true if the ASN is in the private range.
func (c *BGPConfig) IsPrivateASN() bool {
	return (c.ASN >= PrivateASNMin && c.ASN <= PrivateASNMax) ||
		(c.ASN >= PrivateASN4Min && c.ASN <= PrivateASN4Max)
}

// NeighborConfig holds configuration for a BGP neighbor/peer.
type NeighborConfig struct {
	// Address is the neighbor's IP address.
	Address netip.Addr

	// ASN is the neighbor's Autonomous System Number.
	ASN uint32

	// Description is a human-readable description.
	Description string

	// AuthType is the session authentication type.
	AuthType AuthType

	// AuthKey is the authentication key (MD5 or TCP-AO).
	AuthKey string

	// HoldTime is the BGP hold timer in seconds.
	HoldTime uint16

	// KeepaliveInterval is the keepalive interval in seconds.
	KeepaliveInterval uint16

	// ConnectRetry is the connection retry timer in seconds.
	ConnectRetry uint16

	// Password for MD5 authentication (optional).
	Password string

	// PassiveMode enables passive connection mode.
	PassiveMode bool

	// RouteReflectorClient marks this peer as a route reflector client.
	RouteReflectorClient bool

	// EBGPMultihop sets the EBGP multihop TTL (0 for directly connected).
	EBGPMultihop uint8

	// EnabledFamilies specifies address families to enable for this peer.
	EnabledFamilies []AddressFamily

	// RemovePrivateAS removes private AS numbers from updates.
	RemovePrivateAS bool

	// AdminDown starts the peer in administratively disabled state.
	AdminDown bool

	// IPv4Unicast indicates IPv4 unicast is enabled for this peer.
	IPv4Unicast bool

	// IPv6Unicast indicates IPv6 unicast is enabled for this peer.
	IPv6Unicast bool

	// EVPN indicates EVPN is enabled for this peer.
	EVPN bool
}

// Validate checks if the neighbor configuration is valid.
func (c *NeighborConfig) Validate() error {
	if !c.Address.IsValid() || c.Address.IsUnspecified() {
		return ErrInvalidPeerAddress
	}
	if c.ASN < MinASN || c.ASN > MaxASN {
		return ErrInvalidPeerASN
	}
	if !c.AuthType.Valid() {
		return ErrConfigurationInvalid
	}
	if (c.AuthType == AuthTypeMD5 || c.AuthType == AuthTypeTCPAO) && c.AuthKey == "" {
		return ErrConfigurationInvalid
	}
	if c.HoldTime > 0 && c.HoldTime < MinHoldTime {
		return ErrInvalidHoldTime
	}
	if c.HoldTime == 0 {
		c.HoldTime = DefaultHoldTime
	}
	if c.KeepaliveInterval == 0 {
		c.KeepaliveInterval = DefaultKeepaliveInterval
	}
	if c.ConnectRetry == 0 {
		c.ConnectRetry = DefaultConnectRetry
	}
	return nil
}

// HasAnyAFI returns true if at least one address family is enabled.
func (c *NeighborConfig) HasAnyAFI() bool {
	return c.IPv4Unicast || c.IPv6Unicast || c.EVPN || len(c.EnabledFamilies) > 0
}

// PeerInfo contains peer state and statistics.
type PeerInfo struct {
	Address            netip.Addr
	ASN                uint32
	Description        string
	State              PeerState
	Uptime             time.Duration
	AdminDown          bool
	PrefixesReceived   int64
	PrefixesSent       int64
	MessagesReceived   int64
	MessagesSent       int64
	LastError          string
	LastErrorTime      time.Time
	RemoteRouterID     netip.Addr
	LocalAddress       netip.Addr
	NegotiatedHoldTime uint16
	EnabledFamilies    []AddressFamily
}

// Path represents a BGP path/route.
type Path struct {
	Family              AddressFamily
	Prefix              netip.Prefix
	NextHop             netip.Addr
	Origin              OriginType
	ASPath              []uint32
	LocalPref           uint32
	MED                 uint32
	Communities         []uint32
	ExtendedCommunities []string
	LargeCommunities    []string
	Atomic              bool
	Aggregator          *Aggregator
	Best                bool
	Stale               bool
	SourceID            netip.Addr
	Age                 time.Time
	EVPNRoute           *EVPNRoute
}

// Aggregator holds BGP aggregator information.
type Aggregator struct {
	ASN     uint32
	Address netip.Addr
}

// EVPNRoute contains EVPN-specific route information.
type EVPNRoute struct {
	Type               EVPNRouteType
	RouteDistinguisher string
	EthernetTag        uint32
	MAC                string
	MACAddress         net.HardwareAddr
	IPAddress          netip.Addr
	IPPrefix           netip.Prefix
	OriginatingIP      netip.Addr
	Prefix             netip.Prefix
	GatewayIP          netip.Addr
	VNI                uint32
	NextHop            netip.Addr
	RouteTargets       []string
	ESI                string
	Labels             []uint32
}

// Validate checks if the EVPNRoute is valid.
func (r *EVPNRoute) Validate() error {
	if !r.Type.Valid() {
		return ErrRouteRejected
	}
	if r.RouteDistinguisher == "" {
		return ErrInvalidRouteTarget
	}
	switch r.Type {
	case EVPNTypeMACIPAdvertisement:
		if len(r.MACAddress) == 0 && r.MAC == "" {
			return ErrRouteRejected
		}
	case EVPNTypeInclusiveMulticast:
		if !r.OriginatingIP.IsValid() && !r.IPAddress.IsValid() {
			return ErrRouteRejected
		}
	case EVPNTypeIPPrefix:
		if !r.IPPrefix.IsValid() && !r.Prefix.IsValid() {
			return ErrInvalidPrefix
		}
	}
	return nil
}

// TransitRoute represents an IP prefix announcement.
type TransitRoute struct {
	Prefix           netip.Prefix
	NextHop          netip.Addr
	Origin           OriginType
	ASPath           []uint32
	LocalPref        uint32
	MED              uint32
	Communities      []string
	LargeCommunities []string
}

// Validate checks if the TransitRoute is valid.
func (r *TransitRoute) Validate() error {
	if !r.Prefix.IsValid() {
		return ErrInvalidPrefix
	}
	if !r.NextHop.IsValid() {
		return ErrRouteRejected
	}
	if !r.Origin.Valid() {
		return ErrRouteRejected
	}
	return nil
}

// Event represents a BGP event.
type Event struct {
	Type          EventType
	PeerAddress   netip.Addr
	PeerState     PeerState
	PreviousState PeerState
	Path          *Path
	Timestamp     time.Time
}

// PeerStatus represents the current status of a BGP peer.
type PeerStatus struct {
	Address          netip.Addr
	ASN              uint32
	State            PeerState
	UptimeSince      time.Time
	PrefixesReceived uint32
	PrefixesSent     uint32
	MessagesReceived uint64
	MessagesSent     uint64
	LastError        string
	LastErrorTime    time.Time
}

// Uptime returns the duration the session has been established.
func (p *PeerStatus) Uptime() time.Duration {
	if !p.State.IsUp() || p.UptimeSince.IsZero() {
		return 0
	}
	return time.Since(p.UptimeSince)
}

// SpeakerStatus represents the current status of a BGP speaker.
type SpeakerStatus struct {
	RouterID         netip.Addr
	ASN              uint32
	Tier             SpeakerTier
	Running          bool
	StartedAt        time.Time
	PeerCount        int
	EstablishedPeers int
	TotalPrefixes    uint32
	IPv4Prefixes     uint32
	IPv6Prefixes     uint32
	EVPNRoutes       uint32
}

// Uptime returns the duration the speaker has been running.
func (s *SpeakerStatus) Uptime() time.Duration {
	if !s.Running || s.StartedAt.IsZero() {
		return 0
	}
	return time.Since(s.StartedAt)
}

// ServerInfo contains BGP server statistics.
type ServerInfo struct {
	RouterID               netip.Addr
	ASN                    uint32
	ListenPort             uint16
	PeerCount              int
	EstablishedCount       int
	Uptime                 time.Duration
	PathCount              int64
	GracefulRestartEnabled bool
}

// WatchOption configures event watching.
type WatchOption func(*watchOptions)

type watchOptions struct {
	peerStateChanges bool
	pathChanges      bool
	bestPathOnly     bool
	families         []AddressFamily
	peerAddress      netip.Addr
}

// WithPeerStateChanges enables watching for peer state changes.
func WithPeerStateChanges() WatchOption {
	return func(o *watchOptions) { o.peerStateChanges = true }
}

// WithPathChanges enables watching for path changes.
func WithPathChanges() WatchOption {
	return func(o *watchOptions) { o.pathChanges = true }
}

// WithBestPathOnly filters to only best path changes.
func WithBestPathOnly() WatchOption {
	return func(o *watchOptions) { o.bestPathOnly = true }
}

// WithFamilies filters events to specific address families.
func WithFamilies(families ...AddressFamily) WatchOption {
	return func(o *watchOptions) { o.families = families }
}

// WithPeerFilter filters events to a specific peer.
func WithPeerFilter(addr netip.Addr) WatchOption {
	return func(o *watchOptions) { o.peerAddress = addr }
}
