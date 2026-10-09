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
	"context"
	"net/netip"
	"strings"
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

	// DefaultGracefulRestartTime is the graceful restart time in seconds
	// advertised when the configuration sets none.
	DefaultGracefulRestartTime uint16 = 120

	// DefaultMaxPrefixes is the prefix limit applied to each unicast family
	// (ipv4-unicast, ipv6-unicast) of a peer that sets none. The iBGP relays
	// send a default route; anything near this is a misconfigured or hostile
	// peer.
	DefaultMaxPrefixes uint32 = 1000

	// DefaultMaxEVPNPrefixes is the l2vpn-evpn prefix limit of a peer that
	// sets none. EVPN carries a Type-2 route per MAC/IP binding and a Type-3
	// route per VTEP and EVI, so a route-reflector session holds roughly
	// VTEPs × MACs routes: the unicast limit would tear down a healthy
	// fabric at its thousand-and-first MAC.
	DefaultMaxEVPNPrefixes uint32 = 100000

	// DefaultBFDPort is the single-hop BFD control port (RFC 5881).
	DefaultBFDPort uint16 = 3784

	// DefaultBFDInterval is the default BFD transmit and receive interval.
	DefaultBFDInterval = 300 * time.Millisecond

	// MinBFDInterval is the shortest BFD interval the speaker accepts.
	MinBFDInterval = 50 * time.Millisecond

	// DefaultBFDDetectionMultiplier is the default detection multiplier.
	DefaultBFDDetectionMultiplier uint8 = 3

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

// MarshalText implements encoding.TextMarshaler.
func (t SpeakerTier) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler; the empty string is
// the unknown tier, which Validate accepts.
func (t *SpeakerTier) UnmarshalText(text []byte) error {
	switch strings.ToLower(strings.TrimSpace(string(text))) {
	case "", "unknown":
		*t = SpeakerTierUnknown
	case "backbone":
		*t = SpeakerTierBackbone
	case "datacenter":
		*t = SpeakerTierDatacenter
	case "coordinator":
		*t = SpeakerTierCoordinator
	default:
		return ErrUnknownSpeakerTier{Value: string(text)}
	}
	return nil
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

// MarshalText implements encoding.TextMarshaler so the type round-trips
// through YAML and JSON by name.
func (a AuthType) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler: "none", "md5" or
// "tcp-ao" (case-insensitive); the empty string is "none".
func (a *AuthType) UnmarshalText(text []byte) error {
	switch strings.ToLower(strings.TrimSpace(string(text))) {
	case "", "none":
		*a = AuthTypeNone
	case "md5":
		*a = AuthTypeMD5
	case "tcp-ao", "tcpao", "tcp_ao":
		*a = AuthTypeTCPAO
	default:
		return ErrUnknownAuthType{Value: string(text)}
	}
	return nil
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

// MarshalText implements encoding.TextMarshaler.
func (af AddressFamily) MarshalText() ([]byte, error) {
	return []byte(af.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler: "ipv4-unicast",
// "ipv6-unicast" or "evpn" (case-insensitive).
func (af *AddressFamily) UnmarshalText(text []byte) error {
	switch strings.ToLower(strings.TrimSpace(string(text))) {
	case "ipv4-unicast", "ipv4":
		*af = AFamilyIPv4Unicast
	case "ipv6-unicast", "ipv6":
		*af = AFamilyIPv6Unicast
	case "evpn", "l2vpn-evpn":
		*af = AFamilyEVPN
	default:
		return ErrUnknownAddressFamily{Value: string(text)}
	}
	return nil
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
	EVPN bool `yaml:"evpn" json:"evpn" mapstructure:"evpn"`

	// IPv4Unicast indicates support for AFI 1, SAFI 1.
	IPv4Unicast bool `yaml:"ipv4-unicast" json:"ipv4_unicast" mapstructure:"ipv4-unicast"`

	// IPv6Unicast indicates support for AFI 2, SAFI 1.
	IPv6Unicast bool `yaml:"ipv6-unicast" json:"ipv6_unicast" mapstructure:"ipv6-unicast"`

	// RPKIValidation indicates RPKI validation is enabled.
	RPKIValidation bool `yaml:"rpki-validation" json:"rpki_validation" mapstructure:"rpki-validation"`

	// AnnounceIPv6Block indicates announcement of 2001:DB8::/36.
	AnnounceIPv6Block bool `yaml:"announce-ipv6-block" json:"announce_ipv6_block" mapstructure:"announce-ipv6-block"`

	// AnnounceIPv4Block indicates announcement of 203.0.113.0/24.
	AnnounceIPv4Block bool `yaml:"announce-ipv4-block" json:"announce_ipv4_block" mapstructure:"announce-ipv4-block"`
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
//
// Every field carries the hyphenated key the gateway configuration uses
// (`gateway.bgp` in gatewayd's YAML, decoded through viper/mapstructure with
// a TextUnmarshaler hook — see pkg/sdn/gateway/commands/assembly.go). A key
// without a tag decodes only by case-insensitive field name, which is how
// `router-id`, `listen-port` and `peers` silently dropped before #556.
type BGPConfig struct {
	// RouterID is the BGP router identifier (usually the loopback IP).
	RouterID netip.Addr `yaml:"router-id" json:"router_id" mapstructure:"router-id"`

	// ASN is the local Autonomous System Number.
	ASN uint32 `yaml:"asn" json:"asn" mapstructure:"asn"`

	// ListenPort is the TCP port to listen on (default: 179).
	ListenPort uint16 `yaml:"listen-port" json:"listen_port" mapstructure:"listen-port"`

	// ListenAddresses specifies addresses to bind to.
	ListenAddresses []netip.Addr `yaml:"listen-addresses" json:"listen_addresses" mapstructure:"listen-addresses"`

	// OutboundOnly runs the speaker without a listener: it dials its peers
	// and accepts no session, so it can run beside another speaker that owns
	// the BGP port. ListenPort and ListenAddresses are then ignored, and no
	// peer may be passive. Set by code, not configuration.
	OutboundOnly bool `yaml:"-" json:"-" mapstructure:"-"`

	// SessionSource is the local address every session is dialled from, so
	// a peer that knows this speaker by one address sees it there; unset
	// lets the kernel choose. Set by code, not configuration.
	SessionSource netip.Addr `yaml:"-" json:"-" mapstructure:"-"`

	// Tier is the speaker tier in the hierarchy.
	Tier SpeakerTier `yaml:"tier" json:"tier" mapstructure:"tier"`

	// Capabilities defines supported address families and features.
	Capabilities BGPCapabilities `yaml:"capabilities" json:"capabilities" mapstructure:"capabilities"`

	// GracefulRestart enables BGP graceful restart (RFC 4724). It is a
	// pointer so an absent key means the default, which is ON: a speaker
	// restart must not withdraw the site's prefixes.
	GracefulRestart *bool `yaml:"graceful-restart" json:"graceful_restart" mapstructure:"graceful-restart"`

	// GracefulRestartTime is the restart time in seconds.
	GracefulRestartTime uint16 `yaml:"graceful-restart-time" json:"graceful_restart_time" mapstructure:"graceful-restart-time"`

	// MultipathEnabled enables multipath routing.
	MultipathEnabled bool `yaml:"multipath" json:"multipath" mapstructure:"multipath"`

	// EnabledFamilies specifies which address families to enable.
	EnabledFamilies []AddressFamily `yaml:"families" json:"families" mapstructure:"families"`

	// DampeningEnabled indicates if route flap dampening is enabled.
	DampeningEnabled bool `yaml:"dampening" json:"dampening" mapstructure:"dampening"`

	// DampeningHalfLife is the half-life for route dampening penalty decay.
	DampeningHalfLife time.Duration `yaml:"dampening-half-life" json:"dampening_half_life" mapstructure:"dampening-half-life"`

	// DampeningMaxSuppress is the maximum suppression time for dampened routes.
	DampeningMaxSuppress time.Duration `yaml:"dampening-max-suppress" json:"dampening_max_suppress" mapstructure:"dampening-max-suppress"`

	// IsRouteReflector indicates if this speaker is a route reflector.
	IsRouteReflector bool `yaml:"route-reflector" json:"route_reflector" mapstructure:"route-reflector"`

	// ClusterID is the route reflector cluster ID.
	ClusterID string `yaml:"cluster-id" json:"cluster_id" mapstructure:"cluster-id"`

	// Announce holds the prefixes to announce to BGP peers.
	// This supports both iBGP (GRE tunnel topology) and eBGP (direct ISP) modes.
	Announce *AnnounceConfig `yaml:"announce" json:"announce" mapstructure:"announce"`

	// Neighbors is the list of BGP peers/neighbors to establish sessions
	// with. The configuration key is `peers`, the word the shipped gateway
	// template uses.
	Neighbors []NeighborConfig `yaml:"peers" json:"peers" mapstructure:"peers"`

	// Keychains are the TCP-AO keychains peers may reference by name
	// (`auth-type: tcp-ao`, `keychain: <name>`).
	Keychains []TCPAOKeychainConfig `yaml:"keychains" json:"keychains" mapstructure:"keychains"`
}

// GracefulRestartEnabled reports the effective graceful-restart setting:
// on unless the configuration disables it.
func (c *BGPConfig) GracefulRestartEnabled() bool {
	return c.GracefulRestart == nil || *c.GracefulRestart
}

// Keychain returns the TCP-AO keychain with the given name.
func (c *BGPConfig) Keychain(name string) (*TCPAOKeychainConfig, bool) {
	for i := range c.Keychains {
		if c.Keychains[i].Name == name {
			return &c.Keychains[i], true
		}
	}
	return nil, false
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
	if c.IsRouteReflector {
		// GoBGP takes the cluster ID as a dotted quad (RFC 4456 §7).
		clusterID, err := netip.ParseAddr(c.ClusterID)
		if err != nil || !clusterID.Is4() {
			return ErrConfigurationInvalid
		}
	}
	if c.Announce != nil {
		if err := c.Announce.Validate(); err != nil {
			return err
		}
	}
	seen := make(map[string]bool, len(c.Keychains))
	for i := range c.Keychains {
		if err := c.Keychains[i].Validate(); err != nil {
			return err
		}
		if seen[c.Keychains[i].Name] {
			return ErrDuplicateKeychain{Name: c.Keychains[i].Name}
		}
		seen[c.Keychains[i].Name] = true
	}
	for i := range c.Neighbors {
		if err := c.Neighbors[i].Validate(); err != nil {
			return err
		}
		if err := c.Neighbors[i].validateAttributeDirections(c.ASN); err != nil {
			return err
		}
		if c.Neighbors[i].AuthType == AuthTypeTCPAO && !seen[c.Neighbors[i].Keychain] {
			return ErrKeychainNotFound{Peer: c.Neighbors[i].Address.String(), Name: c.Neighbors[i].Keychain}
		}
		if c.OutboundOnly && c.Neighbors[i].PassiveMode {
			return ErrPassivePeerWithoutListener{Peer: c.Neighbors[i].Address.String()}
		}
	}
	if c.GracefulRestartEnabled() && c.GracefulRestartTime == 0 {
		c.GracefulRestartTime = DefaultGracefulRestartTime
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
	// Name is the operator's label for the peer (the template's `name`).
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// Address is the neighbor's IP address.
	Address netip.Addr `yaml:"address" json:"address" mapstructure:"address"`

	// ASN is the neighbor's Autonomous System Number.
	ASN uint32 `yaml:"asn" json:"asn" mapstructure:"asn"`

	// Description is a human-readable description.
	Description string `yaml:"description" json:"description" mapstructure:"description"`

	// AuthType is the session authentication type: none, md5 or tcp-ao.
	AuthType AuthType `yaml:"auth-type" json:"auth_type" mapstructure:"auth-type"`

	// AuthKeyRef names where the MD5 session secret comes from — a secret
	// reference URI (kms://, file://, idevid://, …) resolved at boot by the
	// platform's resolver, never the secret itself (configuration.md §4).
	AuthKeyRef string `yaml:"auth-key-ref" json:"auth_key_ref" mapstructure:"auth-key-ref"`

	// AuthKey is the resolved MD5 session secret. It is never decoded from
	// configuration; ResolveSecrets fills it.
	AuthKey string `yaml:"-" json:"-" mapstructure:"-"`

	// Keychain names the TCP-AO keychain (BGPConfig.Keychains) this peer
	// authenticates with when AuthType is tcp-ao.
	Keychain string `yaml:"keychain" json:"keychain" mapstructure:"keychain"`

	// HoldTime is the BGP hold timer in seconds.
	HoldTime uint16 `yaml:"hold-time" json:"hold_time" mapstructure:"hold-time"`

	// KeepaliveInterval is the keepalive interval in seconds.
	KeepaliveInterval uint16 `yaml:"keepalive-interval" json:"keepalive_interval" mapstructure:"keepalive-interval"`

	// ConnectRetry is the connection retry timer in seconds.
	ConnectRetry uint16 `yaml:"connect-retry" json:"connect_retry" mapstructure:"connect-retry"`

	// PassiveMode enables passive connection mode.
	PassiveMode bool `yaml:"passive" json:"passive" mapstructure:"passive"`

	// RouteReflectorClient marks this peer as a route reflector client.
	RouteReflectorClient bool `yaml:"route-reflector-client" json:"route_reflector_client" mapstructure:"route-reflector-client"`

	// EBGPMultihop sets the EBGP multihop TTL (0 for directly connected).
	EBGPMultihop uint8 `yaml:"ebgp-multihop" json:"ebgp_multihop" mapstructure:"ebgp-multihop"`

	// EnabledFamilies specifies address families to enable for this peer
	// (the template's `families`).
	EnabledFamilies []AddressFamily `yaml:"families" json:"families" mapstructure:"families"`

	// RemovePrivateAS removes private AS numbers from updates.
	RemovePrivateAS bool `yaml:"remove-private-as" json:"remove_private_as" mapstructure:"remove-private-as"`

	// AdminDown starts the peer in administratively disabled state.
	AdminDown bool `yaml:"admin-down" json:"admin_down" mapstructure:"admin-down"`

	// IPv4Unicast indicates IPv4 unicast is enabled for this peer.
	IPv4Unicast bool `yaml:"ipv4-unicast" json:"ipv4_unicast" mapstructure:"ipv4-unicast"`

	// IPv6Unicast indicates IPv6 unicast is enabled for this peer.
	IPv6Unicast bool `yaml:"ipv6-unicast" json:"ipv6_unicast" mapstructure:"ipv6-unicast"`

	// EVPN indicates EVPN is enabled for this peer.
	EVPN bool `yaml:"evpn" json:"evpn" mapstructure:"evpn"`

	// BFD enables single-hop BFD (RFC 5881) toward this peer for fast
	// failure detection.
	BFD *BFDConfig `yaml:"bfd" json:"bfd" mapstructure:"bfd"`

	// MaxPrefixes caps the prefixes accepted from this peer in each unicast
	// family, ipv4-unicast and ipv6-unicast counted separately (0 = the
	// default, DefaultMaxPrefixes); the session is torn down at the limit.
	MaxPrefixes uint32 `yaml:"max-prefixes" json:"max_prefixes" mapstructure:"max-prefixes"`

	// MaxEVPNPrefixes caps the l2vpn-evpn routes accepted from this peer
	// (0 = the default, DefaultMaxEVPNPrefixes). It is separate from
	// MaxPrefixes because an EVPN session is sized by the fabric (VTEPs ×
	// MACs), not by the handful of prefixes a transit peer sends.
	MaxEVPNPrefixes uint32 `yaml:"max-evpn-prefixes" json:"max_evpn_prefixes" mapstructure:"max-evpn-prefixes"`

	// Policy is the RFC 8212 import/export policy for this peer: default
	// deny in both directions, with explicit prefix allowlists.
	Policy PeerPolicyConfig `yaml:"policy" json:"policy" mapstructure:"policy"`
}

// BFDConfig is the per-peer single-hop BFD session configuration.
type BFDConfig struct {
	// Enabled turns BFD on for the peer.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Port is the UDP destination port (default 3784, RFC 5881).
	Port uint16 `yaml:"port" json:"port" mapstructure:"port"`

	// DesiredMinTxInterval is the desired minimum transmit interval.
	DesiredMinTxInterval time.Duration `yaml:"desired-min-tx-interval" json:"desired_min_tx_interval" mapstructure:"desired-min-tx-interval"`

	// RequiredMinRxInterval is the required minimum receive interval.
	RequiredMinRxInterval time.Duration `yaml:"required-min-rx-interval" json:"required_min_rx_interval" mapstructure:"required-min-rx-interval"`

	// DetectionMultiplier is the number of missed packets before the
	// session is declared down.
	DetectionMultiplier uint8 `yaml:"detection-multiplier" json:"detection_multiplier" mapstructure:"detection-multiplier"`
}

// Validate checks the BFD configuration and applies the RFC 5881 defaults.
func (c *BFDConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Port == 0 {
		c.Port = DefaultBFDPort
	}
	if c.DesiredMinTxInterval == 0 {
		c.DesiredMinTxInterval = DefaultBFDInterval
	}
	if c.RequiredMinRxInterval == 0 {
		c.RequiredMinRxInterval = DefaultBFDInterval
	}
	if c.DetectionMultiplier == 0 {
		c.DetectionMultiplier = DefaultBFDDetectionMultiplier
	}
	if c.DesiredMinTxInterval < MinBFDInterval || c.RequiredMinRxInterval < MinBFDInterval {
		return ErrBFDIntervalTooShort{Minimum: MinBFDInterval}
	}
	return nil
}

// PeerPolicyConfig is the per-peer routing policy. Both directions default
// to reject (RFC 8212); a unicast prefix is accepted or exported only if it
// is covered by the corresponding prefix allowlist, and an l2vpn-evpn route
// only if it carries a route target on the corresponding route-target
// allowlist. An empty export prefix allowlist means the speaker's own
// announced prefixes (BGPConfig.Announce); an empty route-target allowlist
// means no EVPN route in that direction.
type PeerPolicyConfig struct {
	// ImportAllow lists the prefixes accepted from the peer. A prefix
	// matches when it is equal to, or more specific than, an entry (up to
	// its /le bound if given as "prefix le N").
	ImportAllow []PrefixMatch `yaml:"import-allow" json:"import_allow" mapstructure:"import-allow"`

	// ExportAllow lists the prefixes announced to the peer. Empty means
	// exactly the configured Announce prefixes.
	ExportAllow []PrefixMatch `yaml:"export-allow" json:"export_allow" mapstructure:"export-allow"`

	// ImportRouteTargets lists the route targets that admit an l2vpn-evpn
	// route from the peer: the route is accepted when it carries at least
	// one of them. Each is "<asn>:<number>" or "<ipv4>:<number>".
	ImportRouteTargets []string `yaml:"import-route-targets" json:"import_route_targets" mapstructure:"import-route-targets"`

	// ExportRouteTargets lists the route targets that let an l2vpn-evpn
	// route be announced to the peer, in the same form.
	ExportRouteTargets []string `yaml:"export-route-targets" json:"export_route_targets" mapstructure:"export-route-targets"`

	// ImportDefaultAccept turns the import direction into accept-by-default
	// (not RFC 8212 compliant; for a trusted internal peer only).
	ImportDefaultAccept bool `yaml:"import-default-accept" json:"import_default_accept" mapstructure:"import-default-accept"`

	// ExportDefaultAccept turns the export direction into accept-by-default.
	ExportDefaultAccept bool `yaml:"export-default-accept" json:"export_default_accept" mapstructure:"export-default-accept"`

	// Import is the traffic engineering applied to paths received from the
	// peer — most often the LOCAL_PREF that ranks this session against the
	// others carrying the same prefix.
	Import *PeerAttributesConfig `yaml:"import" json:"import" mapstructure:"import"`

	// Export is the traffic engineering applied to paths announced to the
	// peer — the MED, AS-path prepend and communities that tell the far
	// side how to rank the paths it receives from this speaker.
	Export *PeerAttributesConfig `yaml:"export" json:"export" mapstructure:"export"`
}

// PrefixMatch is one prefix-list entry: a prefix and the longest prefix
// length it also admits (0 means exact match only).
type PrefixMatch struct {
	// Prefix is the CIDR to match.
	Prefix netip.Prefix `yaml:"prefix" json:"prefix" mapstructure:"prefix"`

	// MaxLength admits more-specific prefixes up to this length; 0 or a
	// value equal to Prefix.Bits() means the exact prefix only.
	MaxLength uint8 `yaml:"max-length" json:"max_length" mapstructure:"max-length"`
}

// Validate checks the prefix entry.
func (m *PrefixMatch) Validate() error {
	if !m.Prefix.IsValid() {
		return &ErrPrefixInvalid{Reason: "policy prefix is invalid"}
	}
	if m.MaxLength != 0 && int(m.MaxLength) < m.Prefix.Bits() {
		return &ErrPrefixInvalid{Reason: "policy max-length is shorter than the prefix"}
	}
	if int(m.MaxLength) > m.Prefix.Addr().BitLen() {
		return &ErrPrefixInvalid{Reason: "policy max-length exceeds the address length"}
	}
	return nil
}

// Validate checks the policy entries and the traffic-engineering
// attributes of both directions.
func (c *PeerPolicyConfig) Validate() error {
	for i := range c.ImportAllow {
		if err := c.ImportAllow[i].Validate(); err != nil {
			return err
		}
	}
	for i := range c.ExportAllow {
		if err := c.ExportAllow[i].Validate(); err != nil {
			return err
		}
	}
	for _, rts := range [][]string{c.ImportRouteTargets, c.ExportRouteTargets} {
		if _, err := routeTargetPatterns(rts); err != nil {
			return err
		}
	}
	if err := c.Import.Validate(PolicyDirectionImport); err != nil {
		return err
	}
	return c.Export.Validate(PolicyDirectionExport)
}

// TCPAOKeychainConfig is a named TCP-AO keychain (RFC 5925). Keys carry the
// send/receive key ids and the algorithm; the master key is a secret
// reference resolved at boot, never a literal.
type TCPAOKeychainConfig struct {
	// Name is the keychain name peers reference.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// Keys are the keychain's keys.
	Keys []TCPAOKeyConfig `yaml:"keys" json:"keys" mapstructure:"keys"`
}

// TCPAOKeyConfig is one TCP-AO key.
type TCPAOKeyConfig struct {
	// SendID is the KeyID used for segments this speaker sends (0–255).
	SendID uint8 `yaml:"send-id" json:"send_id" mapstructure:"send-id"`

	// ReceiveID is the KeyID expected on segments this speaker receives.
	ReceiveID uint8 `yaml:"receive-id" json:"receive_id" mapstructure:"receive-id"`

	// Algorithm is the MAC algorithm: hmac-sha256-128 (default),
	// hmac-sha256-96, aes-128-cmac-96 or hmac-sha1-96.
	Algorithm TCPAOAlgorithm `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`

	// MasterKeyRef is the secret reference URI for the master key.
	MasterKeyRef string `yaml:"master-key-ref" json:"master_key_ref" mapstructure:"master-key-ref"`

	// MasterKey is the resolved master key; never decoded from
	// configuration, filled by ResolveSecrets.
	MasterKey []byte `yaml:"-" json:"-" mapstructure:"-"`

	// ExcludeTCPOptions excludes TCP options from the MAC.
	ExcludeTCPOptions bool `yaml:"exclude-tcp-options" json:"exclude_tcp_options" mapstructure:"exclude-tcp-options"`
}

// TCPAOAlgorithm names a TCP-AO MAC algorithm.
type TCPAOAlgorithm uint8

const (
	// TCPAOAlgorithmHMACSHA256_128 is HMAC-SHA-256 truncated to 128 bits,
	// the default.
	TCPAOAlgorithmHMACSHA256_128 TCPAOAlgorithm = iota

	// TCPAOAlgorithmHMACSHA256_96 is HMAC-SHA-256 truncated to 96 bits.
	TCPAOAlgorithmHMACSHA256_96

	// TCPAOAlgorithmAES128CMAC96 is AES-128-CMAC truncated to 96 bits (RFC 5926).
	TCPAOAlgorithmAES128CMAC96

	// TCPAOAlgorithmHMACSHA1_96 is HMAC-SHA-1 truncated to 96 bits (RFC 5926).
	TCPAOAlgorithmHMACSHA1_96
)

// String returns the configuration spelling.
func (a TCPAOAlgorithm) String() string {
	switch a {
	case TCPAOAlgorithmHMACSHA256_128:
		return "hmac-sha256-128"
	case TCPAOAlgorithmHMACSHA256_96:
		return "hmac-sha256-96"
	case TCPAOAlgorithmAES128CMAC96:
		return "aes-128-cmac-96"
	case TCPAOAlgorithmHMACSHA1_96:
		return "hmac-sha1-96"
	default:
		return "unknown"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (a TCPAOAlgorithm) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler; the empty string is
// the default algorithm.
func (a *TCPAOAlgorithm) UnmarshalText(text []byte) error {
	switch strings.ToLower(strings.TrimSpace(string(text))) {
	case "", "hmac-sha256-128", "hmac-sha256":
		*a = TCPAOAlgorithmHMACSHA256_128
	case "hmac-sha256-96":
		*a = TCPAOAlgorithmHMACSHA256_96
	case "aes-128-cmac-96", "aes-128-cmac":
		*a = TCPAOAlgorithmAES128CMAC96
	case "hmac-sha1-96", "hmac-sha1":
		*a = TCPAOAlgorithmHMACSHA1_96
	default:
		return ErrUnknownTCPAOAlgorithm{Value: string(text)}
	}
	return nil
}

// Validate checks the keychain: a name, at least one key, and a secret
// reference (or an already resolved key) on every key.
func (c *TCPAOKeychainConfig) Validate() error {
	if c.Name == "" {
		return ErrKeychainInvalid{Name: c.Name, Reason: "keychain name is required"}
	}
	if len(c.Keys) == 0 {
		return ErrKeychainInvalid{Name: c.Name, Reason: "keychain has no keys"}
	}
	for i := range c.Keys {
		k := &c.Keys[i]
		if k.MasterKeyRef == "" && len(k.MasterKey) == 0 {
			return ErrKeychainInvalid{Name: c.Name, Reason: "key has no master-key-ref"}
		}
	}
	return nil
}

// SecretResolver resolves a secret reference URI to its value. The bgp
// package never resolves references itself; the daemon that owns the
// resolver SPI supplies one.
type SecretResolver func(ctx context.Context, ref string) ([]byte, error)

// ResolveSecrets fills every MD5 session secret and TCP-AO master key from
// its reference. It fails closed: an unresolved reference is an error, and
// a reference is never used as the secret.
func (c *BGPConfig) ResolveSecrets(ctx context.Context, resolve SecretResolver) error {
	for i := range c.Neighbors {
		n := &c.Neighbors[i]
		if n.AuthType != AuthTypeMD5 || n.AuthKey != "" {
			continue
		}
		if resolve == nil {
			return ErrSecretResolverRequired{Ref: n.AuthKeyRef}
		}
		v, err := resolve(ctx, n.AuthKeyRef)
		if err != nil {
			return ErrSecretResolutionFailed{Ref: n.AuthKeyRef, Cause: err}
		}
		if len(v) == 0 {
			// An empty secret would run the session with no MD5 password
			// while the configuration says md5 — a fail-open, not a value.
			return ErrSecretResolutionFailed{Ref: n.AuthKeyRef, Cause: ErrSecretEmpty{}}
		}
		n.AuthKey = string(v)
	}
	for i := range c.Keychains {
		for j := range c.Keychains[i].Keys {
			k := &c.Keychains[i].Keys[j]
			if len(k.MasterKey) > 0 {
				continue
			}
			if resolve == nil {
				return ErrSecretResolverRequired{Ref: k.MasterKeyRef}
			}
			v, err := resolve(ctx, k.MasterKeyRef)
			if err != nil {
				return ErrSecretResolutionFailed{Ref: k.MasterKeyRef, Cause: err}
			}
			if len(v) == 0 {
				return ErrSecretResolutionFailed{Ref: k.MasterKeyRef, Cause: ErrSecretEmpty{}}
			}
			k.MasterKey = v
		}
	}
	return nil
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
	switch c.AuthType {
	case AuthTypeMD5:
		if !md5SessionAuthPermitted() {
			return ErrAuthTypeUnavailableInFIPS{Peer: c.Address.String(), AuthType: c.AuthType}
		}
		if c.AuthKeyRef == "" && c.AuthKey == "" {
			return ErrAuthSecretRequired{Peer: c.Address.String(), AuthType: c.AuthType}
		}
	case AuthTypeTCPAO:
		if c.Keychain == "" {
			return ErrAuthSecretRequired{Peer: c.Address.String(), AuthType: c.AuthType}
		}
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
	if c.MaxPrefixes == 0 {
		c.MaxPrefixes = DefaultMaxPrefixes
	}
	if c.MaxEVPNPrefixes == 0 {
		c.MaxEVPNPrefixes = DefaultMaxEVPNPrefixes
	}
	if c.BFD != nil {
		if err := c.BFD.Validate(); err != nil {
			return err
		}
	}
	if err := c.Policy.Validate(); err != nil {
		return err
	}
	// The template's `families:` list and the per-family booleans are two
	// spellings of one fact; fold them together so both callers agree.
	for _, af := range c.EnabledFamilies {
		switch af {
		case AFamilyIPv4Unicast:
			c.IPv4Unicast = true
		case AFamilyIPv6Unicast:
			c.IPv6Unicast = true
		case AFamilyEVPN:
			c.EVPN = true
		}
	}
	return nil
}

// PrefixLimit returns the number of routes the peer may send in family
// before the session is torn down. l2vpn-evpn has its own limit; every
// other family takes the unicast one. A limit the configuration left at
// zero is the family's default.
func (c *NeighborConfig) PrefixLimit(family AddressFamily) uint32 {
	if family == AFamilyEVPN {
		if c.MaxEVPNPrefixes == 0 {
			return DefaultMaxEVPNPrefixes
		}
		return c.MaxEVPNPrefixes
	}
	if c.MaxPrefixes == 0 {
		return DefaultMaxPrefixes
	}
	return c.MaxPrefixes
}

// Families returns the peer's enabled address families in a stable order,
// folding the boolean flags and the list together.
func (c *NeighborConfig) Families() []AddressFamily {
	out := make([]AddressFamily, 0, 3)
	seen := map[AddressFamily]bool{}
	add := func(af AddressFamily) {
		if !seen[af] {
			seen[af] = true
			out = append(out, af)
		}
	}
	for _, af := range c.EnabledFamilies {
		add(af)
	}
	if c.IPv4Unicast {
		add(AFamilyIPv4Unicast)
	}
	if c.IPv6Unicast {
		add(AFamilyIPv6Unicast)
	}
	if c.EVPN {
		add(AFamilyEVPN)
	}
	return out
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
	// PrefixesAccepted counts the received prefixes import policy admitted.
	PrefixesAccepted int64
	// BFD is the single-hop BFD session toward this peer, nil when BFD is
	// not configured for it.
	BFD *BFDSessionInfo
}

// BFDSessionState is the RFC 5880 §6.8.1 session state of a BFD session.
type BFDSessionState string

// BFD session states as GoBGP reports them.
const (
	BFDSessionUnknown   BFDSessionState = "unknown"
	BFDSessionUp        BFDSessionState = "up"
	BFDSessionDown      BFDSessionState = "down"
	BFDSessionAdminDown BFDSessionState = "admin-down"
	BFDSessionInit      BFDSessionState = "init"
)

// BFDSessionInfo is the state of one peer's single-hop BFD session (RFC
// 5881) as the speaker reports it.
type BFDSessionInfo struct {
	// LocalState is this end's session state; RemoteState is what the peer
	// last signalled.
	LocalState  BFDSessionState
	RemoteState BFDSessionState
	// LocalDiscriminator and RemoteDiscriminator identify the session at
	// each end; zero until the session has been negotiated.
	LocalDiscriminator  uint32
	RemoteDiscriminator uint32
	// FailureTransitions counts Up→Down transitions since the session was
	// created; LastFailure is when the last one happened (zero if none).
	FailureTransitions uint64
	LastFailure        time.Time
	// LocalDiagnostic and RemoteDiagnostic are the RFC 5880 §4.1 diagnostic
	// codes explaining the last state change at each end.
	LocalDiagnostic  string
	RemoteDiagnostic string
	// DesiredMinTxInterval and RequiredMinRxInterval are the configured
	// timers; DetectionMultiplier the configured multiplier.
	DesiredMinTxInterval  time.Duration
	RequiredMinRxInterval time.Duration
	DetectionMultiplier   uint8
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

	// EVPN is the decoded route of an l2vpn-evpn path; nil for every other
	// family.
	EVPN *EVPNRouteData
}

// Aggregator holds BGP aggregator information.
type Aggregator struct {
	ASN     uint32
	Address netip.Addr
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
