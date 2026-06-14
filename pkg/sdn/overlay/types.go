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

// Package overlay provides overlay network orchestration for SDN environments.
// It coordinates VXLAN tunnel management, BGP/EVPN control plane, and gateway
// node functionality to provide a unified overlay networking layer.
package overlay

import (
	"net"
	"net/netip"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

// VNI range constants matching vxlan package.
const (
	// MinVNI is the minimum valid VNI value.
	MinVNI uint32 = 1

	// MaxVNI is the maximum valid VNI value (2^24 - 1).
	MaxVNI uint32 = 16777215
)

// Default configuration values.
const (
	// DefaultVXLANPort is the standard IANA-assigned UDP port for VXLAN.
	DefaultVXLANPort uint16 = 4789

	// DefaultVNIBase is the base VNI for VLAN-to-VNI mapping.
	DefaultVNIBase uint32 = 1000000

	// DefaultUnderlayMTU is the default MTU for underlay networks.
	DefaultUnderlayMTU int = 9000

	// DefaultStateBackend is the default state storage backend.
	DefaultStateBackend string = "memory"

	// DefaultHealthCheckInterval is the default interval for health checks.
	DefaultHealthCheckInterval = 30 * time.Second

	// DefaultMACExpiration is the default expiration time for learned MACs.
	DefaultMACExpiration = 5 * time.Minute

	// DefaultBridgeName is the default OVS bridge name for overlay traffic.
	DefaultBridgeName = "br-overlay"
)

// ControllerState represents the operational state of the overlay controller.
type ControllerState uint8

const (
	// ControllerStateUnknown indicates the controller state is unknown.
	ControllerStateUnknown ControllerState = iota

	// ControllerStateInitializing indicates the controller is starting up.
	ControllerStateInitializing

	// ControllerStateRunning indicates the controller is fully operational.
	ControllerStateRunning

	// ControllerStateDegraded indicates the controller is running with reduced functionality.
	ControllerStateDegraded

	// ControllerStateStopping indicates the controller is shutting down.
	ControllerStateStopping

	// ControllerStateStopped indicates the controller is stopped.
	ControllerStateStopped

	// ControllerStateError indicates the controller is in an error state.
	ControllerStateError
)

// String returns a human-readable representation of the controller state.
func (s ControllerState) String() string {
	switch s {
	case ControllerStateInitializing:
		return "initializing"
	case ControllerStateRunning:
		return "running"
	case ControllerStateDegraded:
		return "degraded"
	case ControllerStateStopping:
		return "stopping"
	case ControllerStateStopped:
		return "stopped"
	case ControllerStateError:
		return "error"
	default:
		return "unknown"
	}
}

// Valid returns true if the controller state is a recognized value.
func (s ControllerState) Valid() bool {
	return s >= ControllerStateUnknown && s <= ControllerStateError
}

// IsOperational returns true if the controller is in an operational state.
func (s ControllerState) IsOperational() bool {
	return s == ControllerStateRunning || s == ControllerStateDegraded
}

// IsHealthy returns true if the controller is fully healthy.
func (s ControllerState) IsHealthy() bool {
	return s == ControllerStateRunning
}

// Config configures the overlay controller.
type Config struct {
	// NodeID is the unique identifier for this node.
	NodeID string

	// VTEPIP is this node's VTEP IP address.
	VTEPIP netip.Addr

	// UnderlayInterface is the physical interface for underlay traffic.
	UnderlayInterface string

	// UnderlayMTU is the MTU of the underlay network.
	UnderlayMTU int

	// VXLANPort is the UDP port for VXLAN (default 4789).
	VXLANPort uint16

	// VNIBase is the base VNI number for VLAN mapping.
	VNIBase uint32

	// BridgeName is the OVS bridge name for overlay traffic.
	BridgeName string

	// OVSSocketPath is the path to the OVSDB socket.
	OVSSocketPath string

	// BGPConfig is the BGP service configuration.
	BGPConfig *bgp.BGPConfig

	// GatewayConfig is the gateway node configuration.
	GatewayConfig *gateway.GatewayConfig

	// StateBackend determines where state is stored ("memory", "quicbaas").
	StateBackend string

	// HealthCheckInterval is the interval for health checks.
	HealthCheckInterval time.Duration

	// MACExpiration is the expiration time for learned remote MACs.
	MACExpiration time.Duration

	// EnableEVPN enables EVPN for MAC/IP advertisement and learning.
	EnableEVPN bool
}

// Validate validates the overlay configuration.
func (c *Config) Validate() error {
	if c.NodeID == "" {
		return ErrNodeIDEmpty
	}

	if !c.VTEPIP.IsValid() || c.VTEPIP.IsUnspecified() {
		return ErrInvalidVTEPIP
	}

	if c.UnderlayInterface == "" {
		return ErrUnderlayInterfaceEmpty
	}

	if c.UnderlayMTU < vxlan.MinimumMTU {
		return ErrMTUTooSmall
	}

	if c.VXLANPort == 0 {
		return ErrInvalidVXLANPort
	}

	if c.BridgeName == "" {
		return ErrBridgeNameEmpty
	}

	return nil
}

// ApplyDefaults applies default values for unset fields.
func (c *Config) ApplyDefaults() {
	if c.UnderlayMTU == 0 {
		c.UnderlayMTU = DefaultUnderlayMTU
	}
	if c.VXLANPort == 0 {
		c.VXLANPort = DefaultVXLANPort
	}
	if c.VNIBase == 0 {
		c.VNIBase = DefaultVNIBase
	}
	if c.BridgeName == "" {
		c.BridgeName = DefaultBridgeName
	}
	if c.StateBackend == "" {
		c.StateBackend = DefaultStateBackend
	}
	if c.HealthCheckInterval == 0 {
		c.HealthCheckInterval = DefaultHealthCheckInterval
	}
	if c.MACExpiration == 0 {
		c.MACExpiration = DefaultMACExpiration
	}
}

// State represents the current state of the overlay network.
type State struct {
	// NodeID is this node's identifier.
	NodeID string

	// VTEPIP is this node's VTEP IP address.
	VTEPIP netip.Addr

	// ControllerState is the controller's operational state.
	ControllerState ControllerState

	// VTEPs contains information about known VTEP endpoints.
	VTEPs []VTEPInfo

	// Tunnels contains information about VXLAN tunnels.
	Tunnels []TunnelInfo

	// RemoteMACs contains MAC addresses learned from remote VTEPs.
	RemoteMACs []RemoteMACEntry

	// VNIs contains information about configured VNIs.
	VNIs []VNIInfo

	// BGPStatus contains the BGP service status.
	BGPStatus *BGPStatus

	// GatewayMode is the active gateway mode, if any.
	GatewayMode gateway.GatewayMode

	// StartedAt is when the controller was started.
	StartedAt time.Time

	// LastHealthCheck is when the last health check was performed.
	LastHealthCheck time.Time
}

// VTEPInfo contains information about a VTEP endpoint.
type VTEPInfo struct {
	// NodeID is the identifier of the node hosting this VTEP.
	NodeID string

	// IP is the VTEP IP address.
	IP netip.Addr

	// Healthy indicates if the VTEP is healthy.
	Healthy bool

	// LastSeen is when the VTEP was last seen.
	LastSeen time.Time

	// TunnelCount is the number of tunnels to this VTEP.
	TunnelCount int

	// EVPNEnabled indicates if EVPN is enabled for this VTEP.
	EVPNEnabled bool
}

// TunnelInfo contains information about a VXLAN tunnel.
type TunnelInfo struct {
	// ID is the unique tunnel identifier.
	ID string

	// LocalVTEP is the local VTEP IP address.
	LocalVTEP netip.Addr

	// RemoteVTEP is the remote VTEP IP address.
	RemoteVTEP netip.Addr

	// VNI is the VXLAN Network Identifier.
	VNI uint32

	// State is the tunnel's operational state.
	State vxlan.TunnelStatus

	// OVSPort is the OVS port name for this tunnel.
	OVSPort string

	// OFPort is the OpenFlow port number.
	OFPort int32

	// BytesTx is the total bytes transmitted.
	BytesTx uint64

	// BytesRx is the total bytes received.
	BytesRx uint64

	// CreatedAt is when the tunnel was created.
	CreatedAt time.Time
}

// RemoteMACEntry represents a MAC address learned from a remote VTEP.
type RemoteMACEntry struct {
	// MAC is the hardware address.
	MAC net.HardwareAddr

	// VNI is the VXLAN Network Identifier.
	VNI uint32

	// RemoteVTEP is the VTEP IP where this MAC resides.
	RemoteVTEP netip.Addr

	// IP is the associated IP address (for ARP suppression).
	IP netip.Addr

	// LearnedAt is when this MAC was learned.
	LearnedAt time.Time

	// ExpiresAt is when this MAC entry expires.
	ExpiresAt time.Time

	// Source indicates how the MAC was learned ("evpn", "datapath", "static").
	Source string
}

// IsExpired returns true if the MAC entry has expired.
func (e *RemoteMACEntry) IsExpired() bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(e.ExpiresAt)
}

// Key returns a unique key for this MAC entry.
func (e *RemoteMACEntry) Key() string {
	return formatMACKey(e.VNI, e.MAC)
}

// VNIInfo contains information about a configured VNI.
type VNIInfo struct {
	// VNI is the VXLAN Network Identifier.
	VNI uint32

	// VLAN is the associated VLAN ID (0 if none).
	VLAN uint16

	// TunnelCount is the number of tunnels for this VNI.
	TunnelCount int

	// MACCount is the number of learned MACs in this VNI.
	MACCount int

	// IMETAdvertised indicates if IMET is advertised for this VNI.
	IMETAdvertised bool

	// CreatedAt is when this VNI was configured.
	CreatedAt time.Time
}

// BGPStatus contains the BGP service status.
type BGPStatus struct {
	// Running indicates if BGP is running.
	Running bool

	// RouterID is the BGP router ID.
	RouterID netip.Addr

	// ASN is the autonomous system number.
	ASN uint32

	// PeerCount is the total number of configured peers.
	PeerCount int

	// EstablishedPeers is the number of established peer sessions.
	EstablishedPeers int

	// EVPNRoutesReceived is the count of EVPN routes received.
	EVPNRoutesReceived int

	// EVPNRoutesAdvertised is the count of EVPN routes advertised.
	EVPNRoutesAdvertised int

	// Uptime is how long BGP has been running.
	Uptime time.Duration
}

// VNIConfig contains configuration for a VNI.
type VNIConfig struct {
	// VNI is the VXLAN Network Identifier.
	// When Zone is set and VNI is zero, the controller derives the VNI from
	// the zone-specific allocation base:
	//   - ZoneTenant zones use vlan.TenantBase (1000) as the VNI base.
	//   - All other zones use the overlay Config.VNIBase.
	// Callers may override by setting VNI explicitly to a non-zero value.
	VNI uint32

	// VLAN is the optional associated VLAN ID.
	VLAN uint16

	// Zone is the trust/exposure zone for this VNI. When set for a
	// ZoneTenant zone, VNI allocation uses vlan.TenantBase as the base,
	// providing per-tenant isolation in the 1000+ range. For all other
	// zones the overlay Config.VNIBase is used. An empty Zone means no
	// zone-specific allocation; VNI must be set explicitly.
	Zone string

	// Multicast is the optional multicast group for BUM traffic.
	Multicast netip.Addr

	// AdvertiseIMET indicates if IMET should be advertised for this VNI.
	AdvertiseIMET bool
}

// Validate validates the VNI configuration.
func (c *VNIConfig) Validate() error {
	if c.VNI < MinVNI || c.VNI > MaxVNI {
		return ErrVNIOutOfRange
	}
	if c.VLAN > 4094 {
		return ErrVLANOutOfRange
	}
	return nil
}

// formatMACKey creates a key string for MAC lookups.
func formatMACKey(vni uint32, mac net.HardwareAddr) string {
	// Efficient string formatting without fmt
	buf := make([]byte, 0, 32)

	// Format VNI
	vniStr := formatUint32(vni)
	buf = append(buf, vniStr...)
	buf = append(buf, ':')

	// Format MAC
	buf = append(buf, mac.String()...)

	return string(buf)
}

// formatUint32 converts a uint32 to a string without using fmt.
func formatUint32(n uint32) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 10)
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n%10) + '0'
		n /= 10
	}
	return string(buf[i:])
}
