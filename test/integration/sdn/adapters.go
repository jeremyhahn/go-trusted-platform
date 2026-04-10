//go:build integration

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

// Package sdn provides multi-protocol integration test infrastructure for SDN services.
// This file defines the SDNTestAdapter interface and common types used across all
// protocol adapters (CLI, REST, gRPC, QUIC, MCP, Unix) for comprehensive SDN testing.
//
// Phase 6 integration tests verify:
// - VXLAN overlay networking across multiple hosts
// - BGP EVPN control plane operations
// - Multi-mode gateway functionality
// - IPAM pool management and IP allocation
// - DHCP server operations
//
// Run tests via:
//
//	make integration-test-sdn
package sdn

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// =============================================================================
// SDN Test Adapter Interface - Phase 6 Integration Testing
// =============================================================================

// SDNTestAdapter defines the comprehensive command set for SDN integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Unix) implements this interface
// to ensure feature parity across all transport layers.
//
// The interface covers all SDN components:
// - Overlay: VXLAN VTEP management, VNI operations, tunnel and MAC learning
// - Gateway: Mode management, health status, and configuration
// - BGP: Peer management, prefix announcements, EVPN routes
// - IPAM: Pool management, IP allocation and release
// - DHCP: Server status, lease management
type SDNTestAdapter interface {
	// Protocol identification and lifecycle management
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// =========================================================================
	// Overlay Operations
	// =========================================================================

	// ListVTEPs returns all discovered VTEPs in the overlay network.
	// VTEPs (VXLAN Tunnel Endpoints) are the underlay endpoints for VXLAN tunnels.
	ListVTEPs(ctx context.Context) (*VTEPListResponse, error)

	// CreateVNI creates a new VNI (Virtual Network Identifier) for tenant isolation.
	// VNIs provide layer 2 isolation similar to VLANs but with a 24-bit address space.
	CreateVNI(ctx context.Context, vni uint32) error

	// DeleteVNI removes a VNI and all associated tunnels and MAC entries.
	DeleteVNI(ctx context.Context, vni uint32) error

	// ListTunnels returns all active VXLAN tunnels.
	// Tunnels are established between VTEPs for east-west VM traffic.
	ListTunnels(ctx context.Context) (*TunnelListResponse, error)

	// ListRemoteMACs returns all learned remote MAC addresses for a VNI.
	// Remote MACs are learned via EVPN Type-2 routes or datapath learning.
	ListRemoteMACs(ctx context.Context, vni uint32) (*RemoteMACListResponse, error)

	// =========================================================================
	// Gateway Operations
	// =========================================================================

	// GetGatewayStatus returns the current gateway node status.
	// Status includes enabled modes, health, reputation, and uptime.
	GetGatewayStatus(ctx context.Context) (*GatewayStatusResponse, error)

	// SetGatewayMode configures the gateway operational mode(s).
	// Modes: overlay (VXLAN/EVPN), edge (IoT/P2P), transit (BGP announcements).
	SetGatewayMode(ctx context.Context, mode GatewayMode) error

	// =========================================================================
	// BGP Operations
	// =========================================================================

	// GetBGPStatus returns the current BGP speaker status.
	// Status includes ASN, router ID, peer count, and enabled features.
	GetBGPStatus(ctx context.Context) (*BGPStatusResponse, error)

	// ListBGPPeers returns all configured BGP peers and their session state.
	ListBGPPeers(ctx context.Context) (*BGPPeerListResponse, error)

	// AnnouncePrefix announces a new IP prefix via BGP.
	// This is used for transit mode to announce platform IP blocks.
	AnnouncePrefix(ctx context.Context, prefix string) error

	// WithdrawPrefix withdraws a previously announced IP prefix.
	WithdrawPrefix(ctx context.Context, prefix string) error

	// =========================================================================
	// IPAM Operations
	// =========================================================================

	// ListPools returns all configured IPAM pools.
	// Pools define IP ranges for allocation with CIDR, gateway, and DNS.
	ListPools(ctx context.Context) (*IPAMPoolListResponse, error)

	// AllocateIP allocates an IP address from the specified pool.
	// Returns the allocated IP and lease information.
	AllocateIP(ctx context.Context, poolID string) (*IPAllocationResponse, error)

	// ReleaseIP releases a previously allocated IP address.
	ReleaseIP(ctx context.Context, poolID, ip string) error

	// =========================================================================
	// DHCP Operations
	// =========================================================================

	// GetDHCPStatus returns the current DHCP server status.
	// Status includes active/inactive state, statistics, and configuration.
	GetDHCPStatus(ctx context.Context) (*DHCPStatusResponse, error)

	// ListLeases returns all active DHCP leases.
	ListLeases(ctx context.Context) (*DHCPLeaseListResponse, error)
}

// =============================================================================
// VTEP Types
// =============================================================================

// VTEPListResponse contains the list of discovered VTEPs.
type VTEPListResponse struct {
	VTEPs      []VTEPEntry
	TotalCount int
}

// VTEPEntry represents a single VTEP endpoint.
type VTEPEntry struct {
	// NodeID is the unique identifier for this VTEP node.
	NodeID string

	// IP is the underlay IP address of the VTEP.
	IP netip.Addr

	// State indicates the VTEP health state (healthy, degraded, unhealthy).
	State string

	// IsLocal indicates if this is the local VTEP.
	IsLocal bool

	// TunnelPort is the VXLAN UDP port (typically 4789).
	TunnelPort uint16

	// LastSeen is the last time this VTEP was seen.
	LastSeen time.Time

	// VNICount is the number of VNIs this VTEP participates in.
	VNICount int

	// BytesSent is the total bytes sent through this VTEP.
	BytesSent uint64

	// BytesRecv is the total bytes received through this VTEP.
	BytesRecv uint64
}

// =============================================================================
// Tunnel Types
// =============================================================================

// TunnelListResponse contains the list of active tunnels.
type TunnelListResponse struct {
	Tunnels    []TunnelEntry
	TotalCount int
}

// TunnelEntry represents a single VXLAN tunnel.
type TunnelEntry struct {
	// LocalVTEP is the local VTEP IP address.
	LocalVTEP netip.Addr

	// RemoteVTEP is the remote VTEP IP address.
	RemoteVTEP netip.Addr

	// VNI is the Virtual Network Identifier for this tunnel.
	VNI uint32

	// State indicates the tunnel state (up, down, establishing).
	State string

	// PortName is the OVS port name for this tunnel.
	PortName string

	// BytesSent is the bytes sent through this tunnel.
	BytesSent uint64

	// BytesRecv is the bytes received through this tunnel.
	BytesRecv uint64

	// CreatedAt is when this tunnel was established.
	CreatedAt time.Time
}

// =============================================================================
// Remote MAC Types
// =============================================================================

// RemoteMACListResponse contains the list of learned remote MACs.
type RemoteMACListResponse struct {
	MACs       []RemoteMACEntry
	TotalCount int
}

// RemoteMACEntry represents a remote MAC address learned via EVPN or datapath.
type RemoteMACEntry struct {
	// MAC is the remote MAC address.
	MAC net.HardwareAddr

	// IP is the associated IP address (if known from EVPN Type-2).
	IP netip.Addr

	// VNI is the Virtual Network Identifier.
	VNI uint32

	// RemoteVTEP is the VTEP where this MAC is located.
	RemoteVTEP netip.Addr

	// Source indicates how this MAC was learned (evpn, datapath, static).
	Source string

	// LearnedAt is when this MAC was learned.
	LearnedAt time.Time

	// ExpiresAt is when this MAC entry expires (zero for static entries).
	ExpiresAt time.Time
}

// =============================================================================
// Gateway Types
// =============================================================================

// GatewayMode represents the operational modes of a gateway node.
type GatewayMode uint32

const (
	// GatewayModeNone indicates no mode is active.
	GatewayModeNone GatewayMode = 0

	// GatewayModeOverlay enables VXLAN/EVPN overlay networking.
	GatewayModeOverlay GatewayMode = 1 << 0

	// GatewayModeEdge enables IoT device onboarding and P2P services.
	GatewayModeEdge GatewayMode = 1 << 1

	// GatewayModeTransit enables BGP transit for IP block announcements.
	GatewayModeTransit GatewayMode = 1 << 2
)

// String returns a string representation of the gateway mode.
func (m GatewayMode) String() string {
	var modes []string
	if m&GatewayModeOverlay != 0 {
		modes = append(modes, "overlay")
	}
	if m&GatewayModeEdge != 0 {
		modes = append(modes, "edge")
	}
	if m&GatewayModeTransit != 0 {
		modes = append(modes, "transit")
	}
	if len(modes) == 0 {
		return "none"
	}
	result := modes[0]
	for i := 1; i < len(modes); i++ {
		result += "," + modes[i]
	}
	return result
}

// GatewayStatusResponse contains the gateway node status.
type GatewayStatusResponse struct {
	// NodeID is the unique identifier for this gateway.
	NodeID string

	// Modes is the active gateway mode bitmask.
	Modes GatewayMode

	// Tier indicates the BGP speaker tier (backbone, datacenter, coordinator).
	Tier string

	// Healthy indicates if the gateway is healthy.
	Healthy bool

	// Reputation is the node reputation score (0.0 to 1.0).
	Reputation float64

	// Age is how long this node has been a gateway.
	Age time.Duration

	// UptimePct is the uptime percentage.
	UptimePct float64

	// IPv6Pool is the allocated IPv6 pool (if edge mode).
	IPv6Pool string

	// IPv4Pool is the allocated IPv4 pool (if transit mode).
	IPv4Pool string

	// BGPEnabled indicates if BGP is enabled.
	BGPEnabled bool

	// EVPNEnabled indicates if EVPN is enabled.
	EVPNEnabled bool

	// TransitEnabled indicates if BGP transit is enabled.
	TransitEnabled bool
}

// =============================================================================
// BGP Types
// =============================================================================

// BGPStatusResponse contains the BGP speaker status.
type BGPStatusResponse struct {
	// Enabled indicates if BGP is enabled.
	Enabled bool

	// ASN is the local Autonomous System Number.
	ASN uint32

	// RouterID is the BGP router ID.
	RouterID string

	// State is the speaker state (idle, active, running).
	State string

	// PeerCount is the total number of configured peers.
	PeerCount int

	// EstablishedCount is the number of established peer sessions.
	EstablishedCount int

	// EVPNEnabled indicates if EVPN address family is enabled.
	EVPNEnabled bool

	// TransitEnabled indicates if transit announcements are enabled.
	TransitEnabled bool

	// RPKIEnabled indicates if RPKI validation is enabled.
	RPKIEnabled bool
}

// BGPPeerListResponse contains the list of BGP peers.
type BGPPeerListResponse struct {
	Peers      []BGPPeerEntry
	TotalCount int
}

// BGPPeerEntry represents a BGP peer.
type BGPPeerEntry struct {
	// Address is the peer IP address.
	Address string

	// RemoteASN is the peer's Autonomous System Number.
	RemoteASN uint32

	// State is the BGP session state (idle, connect, active, opensent, openconfirm, established).
	State string

	// Uptime is how long the session has been established.
	Uptime time.Duration

	// PrefixesRecv is the number of prefixes received from this peer.
	PrefixesRecv int

	// PrefixesSent is the number of prefixes sent to this peer.
	PrefixesSent int

	// Description is a human-readable description.
	Description string

	// LastError is the last error message (if any).
	LastError string
}

// =============================================================================
// IPAM Types
// =============================================================================

// IPAMPoolListResponse contains the list of IPAM pools.
type IPAMPoolListResponse struct {
	Pools      []IPAMPoolEntry
	TotalCount int
}

// IPAMPoolEntry represents an IPAM pool.
type IPAMPoolEntry struct {
	// ID is the unique pool identifier.
	ID string

	// Name is the human-readable pool name.
	Name string

	// CIDR is the IP range in CIDR notation.
	CIDR string

	// Gateway is the gateway address for this pool.
	Gateway string

	// TotalIPs is the total number of IPs in this pool.
	TotalIPs int64

	// AllocatedIPs is the number of currently allocated IPs.
	AllocatedIPs int64

	// AvailableIPs is the number of available IPs.
	AvailableIPs int64

	// UtilizationPct is the utilization percentage.
	UtilizationPct float64

	// DNS is the list of DNS servers for this pool.
	DNS []string

	// LeaseDuration is the default lease duration for allocations.
	LeaseDuration time.Duration
}

// IPAllocationResponse contains the result of an IP allocation.
type IPAllocationResponse struct {
	// IP is the allocated IP address.
	IP netip.Addr

	// PoolID is the pool from which the IP was allocated.
	PoolID string

	// LeaseExpiry is when the lease expires.
	LeaseExpiry time.Time

	// Gateway is the gateway for this allocation.
	Gateway string

	// DNS is the DNS servers for this allocation.
	DNS []string

	// SubnetMask is the subnet mask.
	SubnetMask string
}

// =============================================================================
// DHCP Types
// =============================================================================

// DHCPStatusResponse contains the DHCP server status.
type DHCPStatusResponse struct {
	// Running indicates if the DHCP server is running.
	Running bool

	// Interface is the network interface the server is bound to.
	Interface string

	// StartedAt is when the server was started.
	StartedAt time.Time

	// Uptime is how long the server has been running.
	Uptime time.Duration

	// PacketsReceived is the total packets received.
	PacketsReceived uint64

	// PacketsSent is the total packets sent.
	PacketsSent uint64

	// ActiveLeases is the number of active leases.
	ActiveLeases int

	// Stats contains detailed statistics.
	Stats DHCPStats
}

// DHCPStats contains detailed DHCP statistics.
type DHCPStats struct {
	DiscoverCount uint64
	OfferCount    uint64
	RequestCount  uint64
	AckCount      uint64
	NakCount      uint64
	ReleaseCount  uint64
	DeclineCount  uint64
	InformCount   uint64
	ErrorCount    uint64
}

// DHCPLeaseListResponse contains the list of DHCP leases.
type DHCPLeaseListResponse struct {
	Leases     []DHCPLeaseEntry
	TotalCount int
}

// DHCPLeaseEntry represents a DHCP lease.
type DHCPLeaseEntry struct {
	// IP is the leased IP address.
	IP netip.Addr

	// MAC is the client MAC address.
	MAC net.HardwareAddr

	// Hostname is the client hostname (if provided).
	Hostname string

	// State is the lease state (active, expired, released).
	State string

	// LeaseStart is when the lease started.
	LeaseStart time.Time

	// LeaseExpiry is when the lease expires.
	LeaseExpiry time.Time

	// ClientID is the DHCP client identifier.
	ClientID string

	// PoolID is the pool from which this lease was allocated.
	PoolID string
}

// =============================================================================
// Adapter Error Types
// =============================================================================

// ErrAdapterSetupFailed indicates adapter setup failed.
type ErrAdapterSetupFailed struct {
	Protocol string
	Err      error
}

func (e ErrAdapterSetupFailed) Error() string {
	return "adapter setup failed for " + e.Protocol + ": " + e.Err.Error()
}

func (e ErrAdapterSetupFailed) Unwrap() error {
	return e.Err
}

// ErrAdapterNotImplemented indicates the operation is not implemented for this adapter.
type ErrAdapterNotImplemented struct {
	Protocol  string
	Operation string
}

func (e ErrAdapterNotImplemented) Error() string {
	return "operation " + e.Operation + " not implemented for protocol " + e.Protocol
}

// ErrVTEPNotFound indicates a VTEP was not found.
type ErrVTEPNotFound struct {
	NodeID string
}

func (e ErrVTEPNotFound) Error() string {
	return "VTEP not found: " + e.NodeID
}

// ErrVNINotFound indicates a VNI was not found.
type ErrVNINotFound struct {
	VNI uint32
}

func (e ErrVNINotFound) Error() string {
	return "VNI not found: " + string(rune(e.VNI))
}

// ErrPoolNotFound indicates an IPAM pool was not found.
type ErrPoolNotFound struct {
	PoolID string
}

func (e ErrPoolNotFound) Error() string {
	return "pool not found: " + e.PoolID
}

// ErrAllocationFailed indicates IP allocation failed.
type ErrAllocationFailed struct {
	PoolID string
	Reason string
}

func (e ErrAllocationFailed) Error() string {
	return "allocation failed for pool " + e.PoolID + ": " + e.Reason
}

// ErrBGPPrefixInvalid indicates an invalid BGP prefix.
type ErrBGPPrefixInvalid struct {
	Prefix string
	Reason string
}

func (e ErrBGPPrefixInvalid) Error() string {
	return "invalid BGP prefix " + e.Prefix + ": " + e.Reason
}

// ErrGatewayModeInvalid indicates an invalid gateway mode.
type ErrGatewayModeInvalid struct {
	Mode string
}

func (e ErrGatewayModeInvalid) Error() string {
	return "invalid gateway mode: " + e.Mode
}

// =============================================================================
// Adapter Factory Functions
// =============================================================================

// NewSDNTestAdapters returns all available SDN test adapters.
// This function creates instances of all protocol adapters for multi-protocol testing.
func NewSDNTestAdapters() []SDNTestAdapter {
	return []SDNTestAdapter{
		NewSDNRESTAdapter(),
		NewSDNGRPCAdapter(),
		NewSDNQUICAdapter(),
		NewSDNMCPAdapter(),
		NewSDNUnixAdapter(),
	}
}

// NewSDNTestAdaptersWithCLI returns all SDN test adapters including CLI.
// CLI adapter is separate because it requires the platformctl binary.
func NewSDNTestAdaptersWithCLI() []SDNTestAdapter {
	adapters := NewSDNTestAdapters()
	// Prepend CLI adapter
	return append([]SDNTestAdapter{NewSDNCLIAdapter()}, adapters...)
}
