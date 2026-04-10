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

package sdn

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// =============================================================================
// Overlay Commands Interface
// =============================================================================

// OverlayCommands defines the command set for overlay/gateway/IPAM integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Socket) implements this interface.
type OverlayCommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Overlay Status
	OverlayStatus(ctx context.Context) (*OverlayStatusResult, error)

	// VTEP Commands (platformctl sdn overlay vtep ...)
	VTEPList(ctx context.Context) (*VTEPListResult, error)
	VTEPGet(ctx context.Context, nodeID string) (*VTEPGetResult, error)

	// VNI Commands (platformctl sdn overlay vni ...)
	VNICreate(ctx context.Context, opts VNICreateOptions) (*VNICreateResult, error)
	VNIDelete(ctx context.Context, vni uint32) (*VNIDeleteResult, error)
	VNIList(ctx context.Context) (*VNIListResult, error)

	// Tunnel Commands (platformctl sdn overlay tunnel ...)
	TunnelList(ctx context.Context, opts TunnelListOptions) (*TunnelListResult, error)

	// MAC Commands (platformctl sdn overlay mac ...)
	MACList(ctx context.Context, opts MACListOptions) (*MACListResult, error)
	MACForget(ctx context.Context, mac string, vni uint32) (*MACForgetResult, error)

	// Gateway Commands (platformctl sdn gateway ...)
	GatewayStatus(ctx context.Context) (*GatewayStatusResult, error)
	GatewaySetMode(ctx context.Context, opts GatewayModeOptions) (*GatewayModeResult, error)

	// BGP Commands (platformctl sdn gateway bgp ...)
	BGPStatus(ctx context.Context) (*BGPStatusResult, error)
	BGPPeers(ctx context.Context) (*BGPPeersResult, error)
	BGPPrefixes(ctx context.Context) (*BGPPrefixesResult, error)
	BGPAnnounce(ctx context.Context, opts BGPAnnounceOptions) (*BGPAnnounceResult, error)
	BGPWithdraw(ctx context.Context, prefix string) (*BGPWithdrawResult, error)

	// IPAM Commands (platformctl sdn ipam ...)
	IPAMPoolList(ctx context.Context) (*IPAMPoolListResult, error)
	IPAMPoolCreate(ctx context.Context, opts IPAMPoolCreateOptions) (*IPAMPoolCreateResult, error)
	IPAMPoolDelete(ctx context.Context, poolID string) (*IPAMPoolDeleteResult, error)
	IPAMAllocate(ctx context.Context, opts IPAMAllocateOptions) (*IPAMAllocateResult, error)
	IPAMRelease(ctx context.Context, ip string) (*IPAMReleaseResult, error)
	IPAMList(ctx context.Context, opts IPAMListOptions) (*IPAMListResult, error)
}

// =============================================================================
// Overlay Status Types
// =============================================================================

// OverlayStatusResult contains the overall overlay network status.
type OverlayStatusResult struct {
	NodeID          string
	VTEPIP          netip.Addr
	ControllerState string
	UnderlayMTU     int
	VXLANPort       uint16
	VNICount        int
	VTEPCount       int
	RemoteMACCount  int
	TunnelCount     int
	Uptime          time.Duration
}

// =============================================================================
// VTEP Types
// =============================================================================

// VTEPListResult contains the list of VTEPs.
type VTEPListResult struct {
	VTEPs      []VTEPInfo
	TotalCount int
}

// VTEPInfo contains information about a VTEP.
type VTEPInfo struct {
	NodeID     string
	IP         netip.Addr
	Healthy    bool
	LastSeen   time.Time
	IsLocal    bool
	TunnelPort int
}

// VTEPGetResult contains details about a specific VTEP.
type VTEPGetResult struct {
	VTEPInfo
	VNIs      []uint32
	MACCount  int
	BytesSent uint64
	BytesRecv uint64
}

// =============================================================================
// VNI Types
// =============================================================================

// VNICreateOptions contains options for creating a VNI.
type VNICreateOptions struct {
	VNI  uint32
	VLAN uint16
	Name string
}

// VNICreateResult contains the result of creating a VNI.
type VNICreateResult struct {
	VNI       uint32
	VLAN      uint16
	Name      string
	CreatedAt time.Time
}

// VNIDeleteResult contains the result of deleting a VNI.
type VNIDeleteResult struct {
	VNI     uint32
	Deleted bool
}

// VNIListResult contains the list of VNIs.
type VNIListResult struct {
	VNIs       []VNIInfo
	TotalCount int
}

// VNIInfo contains information about a VNI.
type VNIInfo struct {
	VNI        uint32
	VLAN       uint16
	Name       string
	MACCount   int
	TunnelPort string
	CreatedAt  time.Time
}

// =============================================================================
// Tunnel Types
// =============================================================================

// TunnelListOptions contains options for listing tunnels.
type TunnelListOptions struct {
	VNI uint32 // Filter by VNI (0 = all)
}

// TunnelListResult contains the list of tunnels.
type TunnelListResult struct {
	Tunnels    []TunnelInfo
	TotalCount int
}

// TunnelInfo contains information about a tunnel.
type TunnelInfo struct {
	LocalVTEP  netip.Addr
	RemoteVTEP netip.Addr
	VNI        uint32
	Port       string
	State      string
	BytesSent  uint64
	BytesRecv  uint64
}

// =============================================================================
// MAC Types
// =============================================================================

// MACListOptions contains options for listing remote MACs.
type MACListOptions struct {
	VNI uint32 // Filter by VNI (0 = all)
}

// MACListResult contains the list of remote MACs.
type MACListResult struct {
	MACs       []RemoteMACInfo
	TotalCount int
}

// RemoteMACInfo contains information about a remote MAC.
type RemoteMACInfo struct {
	MAC        net.HardwareAddr
	IP         netip.Addr
	VNI        uint32
	RemoteVTEP netip.Addr
	Source     string // "evpn", "datapath", "static"
	LearnedAt  time.Time
	ExpiresAt  time.Time
}

// MACForgetResult contains the result of forgetting a MAC.
type MACForgetResult struct {
	MAC     string
	VNI     uint32
	Deleted bool
}

// =============================================================================
// Gateway Types
// =============================================================================

// GatewayStatusResult contains gateway status information.
type GatewayStatusResult struct {
	NodeID         string
	Modes          []string // "overlay", "edge", "transit"
	Tier           string   // "backbone", "datacenter", "coordinator"
	Healthy        bool
	Reputation     float64
	Age            time.Duration
	UptimePct      float64
	IPv6Pool       string
	IPv4Pool       string
	BGPEnabled     bool
	EVPNEnabled    bool
	TransitEnabled bool
}

// GatewayModeOptions contains options for setting gateway mode.
type GatewayModeOptions struct {
	Modes []string // "overlay", "edge", "transit"
}

// GatewayModeResult contains the result of setting gateway mode.
type GatewayModeResult struct {
	Modes   []string
	Success bool
}

// =============================================================================
// BGP Types
// =============================================================================

// BGPStatusResult contains BGP status information.
type BGPStatusResult struct {
	Enabled          bool
	ASN              uint32
	RouterID         string
	State            string
	PeerCount        int
	EstablishedCount int
	EVPNEnabled      bool
	TransitEnabled   bool
}

// BGPPeersResult contains the list of BGP peers.
type BGPPeersResult struct {
	Peers      []BGPPeerInfo
	TotalCount int
}

// BGPPeerInfo contains information about a BGP peer.
type BGPPeerInfo struct {
	Address      string
	RemoteASN    uint32
	State        string
	Uptime       time.Duration
	PrefixesRecv int
	PrefixesSent int
	Description  string
}

// BGPPrefixesResult contains the list of announced prefixes.
type BGPPrefixesResult struct {
	Prefixes   []BGPPrefixInfo
	TotalCount int
}

// BGPPrefixInfo contains information about an announced prefix.
type BGPPrefixInfo struct {
	Prefix      string
	NextHop     string
	Origin      string
	ASPath      string
	LocalPref   uint32
	MED         uint32
	Communities []string
}

// BGPAnnounceOptions contains options for announcing a prefix.
type BGPAnnounceOptions struct {
	Prefix  string
	NextHop string
}

// BGPAnnounceResult contains the result of announcing a prefix.
type BGPAnnounceResult struct {
	Prefix  string
	Success bool
}

// BGPWithdrawResult contains the result of withdrawing a prefix.
type BGPWithdrawResult struct {
	Prefix  string
	Success bool
}

// =============================================================================
// IPAM Types
// =============================================================================

// IPAMPoolListResult contains the list of IPAM pools.
type IPAMPoolListResult struct {
	Pools      []IPAMPoolInfo
	TotalCount int
}

// IPAMPoolInfo contains information about an IPAM pool.
type IPAMPoolInfo struct {
	ID             string
	Name           string
	CIDR           string
	Gateway        string
	TotalIPs       int64
	AllocatedIPs   int64
	AvailableIPs   int64
	UtilizationPct float64
	DNS            []string
	LeaseDuration  time.Duration
}

// IPAMPoolCreateOptions contains options for creating an IPAM pool.
type IPAMPoolCreateOptions struct {
	Name          string
	CIDR          string
	Gateway       string
	DNS           []string
	LeaseDuration time.Duration
}

// IPAMPoolCreateResult contains the result of creating an IPAM pool.
type IPAMPoolCreateResult struct {
	ID        string
	Name      string
	CIDR      string
	CreatedAt time.Time
}

// IPAMPoolDeleteResult contains the result of deleting an IPAM pool.
type IPAMPoolDeleteResult struct {
	ID      string
	Deleted bool
}

// IPAMAllocateOptions contains options for allocating an IP.
type IPAMAllocateOptions struct {
	PoolID   string
	DeviceID string
	Hostname string
}

// IPAMAllocateResult contains the result of allocating an IP.
type IPAMAllocateResult struct {
	IP          netip.Addr
	PoolID      string
	DeviceID    string
	Hostname    string
	LeaseExpiry time.Time
}

// IPAMReleaseResult contains the result of releasing an IP.
type IPAMReleaseResult struct {
	IP       string
	Released bool
}

// IPAMListOptions contains options for listing IPAM allocations.
type IPAMListOptions struct {
	PoolID string // Filter by pool (empty = all)
}

// IPAMListResult contains the list of IPAM allocations.
type IPAMListResult struct {
	Allocations []IPAMAllocationInfo
	TotalCount  int
}

// IPAMAllocationInfo contains information about an IPAM allocation.
type IPAMAllocationInfo struct {
	IP          netip.Addr
	PoolID      string
	DeviceID    string
	Hostname    string
	Status      string
	AllocatedAt time.Time
	LeaseExpiry time.Time
	LastSeen    time.Time
}
