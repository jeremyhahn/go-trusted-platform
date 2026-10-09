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

package quic

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Gateway operation codes (using extended opcode space)
// These opcodes are defined here to avoid conflicts with existing protocol.go allocations
const (
	OpGatewayStatus          byte = 0x01 // Extended gateway opcode category marker
	OpGatewaySetMode         byte = 0x02
	OpGatewayBGPStatus       byte = 0x03
	OpGatewayBGPPeers        byte = 0x04
	OpGatewayAnnouncePrefix  byte = 0x05
	OpGatewayWithdrawPrefix  byte = 0x06
	OpGatewayListPrefixes    byte = 0x07
	OpGatewayListIPAMPools   byte = 0x08
	OpGatewayAllocateIP      byte = 0x09
	OpGatewayReleaseIP       byte = 0x0A
	OpGatewayListAllocations byte = 0x0B
	OpGatewayCreateIPAMPool  byte = 0x0C
	OpGatewayDeleteIPAMPool  byte = 0x0D
	OpGatewayGetIPAMPool     byte = 0x0E
	OpGatewayUpdateIPAMPool  byte = 0x0F

	// Telemetry snapshot operations (0x15-0x16): the whole datapath
	// picture one gatewayd reports — sessions, BFD, tunnels, uplink policy
	// routes, host filter, NAT and the base pipeline (#594).
	OpGatewaySnapshot          byte = 0x15
	OpGatewayListSnapshots     byte = 0x16
	OpGatewayAdmittedVTEP      byte = 0x17
	OpGatewayListAdmittedVTEPs byte = 0x18

	// Network Zone Operations (0x10-0x13). 0x14 was the retired
	// assign-network-to-zone operation (networks are zones since #708);
	// it is never reused.
	OpGatewayListNetworkZones  byte = 0x10
	OpGatewayCreateNetworkZone byte = 0x11
	OpGatewayUpdateNetworkZone byte = 0x12
	OpGatewayDeleteNetworkZone byte = 0x13
)

// Gateway pagination defaults
const (
	gatewayDefaultLimit int32 = 100
	gatewayMaxLimit     int32 = 1000
)

// Gateway modes
const (
	GatewayModeL2       = "l2"
	GatewayModeL3       = "l3"
	GatewayModeNAT      = "nat"
	GatewayModeDisabled = "disabled"
)

// Gateway sentinel errors
var (
	// ErrGatewayServiceNotAvailable is returned when the gateway service is not
	// configured or unavailable.
	ErrGatewayServiceNotAvailable = errors.New("gateway service not available")

	// ErrGatewayMissingMode is returned when a gateway mode is required but
	// not provided.
	ErrGatewayMissingMode = errors.New("gateway mode is required")

	// ErrGatewayInvalidMode is returned when an invalid gateway mode is specified.
	ErrGatewayInvalidMode = errors.New("invalid gateway mode: must be l2, l3, nat, or disabled")

	// ErrGatewayMissingPrefix is returned when a prefix is required but
	// not provided.
	ErrGatewayMissingPrefix = errors.New("prefix is required")

	// ErrGatewayInvalidPrefix is returned when an invalid prefix is specified.
	ErrGatewayInvalidPrefix = errors.New("invalid prefix format")

	// ErrGatewayMissingPoolID is returned when a pool ID is required but
	// not provided.
	ErrGatewayMissingPoolID = errors.New("pool ID is required")

	// ErrGatewayMissingPoolName is returned when a pool name is required but
	// not provided.
	ErrGatewayMissingPoolName = errors.New("pool name is required")

	// ErrGatewayMissingPoolCIDR is returned when a pool CIDR is required but
	// not provided.
	ErrGatewayMissingPoolCIDR = errors.New("pool CIDR is required")

	// ErrGatewayInvalidPoolCIDR is returned when an invalid pool CIDR is specified.
	ErrGatewayInvalidPoolCIDR = errors.New("invalid pool CIDR format")

	// ErrGatewayIPAMWindow is returned when a request names a reserved
	// address, or a pool's reserved prefixes or allocation range do not fit
	// its CIDR. Implementations wrap it in ErrGatewayIPAMWindowDetail.
	ErrGatewayIPAMWindow = errors.New("ipam: reserved address or invalid allocation window")

	// ErrGatewayPoolAlreadyExists is returned when attempting to create a pool
	// that already exists.
	ErrGatewayPoolAlreadyExists = errors.New("IPAM pool already exists")

	// ErrGatewayMissingIPAddress is returned when an IP address is required but
	// not provided.
	ErrGatewayMissingIPAddress = errors.New("IP address is required")

	// ErrGatewayInvalidIPAddress is returned when an invalid IP address is specified.
	ErrGatewayInvalidIPAddress = errors.New("invalid IP address format")

	// ErrGatewayPrefixNotFound is returned when a requested prefix does not exist.
	ErrGatewayPrefixNotFound = errors.New("prefix not found")

	// ErrGatewayPrefixAlreadyExists is returned when attempting to announce a prefix
	// that is already announced.
	ErrGatewayPrefixAlreadyExists = errors.New("prefix already announced")

	// ErrGatewayPoolNotFound is returned when a requested IPAM pool does not exist.
	ErrGatewayPoolNotFound = errors.New("IPAM pool not found")

	// ErrGatewayPoolExhausted is returned when an IPAM pool has no available addresses.
	ErrGatewayPoolExhausted = errors.New("IPAM pool exhausted")

	// ErrGatewayAllocationNotFound is returned when a requested allocation does not exist.
	ErrGatewayAllocationNotFound = errors.New("IP allocation not found")

	// ErrGatewayMissingOwner is returned when an allocation names no owner. The
	// owner is the device the address is allocated to -- the same identifier
	// gRPC and REST call device_id, and which they also require.
	ErrGatewayMissingOwner = errors.New("owner (the device the address is allocated to) is required")

	// ErrGatewayIPAlreadyAllocated is returned when a specific address is
	// requested that another allocation already holds.
	ErrGatewayIPAlreadyAllocated = errors.New("IP address already allocated")

	// ErrGatewayMACNotRecorded is returned when an allocation carries a MAC
	// address. IPAM records no MAC, so accepting one would drop it silently.
	ErrGatewayMACNotRecorded = errors.New("mac_address is not recorded by IPAM allocation")

	// ErrGatewayInvalidAllocationType is returned for an allocation type other
	// than "dynamic" or "static".
	ErrGatewayInvalidAllocationType = errors.New("allocation type must be dynamic or static")

	// ErrGatewayBGPNotEnabled is returned when BGP operations are attempted
	// but BGP is not enabled.
	ErrGatewayBGPNotEnabled = errors.New("BGP is not enabled")

	// ErrGatewayBGPPeerNotFound is returned when a BGP peer is not found.
	ErrGatewayBGPPeerNotFound = errors.New("BGP peer not found")

	// ErrGatewayZoneNameRequired is returned when a zone name is required.
	ErrGatewayZoneNameRequired = errors.New("zone name is required")

	// ErrGatewayZoneNotFound is returned when a zone is not found.
	ErrGatewayZoneNotFound = errors.New("zone not found")

	// ErrGatewayZoneAlreadyExists is returned when a zone already exists.
	ErrGatewayZoneAlreadyExists = errors.New("zone already exists")

	// ErrGatewayZoneInvalid is returned when a zone mutation fails zone or
	// numbering validation.
	ErrGatewayZoneInvalid = errors.New("invalid zone")

	// ErrGatewayFeatureNotConfigured is returned when a gateway feature is
	// requested but the backing service or hardware is not configured. Adapters
	// that only support a subset of the GatewayServiceInterface (e.g. zone-only
	// adapters) return this error for every unsupported method so the QUIC
	// handler correctly emits StatusUnavailable to the client.
	ErrGatewayFeatureNotConfigured = errors.New("gateway feature not configured")

	// ErrGatewayPreconditionFailed is returned when the host cannot carry
	// a configured gateway service until an operator acts on it, such as
	// a kernel without the NAT64 translator module. It is gRPC's
	// FailedPrecondition, bridged to StatusInvalidRequest as the other
	// QUIC delegates bridge it, and is never a retryable StatusUnavailable
	// or a daemon-fault StatusInternalError.
	ErrGatewayPreconditionFailed = errors.New("gateway precondition failed")
)

// GatewayServiceInterface defines the interface for gateway operations.
type GatewayServiceInterface interface {
	// Status returns the current gateway status
	Status(ctx context.Context) (*GatewayStatusInfo, error)

	// Snapshot returns one gateway's telemetry snapshot. An empty
	// gatewayID means the gateway this node runs itself.
	Snapshot(ctx context.Context, gatewayID string) (*GatewaySnapshotInfo, error)

	// ListSnapshots returns every reported gateway's telemetry snapshot.
	ListSnapshots(ctx context.Context) ([]*GatewaySnapshotInfo, error)

	// Admitted VTEP operations read the overlay decap admission set.
	GetAdmittedVTEP(ctx context.Context, gatewayID, vtep string) (*GatewayAdmittedVTEPInfo, error)
	ListAdmittedVTEPs(ctx context.Context, gatewayID string) ([]*GatewayAdmittedVTEPInfo, error)

	// Mode operations
	SetMode(ctx context.Context, mode string) error

	// BGP operations
	BGPStatus(ctx context.Context) (*BGPStatusInfo, error)
	ListBGPPeers(ctx context.Context) ([]*BGPPeerInfo, error)
	AnnouncePrefix(ctx context.Context, prefix string, opts *AnnouncePrefixOptions) error
	WithdrawPrefix(ctx context.Context, prefix string) error
	ListPrefixes(ctx context.Context) ([]*PrefixInfo, error)

	// IPAM operations
	ListIPAMPools(ctx context.Context, zone string) ([]*IPAMPoolInfo, error)
	GetIPAMPool(ctx context.Context, poolID string) (*IPAMPoolInfo, error)
	CreateIPAMPool(ctx context.Context, opts *CreateIPAMPoolOptions) (*IPAMPoolInfo, error)
	UpdateIPAMPool(ctx context.Context, poolID string, opts *UpdateIPAMPoolOptions) (*IPAMPoolInfo, error)
	DeleteIPAMPool(ctx context.Context, poolID string) error
	AllocateIP(ctx context.Context, poolID string, opts *AllocateIPOptions) (*IPAllocationInfo, error)
	ReleaseIP(ctx context.Context, poolID string, ip string) error
	ListAllocations(ctx context.Context, poolID string) ([]*IPAllocationInfo, error)

	// Network Zone operations
	ListNetworkZones(ctx context.Context, lifecycleRole string) ([]*NetworkZoneInfo, error)
	CreateNetworkZone(ctx context.Context, opts *CreateNetworkZoneOptions) (*NetworkZoneInfo, error)
	UpdateNetworkZone(ctx context.Context, name string, opts *UpdateNetworkZoneOptions) (*NetworkZoneInfo, error)
	DeleteNetworkZone(ctx context.Context, name string) (bool, error)

	// Load balancer VIP operations (sub-opcodes 0x30-0x35)
	AddVIP(ctx context.Context, spec *LBVIPSpec) (*LBVIPInfo, error)
	RemoveVIP(ctx context.Context, protocol, address string, port uint16) error
	GetVIP(ctx context.Context, protocol, address string, port uint16) (*LBVIPInfo, error)
	ListVIPs(ctx context.Context) ([]*LBVIPInfo, error)
	SetVIPBackends(ctx context.Context, protocol, address string, port uint16, backends []*LBBackendSpec) (*LBVIPInfo, error)
	LBStatus(ctx context.Context) (*LBStatusInfo, error)

	// NAT64Status returns the NAT64 translator's health snapshot.
	NAT64Status(ctx context.Context) (*NAT64StatusInfo, error)
}

// GatewayStatusInfo contains gateway status information
type GatewayStatusInfo struct {
	Enabled       bool              `codec:"enabled"`
	Mode          string            `codec:"mode"`
	BGPEnabled    bool              `codec:"bgp_enabled"`
	BGPRouterID   string            `codec:"bgp_router_id,omitempty"`
	BGPLocalAS    uint32            `codec:"bgp_local_as,omitempty"`
	ExternalIface string            `codec:"external_iface,omitempty"`
	InternalIface string            `codec:"internal_iface,omitempty"`
	NATEnabled    bool              `codec:"nat_enabled"`
	PeerCount     int               `codec:"peer_count"`
	PrefixCount   int               `codec:"prefix_count"`
	PoolCount     int               `codec:"pool_count"`
	HealthStatus  string            `codec:"health_status"`
	Uptime        int64             `codec:"uptime"`
	Metadata      map[string]string `codec:"metadata,omitempty"`
}

// GatewaySnapshotInfo is one gateway's telemetry snapshot on the wire: the
// datapath sections each service reports, carried verbatim so QUIC clients
// read the same picture as the control plane's REST consumers (#594).
type GatewaySnapshotInfo struct {
	GatewayID    string                    `codec:"gateway_id"`
	Hostname     string                    `codec:"hostname,omitempty"`
	Mode         string                    `codec:"mode,omitempty"`
	ReportedAt   int64                     `codec:"reported_at,omitempty"`
	ReceivedAt   int64                     `codec:"received_at,omitempty"`
	HealthStatus string                    `codec:"health_status,omitempty"`
	Components   map[string]string         `codec:"components,omitempty"`
	BGP          *SnapshotBGPInfo          `codec:"bgp,omitempty"`
	Services     []SnapshotServiceInfo     `codec:"services,omitempty"`
	Tunnels      []SnapshotTunnelInfo      `codec:"tunnels,omitempty"`
	Uplinks      []SnapshotUplinkInfo      `codec:"uplinks,omitempty"`
	HostFirewall *SnapshotHostFirewallInfo `codec:"host_firewall,omitempty"`
	Firewall     *SnapshotFirewallInfo     `codec:"firewall,omitempty"`
	NAT          *SnapshotNATInfo          `codec:"nat,omitempty"`
	Pipeline     *SnapshotPipelineInfo     `codec:"pipeline,omitempty"`
	Overlay      *SnapshotOverlayInfo      `codec:"overlay,omitempty"`
	Annotations  map[string]string         `codec:"annotations,omitempty"`
}

// SnapshotBGPInfo is the snapshot's BGP section.
type SnapshotBGPInfo struct {
	LocalAS          uint32                `codec:"local_as,omitempty"`
	RouterID         string                `codec:"router_id,omitempty"`
	PeerCount        int                   `codec:"peer_count"`
	EstablishedPeers int                   `codec:"established_peers"`
	ReceivedPrefixes int                   `codec:"received_prefixes"`
	Peers            []SnapshotBGPPeerInfo `codec:"peers,omitempty"`
}

// SnapshotBGPPeerInfo is one session in the snapshot's BGP section.
type SnapshotBGPPeerInfo struct {
	Address          string           `codec:"address"`
	ASN              uint32           `codec:"asn,omitempty"`
	Description      string           `codec:"description,omitempty"`
	State            string           `codec:"state"`
	UptimeSeconds    int64            `codec:"uptime_seconds,omitempty"`
	AdminDown        bool             `codec:"admin_down,omitempty"`
	PrefixesReceived int64            `codec:"prefixes_received"`
	PrefixesAccepted int64            `codec:"prefixes_accepted"`
	PrefixesSent     int64            `codec:"prefixes_sent"`
	LocalAddress     string           `codec:"local_address,omitempty"`
	RemoteRouterID   string           `codec:"remote_router_id,omitempty"`
	HoldTimeSeconds  int              `codec:"hold_time_seconds,omitempty"`
	Families         []string         `codec:"families,omitempty"`
	LastError        string           `codec:"last_error,omitempty"`
	BFD              *SnapshotBFDInfo `codec:"bfd,omitempty"`
}

// SnapshotBFDInfo is one neighbour's BFD session.
type SnapshotBFDInfo struct {
	State               string `codec:"state"`
	RemoteState         string `codec:"remote_state,omitempty"`
	FailureTransitions  uint64 `codec:"failure_transitions,omitempty"`
	LastFailure         int64  `codec:"last_failure,omitempty"`
	Diagnostic          string `codec:"diagnostic,omitempty"`
	RemoteDiagnostic    string `codec:"remote_diagnostic,omitempty"`
	TxIntervalMS        int64  `codec:"tx_interval_ms,omitempty"`
	RxIntervalMS        int64  `codec:"rx_interval_ms,omitempty"`
	DetectionMultiplier uint8  `codec:"detection_multiplier,omitempty"`
}

// SnapshotServiceInfo is one configured service's disposition.
type SnapshotServiceInfo struct {
	Name          string `codec:"name"`
	Active        bool   `codec:"active"`
	Healthy       bool   `codec:"healthy"`
	RefusedReason string `codec:"refused_reason,omitempty"`
}

// SnapshotTunnelInfo is one managed tunnel.
type SnapshotTunnelInfo struct {
	Name         string `codec:"name"`
	Transport    string `codec:"transport,omitempty"`
	Type         string `codec:"type,omitempty"`
	State        string `codec:"state"`
	Uplink       string `codec:"uplink,omitempty"`
	Bound        bool   `codec:"bound,omitempty"`
	LocalIP      string `codec:"local_ip,omitempty"`
	RemoteIP     string `codec:"remote_ip,omitempty"`
	TunnelIP     string `codec:"tunnel_ip,omitempty"`
	RxBytes      uint64 `codec:"rx_bytes,omitempty"`
	TxBytes      uint64 `codec:"tx_bytes,omitempty"`
	RxPackets    uint64 `codec:"rx_packets,omitempty"`
	TxPackets    uint64 `codec:"tx_packets,omitempty"`
	RekeySeconds int64  `codec:"rekey_seconds,omitempty"`
	LastRekey    int64  `codec:"last_rekey,omitempty"`
}

// SnapshotUplinkInfo is one uplink's policy-routing state.
type SnapshotUplinkInfo struct {
	Name      string   `codec:"name"`
	Interface string   `codec:"interface,omitempty"`
	Table     int      `codec:"table"`
	GatewayV4 string   `codec:"gateway_v4,omitempty"`
	GatewayV6 string   `codec:"gateway_v6,omitempty"`
	Addresses []string `codec:"addresses,omitempty"`
	Priority  int      `codec:"priority,omitempty"`
	RuleCount int      `codec:"rule_count"`
	Tunnels   []string `codec:"tunnels,omitempty"`
}

// SnapshotHostFirewallInfo is the nftables host filter's state.
type SnapshotHostFirewallInfo struct {
	Active        bool   `codec:"active"`
	Installed     bool   `codec:"installed"`
	Fingerprint   string `codec:"fingerprint,omitempty"`
	RuleCount     int    `codec:"rule_count"`
	LastReconcile int64  `codec:"last_reconcile,omitempty"`
	LastError     string `codec:"last_error,omitempty"`
}

// SnapshotFirewallInfo is the OVS conntrack firewall's state.
type SnapshotFirewallInfo struct {
	Active        bool              `codec:"active"`
	FlowCount     int               `codec:"flow_count"`
	LastReconcile int64             `codec:"last_reconcile,omitempty"`
	CTZones       map[string]uint16 `codec:"ct_zones,omitempty"`
}

// SnapshotNATInfo is the NAT service's state.
type SnapshotNATInfo struct {
	Active      bool                    `codec:"active"`
	SNATEnabled bool                    `codec:"snat_enabled"`
	DNATRules   int                     `codec:"dnat_rules"`
	CTZone      uint16                  `codec:"ct_zone,omitempty"`
	Uplinks     []SnapshotNATUplinkInfo `codec:"uplinks,omitempty"`
}

// SnapshotNATUplinkInfo is one uplink's translation resources.
type SnapshotNATUplinkInfo struct {
	Name          string `codec:"name"`
	Default       bool   `codec:"default,omitempty"`
	PoolAddresses int    `codec:"pool_addresses"`
	Ports         int    `codec:"ports"`
	Static        int    `codec:"static"`
}

// SnapshotPipelineInfo is the base OVS pipeline the gateway holds.
type SnapshotPipelineInfo struct {
	Installed bool   `codec:"installed"`
	Bridge    string `codec:"bridge,omitempty"`
	Owner     string `codec:"owner,omitempty"`
	Terminal  string `codec:"terminal,omitempty"`
	FailMode  string `codec:"fail_mode,omitempty"`
}

// SnapshotOverlayInfo describes the EVPN overlay service of a gateway snapshot.
type SnapshotOverlayInfo struct {
	Running                  bool                         `codec:"running"`
	LocalVTEP                string                       `codec:"local_vtep,omitempty"`
	VNICount                 uint32                       `codec:"vni_count,omitempty"`
	RemoteVTEPCount          uint32                       `codec:"remote_vtep_count,omitempty"`
	LocalMACCount            uint32                       `codec:"local_mac_count,omitempty"`
	RemoteMACCount           uint32                       `codec:"remote_mac_count,omitempty"`
	PrefixCount              uint32                       `codec:"prefix_count,omitempty"`
	RefusedBindings          uint64                       `codec:"refused_bindings,omitempty"`
	L3VNI                    uint32                       `codec:"l3_vni,omitempty"`
	ARPSuppressionEnabled    bool                         `codec:"arp_suppression_enabled,omitempty"`
	AnycastGatewayConfigured bool                         `codec:"anycast_gateway_configured,omitempty"`
	StartedAt                int64                        `codec:"started_at,omitempty"`
	UptimeSeconds            int64                        `codec:"uptime_seconds,omitempty"`
	AdmittedVTEPs            []GatewayAdmittedVTEPInfo    `codec:"admitted_vteps,omitempty"`
	NDCounters               SnapshotOverlayNDCounterInfo `codec:"nd_counters"`
}

// SnapshotOverlayNDCounterInfo counts the overlay's neighbor discovery punts
// and what became of them.
type SnapshotOverlayNDCounterInfo struct {
	Punted       uint64 `codec:"punted"`
	Answered     uint64 `codec:"answered"`
	MeterDropped uint64 `codec:"meter_dropped"`
	QueueDropped uint64 `codec:"queue_dropped"`
	FellThrough  uint64 `codec:"fell_through"`
}

// GatewayAdmittedVTEPInfo is a remote VTEP the gateway admitted to the overlay,
// with the device and attestation verdict that admitted it.
type GatewayAdmittedVTEPInfo struct {
	VTEP           string `codec:"vtep"`
	DeviceID       uint64 `codec:"device_id,omitempty"`
	HostID         string `codec:"host_id,omitempty"`
	Serial         string `codec:"serial,omitempty"`
	Hostname       string `codec:"hostname,omitempty"`
	AllocationID   string `codec:"allocation_id,omitempty"`
	BaselineSource string `codec:"baseline_source,omitempty"`
	ProfileID      uint64 `codec:"profile_id,omitempty"`
	VerdictAt      int64  `codec:"verdict_at,omitempty"`
}

// BGPStatusInfo contains BGP status information
type BGPStatusInfo struct {
	Enabled           bool   `codec:"enabled"`
	RouterID          string `codec:"router_id"`
	LocalAS           uint32 `codec:"local_as"`
	HoldTime          int    `codec:"hold_time"`
	KeepaliveInterval int    `codec:"keepalive_interval"`
	PeerCount         int    `codec:"peer_count"`
	EstablishedCount  int    `codec:"established_count"`
	PrefixesReceived  int    `codec:"prefixes_received"`
	PrefixesSent      int    `codec:"prefixes_sent"`
	Uptime            int64  `codec:"uptime"`
	LastError         string `codec:"last_error,omitempty"`
}

// BGPPeerInfo contains BGP peer information
type BGPPeerInfo struct {
	Address          string   `codec:"address"`
	RemoteAS         uint32   `codec:"remote_as"`
	LocalAS          uint32   `codec:"local_as"`
	State            string   `codec:"state"`
	Description      string   `codec:"description,omitempty"`
	HoldTime         int      `codec:"hold_time"`
	KeepaliveTime    int      `codec:"keepalive_time"`
	PrefixesReceived int      `codec:"prefixes_received"`
	PrefixesSent     int      `codec:"prefixes_sent"`
	Uptime           int64    `codec:"uptime"`
	LastError        string   `codec:"last_error,omitempty"`
	Capabilities     []string `codec:"capabilities,omitempty"`
	RouteReflector   bool     `codec:"route_reflector"`
}

// PrefixInfo contains announced prefix information
type PrefixInfo struct {
	Prefix      string            `codec:"prefix"`
	NextHop     string            `codec:"next_hop,omitempty"`
	Origin      string            `codec:"origin"`
	ASPath      []uint32          `codec:"as_path,omitempty"`
	LocalPref   uint32            `codec:"local_pref,omitempty"`
	MED         uint32            `codec:"med,omitempty"`
	Communities []string          `codec:"communities,omitempty"`
	Status      string            `codec:"status"`
	AnnouncedAt int64             `codec:"announced_at"`
	Labels      map[string]string `codec:"labels,omitempty"`
}

// AnnouncePrefixOptions contains options for announcing a prefix
type AnnouncePrefixOptions struct {
	NextHop     string            `codec:"next_hop,omitempty"`
	LocalPref   uint32            `codec:"local_pref,omitempty"`
	MED         uint32            `codec:"med,omitempty"`
	Communities []string          `codec:"communities,omitempty"`
	Labels      map[string]string `codec:"labels,omitempty"`
}

// IPAMPoolInfo contains IPAM pool information
type IPAMPoolInfo struct {
	ID            string            `codec:"id"`
	Name          string            `codec:"name"`
	CIDR          string            `codec:"cidr"`
	Gateway       string            `codec:"gateway,omitempty"`
	Zone          string            `codec:"zone,omitempty"`
	Description   string            `codec:"description,omitempty"`
	TotalIPs      int               `codec:"total_ips"`
	AllocatedIPs  int               `codec:"allocated_ips"`
	AvailableIPs  int               `codec:"available_ips"`
	ReservedIPs   int               `codec:"reserved_ips"`
	Type          string            `codec:"type"` // static, dynamic, dhcp
	VNI           uint32            `codec:"vni,omitempty"`
	TenantID      string            `codec:"tenant_id,omitempty"`
	Labels        map[string]string `codec:"labels,omitempty"`
	CreatedAt     int64             `codec:"created_at"`
	LastAllocated int64             `codec:"last_allocated,omitempty"`
	// Reserved lists never-allocatable prefixes (CIDR notation); the
	// gateway is always reserved as well.
	Reserved []string `codec:"reserved,omitempty"`
	// RangeStart and RangeEnd bound dynamic allocation; empty means the
	// whole CIDR.
	RangeStart string `codec:"range_start,omitempty"`
	RangeEnd   string `codec:"range_end,omitempty"`
}

// IPAllocationInfo contains IP allocation information
type IPAllocationInfo struct {
	ID         string            `codec:"id"`
	PoolID     string            `codec:"pool_id"`
	IPAddress  string            `codec:"ip_address"`
	MACAddress string            `codec:"mac_address,omitempty"`
	Hostname   string            `codec:"hostname,omitempty"`
	Owner      string            `codec:"owner,omitempty"`
	Type       string            `codec:"type"` // static, dynamic
	Status     string            `codec:"status"`
	ExpiresAt  int64             `codec:"expires_at,omitempty"`
	Labels     map[string]string `codec:"labels,omitempty"`
	CreatedAt  int64             `codec:"created_at"`
	UpdatedAt  int64             `codec:"updated_at"`
}

// AllocateIPOptions contains options for allocating an IP address
type AllocateIPOptions struct {
	IPAddress  string            `codec:"ip_address,omitempty"` // Request specific IP
	MACAddress string            `codec:"mac_address,omitempty"`
	Hostname   string            `codec:"hostname,omitempty"`
	Owner      string            `codec:"owner,omitempty"`
	Type       string            `codec:"type,omitempty"` // static, dynamic
	TTL        int64             `codec:"ttl,omitempty"`  // Lease duration in seconds
	Labels     map[string]string `codec:"labels,omitempty"`
}

// CreateIPAMPoolOptions contains options for creating an IPAM pool
type CreateIPAMPoolOptions struct {
	ID            string `codec:"id,omitempty"`
	Name          string `codec:"name"`
	CIDR          string `codec:"cidr"`
	Gateway       string `codec:"gateway,omitempty"`
	Zone          string `codec:"zone,omitempty"`
	Description   string `codec:"description,omitempty"`
	LeaseDuration int64  `codec:"lease_duration_nanos,omitempty"`
	// Reserved lists never-allocatable prefixes (CIDR notation).
	Reserved []string `codec:"reserved,omitempty"`
	// RangeStart and RangeEnd bound dynamic allocation; set both or neither.
	RangeStart string `codec:"range_start,omitempty"`
	RangeEnd   string `codec:"range_end,omitempty"`
}

// UpdateIPAMPoolOptions contains options for updating an IPAM pool.
// CIDR is immutable and must not be specified.
type UpdateIPAMPoolOptions struct {
	Name          string `codec:"name,omitempty"`
	Gateway       string `codec:"gateway,omitempty"`
	Zone          string `codec:"zone,omitempty"`
	Description   string `codec:"description,omitempty"`
	LeaseDuration int64  `codec:"lease_duration_nanos,omitempty"`
	// UpdateWindow, when true, makes Reserved, RangeStart and RangeEnd
	// replace the pool's allocation window (empty values clear it).
	UpdateWindow bool     `codec:"update_window,omitempty"`
	Reserved     []string `codec:"reserved,omitempty"`
	RangeStart   string   `codec:"range_start,omitempty"`
	RangeEnd     string   `codec:"range_end,omitempty"`
}

// NetworkZonePathInfo is a directed path from a zone to another zone with
// an optional service allowlist (empty means all services).
type NetworkZonePathInfo struct {
	Zone     string   `codec:"zone"`
	Services []string `codec:"services,omitempty"`
}

// NetworkZonePrivilegedAccessInfo is the audited override a zone carries
// when it opens a path into control-plane or management beyond the
// reference defaults.
type NetworkZonePrivilegedAccessInfo struct {
	Reason     string `codec:"reason"`
	ApprovedBy string `codec:"approved_by"`
}

// NetworkZoneNumberingInfo is a zone's numbering derived by the network
// plan from the node's environment.
type NetworkZoneNumberingInfo struct {
	VLAN    uint16 `codec:"vlan"`
	Subnet4 string `codec:"subnet4"`
	Subnet6 string `codec:"subnet6,omitempty"`
	Gateway string `codec:"gateway"`
}

// NetworkZoneInfo contains network zone information: the resolved zone
// (pkg/sdn/zone.ZoneConfig) and, when the node has an environment, its
// derived numbering.
type NetworkZoneInfo struct {
	Name             string                           `codec:"name"`
	Offset           uint8                            `codec:"offset,omitempty"`
	PortClasses      []string                         `codec:"port_classes,omitempty"`
	InternetIngress  bool                             `codec:"internet_ingress,omitempty"`
	IsolateFrom      []string                         `codec:"isolate_from,omitempty"`
	AllowTo          []NetworkZonePathInfo            `codec:"allow_to,omitempty"`
	Services         []string                         `codec:"services,omitempty"`
	Isolate          bool                             `codec:"isolate,omitempty"`
	OOB              bool                             `codec:"oob,omitempty"`
	LifecycleRole    string                           `codec:"lifecycle_role,omitempty"`
	PrivilegedAccess *NetworkZonePrivilegedAccessInfo `codec:"privileged_access,omitempty"`
	Numbering        *NetworkZoneNumberingInfo        `codec:"numbering,omitempty"`
	RestartRequired  bool                             `codec:"restart_required,omitempty"`
	CreatedAt        int64                            `codec:"created_at"`
	UpdatedAt        int64                            `codec:"updated_at"`
}

// CreateNetworkZoneOptions contains options for creating an owner-defined
// network zone.
type CreateNetworkZoneOptions struct {
	Name             string                           `codec:"name"`
	Offset           uint8                            `codec:"offset,omitempty"`
	PortClasses      []string                         `codec:"port_classes,omitempty"`
	InternetIngress  bool                             `codec:"internet_ingress,omitempty"`
	IsolateFrom      []string                         `codec:"isolate_from,omitempty"`
	AllowTo          []NetworkZonePathInfo            `codec:"allow_to,omitempty"`
	Services         []string                         `codec:"services,omitempty"`
	Isolate          bool                             `codec:"isolate,omitempty"`
	OOB              bool                             `codec:"oob,omitempty"`
	LifecycleRole    string                           `codec:"lifecycle_role,omitempty"`
	PrivilegedAccess *NetworkZonePrivilegedAccessInfo `codec:"privileged_access,omitempty"`
}

// UpdateNetworkZoneOptions contains options for updating a network zone:
// tuning a built-in zone's policy or replacing an owner-defined zone.
type UpdateNetworkZoneOptions struct {
	Offset           uint8                            `codec:"offset,omitempty"`
	PortClasses      []string                         `codec:"port_classes,omitempty"`
	InternetIngress  bool                             `codec:"internet_ingress,omitempty"`
	IsolateFrom      []string                         `codec:"isolate_from,omitempty"`
	AllowTo          []NetworkZonePathInfo            `codec:"allow_to,omitempty"`
	Services         []string                         `codec:"services,omitempty"`
	Isolate          bool                             `codec:"isolate,omitempty"`
	OOB              bool                             `codec:"oob,omitempty"`
	LifecycleRole    string                           `codec:"lifecycle_role,omitempty"`
	PrivilegedAccess *NetworkZonePrivilegedAccessInfo `codec:"privileged_access,omitempty"`
}

// GatewayListNetworkZonesRequest represents a zone list request.
type GatewayListNetworkZonesRequest struct {
	LifecycleRole string `codec:"lifecycle_role,omitempty"`
}

// GatewayListNetworkZonesResponse represents a zone list response.
type GatewayListNetworkZonesResponse struct {
	Zones     []*NetworkZoneInfo `codec:"zones"`
	Timestamp int64              `codec:"timestamp"`
}

// GatewayCreateNetworkZoneRequest represents a zone create request.
type GatewayCreateNetworkZoneRequest struct {
	Opts *CreateNetworkZoneOptions `codec:"opts"`
}

// GatewayCreateNetworkZoneResponse represents a zone create response.
type GatewayCreateNetworkZoneResponse struct {
	Zone *NetworkZoneInfo `codec:"zone"`
}

// GatewayUpdateNetworkZoneRequest represents a zone update request.
type GatewayUpdateNetworkZoneRequest struct {
	Name string                    `codec:"name"`
	Opts *UpdateNetworkZoneOptions `codec:"opts"`
}

// GatewayUpdateNetworkZoneResponse represents a zone update response.
type GatewayUpdateNetworkZoneResponse struct {
	Zone *NetworkZoneInfo `codec:"zone"`
}

// GatewayDeleteNetworkZoneRequest represents a zone delete request.
type GatewayDeleteNetworkZoneRequest struct {
	Name string `codec:"name"`
}

// GatewayDeleteNetworkZoneResponse represents a zone delete response.
type GatewayDeleteNetworkZoneResponse struct {
	RestartRequired bool  `codec:"restart_required"`
	Timestamp       int64 `codec:"timestamp"`
}

// GatewayHandler handles gateway operations over QUIC
type GatewayHandler struct {
	gatewayService GatewayServiceInterface
	perfService    GatewayPerfServiceInterface
	logger         *logging.Logger
}

// NewGatewayHandler creates a new gateway handler
func NewGatewayHandler(logger *logging.Logger, gatewayService GatewayServiceInterface) *GatewayHandler {
	return &GatewayHandler{
		gatewayService: gatewayService,
		logger:         logger,
	}
}

// HandleRequest processes a gateway request and returns a response.
// This handler expects extended opcodes with the gateway category marker.
func (h *GatewayHandler) HandleRequest(ctx context.Context, req *Request) *Response {
	if req == nil {
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte(ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	case OpGatewayStatus:
		return h.handleStatus(ctx, req)
	case OpGatewaySetMode:
		return h.handleSetMode(ctx, req)
	case OpGatewaySnapshot:
		return h.handleSnapshot(ctx, req)
	case OpGatewayListSnapshots:
		return h.handleListSnapshots(ctx, req)
	case OpGatewayAdmittedVTEP:
		return h.handleAdmittedVTEP(ctx, req)
	case OpGatewayListAdmittedVTEPs:
		return h.handleListAdmittedVTEPs(ctx, req)
	case OpGatewayBGPStatus:
		return h.handleBGPStatus(ctx, req)
	case OpGatewayBGPPeers:
		return h.handleBGPPeers(ctx, req)
	case OpGatewayAnnouncePrefix:
		return h.handleAnnouncePrefix(ctx, req)
	case OpGatewayWithdrawPrefix:
		return h.handleWithdrawPrefix(ctx, req)
	case OpGatewayListPrefixes:
		return h.handleListPrefixes(ctx, req)
	case OpGatewayListIPAMPools:
		return h.handleListIPAMPools(ctx, req)
	case OpGatewayAllocateIP:
		return h.handleAllocateIP(ctx, req)
	case OpGatewayReleaseIP:
		return h.handleReleaseIP(ctx, req)
	case OpGatewayListAllocations:
		return h.handleListAllocations(ctx, req)
	case OpGatewayCreateIPAMPool:
		return h.handleCreateIPAMPool(ctx, req)
	case OpGatewayDeleteIPAMPool:
		return h.handleDeleteIPAMPool(ctx, req)
	case OpGatewayGetIPAMPool:
		return h.handleGetIPAMPool(ctx, req)
	case OpGatewayUpdateIPAMPool:
		return h.handleUpdateIPAMPool(ctx, req)

	// Network Zone operations
	case OpGatewayListNetworkZones:
		return h.handleListNetworkZones(ctx, req)
	case OpGatewayCreateNetworkZone:
		return h.handleCreateNetworkZone(ctx, req)
	case OpGatewayUpdateNetworkZone:
		return h.handleUpdateNetworkZone(ctx, req)
	case OpGatewayDeleteNetworkZone:
		return h.handleDeleteNetworkZone(ctx, req)

	default:
		// Load balancer sub-opcodes (0x30-0x35) dispatch via map lookup.
		if handler, ok := gatewayLBHandlers[req.Opcode]; ok {
			return handler(h, ctx, req)
		}
		// Perf sub-opcodes (0x36-0x38) dispatch via map lookup.
		if handler, ok := gatewayPerfHandlers[req.Opcode]; ok {
			return handler(h, ctx, req)
		}
		// NAT64 sub-opcodes (0x39) dispatch via map lookup.
		if handler, ok := gatewayNAT64Handlers[req.Opcode]; ok {
			return handler(h, ctx, req)
		}
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte("unknown gateway operation"),
		}
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// GatewayStatusRequest represents a status request
type GatewayStatusRequest struct{}

// GatewayStatusResponse represents a status response
type GatewayStatusResponse struct {
	Status    *GatewayStatusInfo `codec:"status"`
	Timestamp int64              `codec:"timestamp"`
}

// GatewaySnapshotRequest asks for one gateway's telemetry snapshot; an
// empty GatewayID means the gateway this node runs itself.
type GatewaySnapshotRequest struct {
	GatewayID string `codec:"gateway_id,omitempty"`
}

// GatewaySnapshotResponse carries one telemetry snapshot.
type GatewaySnapshotResponse struct {
	Snapshot  *GatewaySnapshotInfo `codec:"snapshot"`
	Timestamp int64                `codec:"timestamp"`
}

// GatewayListSnapshotsResponse carries every reported gateway's snapshot.
type GatewayListSnapshotsResponse struct {
	Snapshots []*GatewaySnapshotInfo `codec:"snapshots"`
	Count     int32                  `codec:"count"`
	Timestamp int64                  `codec:"timestamp"`
}

// GatewayAdmittedVTEPRequest asks for one admitted VTEP by address.
type GatewayAdmittedVTEPRequest struct {
	GatewayID string `codec:"gateway_id,omitempty"`
	VTEP      string `codec:"vtep"`
}

// GatewayAdmittedVTEPResponse carries one admitted VTEP.
type GatewayAdmittedVTEPResponse struct {
	VTEP      *GatewayAdmittedVTEPInfo `codec:"vtep"`
	Timestamp int64                    `codec:"timestamp"`
}

// GatewayListAdmittedVTEPsRequest asks for every VTEP a gateway admitted.
type GatewayListAdmittedVTEPsRequest struct {
	GatewayID string `codec:"gateway_id,omitempty"`
}

// GatewayListAdmittedVTEPsResponse carries every VTEP a gateway admitted.
type GatewayListAdmittedVTEPsResponse struct {
	VTEPs     []*GatewayAdmittedVTEPInfo `codec:"vteps"`
	Count     int32                      `codec:"count"`
	Timestamp int64                      `codec:"timestamp"`
}

// GatewaySetModeRequest represents a mode set request
type GatewaySetModeRequest struct {
	Mode string `codec:"mode"`
}

// GatewaySetModeResponse represents a mode set response
type GatewaySetModeResponse struct {
	Mode      string `codec:"mode"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// GatewayBGPStatusRequest represents a BGP status request
type GatewayBGPStatusRequest struct{}

// GatewayBGPStatusResponse represents a BGP status response
type GatewayBGPStatusResponse struct {
	Status    *BGPStatusInfo `codec:"status"`
	Timestamp int64          `codec:"timestamp"`
}

// GatewayBGPPeersRequest represents a BGP peers list request
type GatewayBGPPeersRequest struct {
	Limit int32 `codec:"limit,omitempty"`
}

// GatewayBGPPeersResponse represents a BGP peers list response
type GatewayBGPPeersResponse struct {
	Peers     []*BGPPeerInfo `codec:"peers"`
	Count     int32          `codec:"count"`
	Timestamp int64          `codec:"timestamp"`
}

// GatewayAnnouncePrefixRequest represents a prefix announce request
type GatewayAnnouncePrefixRequest struct {
	Prefix      string            `codec:"prefix"`
	NextHop     string            `codec:"next_hop,omitempty"`
	LocalPref   uint32            `codec:"local_pref,omitempty"`
	MED         uint32            `codec:"med,omitempty"`
	Communities []string          `codec:"communities,omitempty"`
	Labels      map[string]string `codec:"labels,omitempty"`
}

// GatewayAnnouncePrefixResponse represents a prefix announce response
type GatewayAnnouncePrefixResponse struct {
	Prefix    string `codec:"prefix"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// GatewayWithdrawPrefixRequest represents a prefix withdraw request
type GatewayWithdrawPrefixRequest struct {
	Prefix string `codec:"prefix"`
}

// GatewayWithdrawPrefixResponse represents a prefix withdraw response
type GatewayWithdrawPrefixResponse struct {
	Prefix    string `codec:"prefix"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// GatewayListPrefixesRequest represents a prefixes list request
type GatewayListPrefixesRequest struct {
	Limit int32 `codec:"limit,omitempty"`
}

// GatewayListPrefixesResponse represents a prefixes list response
type GatewayListPrefixesResponse struct {
	Prefixes  []*PrefixInfo `codec:"prefixes"`
	Count     int32         `codec:"count"`
	Timestamp int64         `codec:"timestamp"`
}

// GatewayListIPAMPoolsRequest represents an IPAM pools list request
type GatewayListIPAMPoolsRequest struct {
	// Zone filters pools by trust/exposure zone; empty returns all pools.
	Zone  string `codec:"zone,omitempty"`
	Limit int32  `codec:"limit,omitempty"`
}

// GatewayGetIPAMPoolRequest represents an IPAM pool get request
type GatewayGetIPAMPoolRequest struct {
	PoolID string `codec:"pool_id"`
}

// GatewayGetIPAMPoolResponse represents an IPAM pool get response
type GatewayGetIPAMPoolResponse struct {
	Pool      *IPAMPoolInfo `codec:"pool"`
	Timestamp int64         `codec:"timestamp"`
}

// GatewayUpdateIPAMPoolRequest represents an IPAM pool update request
type GatewayUpdateIPAMPoolRequest struct {
	PoolID        string `codec:"pool_id"`
	Name          string `codec:"name,omitempty"`
	Gateway       string `codec:"gateway,omitempty"`
	Zone          string `codec:"zone,omitempty"`
	Description   string `codec:"description,omitempty"`
	LeaseDuration int64  `codec:"lease_duration_nanos,omitempty"`
	// UpdateWindow, when true, makes Reserved, RangeStart and RangeEnd
	// replace the pool's allocation window (empty values clear it).
	UpdateWindow bool     `codec:"update_window,omitempty"`
	Reserved     []string `codec:"reserved,omitempty"`
	RangeStart   string   `codec:"range_start,omitempty"`
	RangeEnd     string   `codec:"range_end,omitempty"`
}

// GatewayUpdateIPAMPoolResponse represents an IPAM pool update response
type GatewayUpdateIPAMPoolResponse struct {
	Pool      *IPAMPoolInfo `codec:"pool"`
	Timestamp int64         `codec:"timestamp"`
}

// GatewayListIPAMPoolsResponse represents an IPAM pools list response
type GatewayListIPAMPoolsResponse struct {
	Pools     []*IPAMPoolInfo `codec:"pools"`
	Count     int32           `codec:"count"`
	Timestamp int64           `codec:"timestamp"`
}

// GatewayCreateIPAMPoolRequest represents an IPAM pool create request
type GatewayCreateIPAMPoolRequest struct {
	ID            string `codec:"id,omitempty"`
	Name          string `codec:"name"`
	CIDR          string `codec:"cidr"`
	Gateway       string `codec:"gateway,omitempty"`
	Zone          string `codec:"zone,omitempty"`
	Description   string `codec:"description,omitempty"`
	LeaseDuration int64  `codec:"lease_duration_nanos,omitempty"`
	// Reserved lists never-allocatable prefixes (CIDR notation).
	Reserved []string `codec:"reserved,omitempty"`
	// RangeStart and RangeEnd bound dynamic allocation; set both or neither.
	RangeStart string `codec:"range_start,omitempty"`
	RangeEnd   string `codec:"range_end,omitempty"`
}

// GatewayCreateIPAMPoolResponse represents an IPAM pool create response
type GatewayCreateIPAMPoolResponse struct {
	Pool      *IPAMPoolInfo `codec:"pool"`
	Timestamp int64         `codec:"timestamp"`
}

// GatewayDeleteIPAMPoolRequest represents an IPAM pool delete request
type GatewayDeleteIPAMPoolRequest struct {
	PoolID string `codec:"pool_id"`
}

// GatewayDeleteIPAMPoolResponse represents an IPAM pool delete response
type GatewayDeleteIPAMPoolResponse struct {
	PoolID    string `codec:"pool_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// GatewayAllocateIPRequest represents an IP allocation request
type GatewayAllocateIPRequest struct {
	PoolID     string            `codec:"pool_id"`
	IPAddress  string            `codec:"ip_address,omitempty"`
	MACAddress string            `codec:"mac_address,omitempty"`
	Hostname   string            `codec:"hostname,omitempty"`
	Owner      string            `codec:"owner,omitempty"`
	Type       string            `codec:"type,omitempty"`
	TTL        int64             `codec:"ttl,omitempty"`
	Labels     map[string]string `codec:"labels,omitempty"`
}

// GatewayAllocateIPResponse represents an IP allocation response
type GatewayAllocateIPResponse struct {
	Allocation *IPAllocationInfo `codec:"allocation"`
	Timestamp  int64             `codec:"timestamp"`
}

// GatewayReleaseIPRequest represents an IP release request. PoolID is
// optional; when set, the address must belong to that pool.
type GatewayReleaseIPRequest struct {
	PoolID    string `codec:"pool_id,omitempty"`
	IPAddress string `codec:"ip_address"`
}

// GatewayReleaseIPResponse represents an IP release response
type GatewayReleaseIPResponse struct {
	PoolID    string `codec:"pool_id"`
	IPAddress string `codec:"ip_address"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// GatewayListAllocationsRequest represents an allocations list request
type GatewayListAllocationsRequest struct {
	PoolID string `codec:"pool_id"`
	Limit  int32  `codec:"limit,omitempty"`
}

// GatewayListAllocationsResponse represents an allocations list response
type GatewayListAllocationsResponse struct {
	Allocations []*IPAllocationInfo `codec:"allocations"`
	Count       int32               `codec:"count"`
	Timestamp   int64               `codec:"timestamp"`
}

// =============================================================================
// Handler Methods
// =============================================================================

// handleStatus returns the gateway status
func (h *GatewayHandler) handleStatus(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	status, err := h.gatewayService.Status(ctx)
	if err != nil {
		h.logger.Error(err, "failed to get gateway status")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayStatusResponse{
		Status:    status,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleSnapshot returns one gateway's telemetry snapshot.
func (h *GatewayHandler) handleSnapshot(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var snapReq GatewaySnapshotRequest
	if err := DecodePayload(req.Payload, &snapReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	snapshot, err := h.gatewayService.Snapshot(ctx, snapReq.GatewayID)
	if err != nil {
		h.logger.Error(err, "failed to get the gateway snapshot")
		return h.gatewayErrorResponse(err)
	}

	payload, err := EncodePayload(&GatewaySnapshotResponse{Snapshot: snapshot, Timestamp: time.Now().Unix()})
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &Response{Status: StatusOK, Payload: payload}
}

// handleListSnapshots returns every reported gateway's telemetry snapshot.
func (h *GatewayHandler) handleListSnapshots(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	snapshots, err := h.gatewayService.ListSnapshots(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list gateway snapshots")
		return h.gatewayErrorResponse(err)
	}

	payload, err := EncodePayload(&GatewayListSnapshotsResponse{
		Snapshots: snapshots,
		Count:     int32(len(snapshots)),
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &Response{Status: StatusOK, Payload: payload}
}

func (h *GatewayHandler) handleAdmittedVTEP(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var vtepReq GatewayAdmittedVTEPRequest
	if err := DecodePayload(req.Payload, &vtepReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}
	if vtepReq.VTEP == "" {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayMissingIPAddress)
	}

	vtep, err := h.gatewayService.GetAdmittedVTEP(ctx, vtepReq.GatewayID, vtepReq.VTEP)
	if err != nil {
		h.logger.Error(err, "failed to get gateway admitted VTEP")
		return h.gatewayErrorResponse(err)
	}
	payload, err := EncodePayload(&GatewayAdmittedVTEPResponse{VTEP: vtep, Timestamp: time.Now().Unix()})
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &Response{Status: StatusOK, Payload: payload}
}

func (h *GatewayHandler) handleListAdmittedVTEPs(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var listReq GatewayListAdmittedVTEPsRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	vteps, err := h.gatewayService.ListAdmittedVTEPs(ctx, listReq.GatewayID)
	if err != nil {
		h.logger.Error(err, "failed to list gateway admitted VTEPs")
		return h.gatewayErrorResponse(err)
	}
	payload, err := EncodePayload(&GatewayListAdmittedVTEPsResponse{VTEPs: vteps, Count: int32(len(vteps)), Timestamp: time.Now().Unix()})
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &Response{Status: StatusOK, Payload: payload}
}

// handleSetMode sets the gateway mode
func (h *GatewayHandler) handleSetMode(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var setReq GatewaySetModeRequest
	if err := DecodePayload(req.Payload, &setReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	if setReq.Mode == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayMissingMode)
	}

	// Validate mode
	switch setReq.Mode {
	case GatewayModeL2, GatewayModeL3, GatewayModeNAT, GatewayModeDisabled:
		// Valid mode
	default:
		return h.errorResponse(StatusInvalidArgument, ErrGatewayInvalidMode)
	}

	if err := h.gatewayService.SetMode(ctx, setReq.Mode); err != nil {
		h.logger.Error(err, "failed to set gateway mode")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewaySetModeResponse{
		Mode:      setReq.Mode,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleBGPStatus returns the BGP status
func (h *GatewayHandler) handleBGPStatus(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	status, err := h.gatewayService.BGPStatus(ctx)
	if err != nil {
		h.logger.Error(err, "failed to get BGP status")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayBGPStatusResponse{
		Status:    status,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleBGPPeers lists BGP peers
func (h *GatewayHandler) handleBGPPeers(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var listReq GatewayBGPPeersRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	peers, err := h.gatewayService.ListBGPPeers(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list BGP peers")
		return h.gatewayErrorResponse(err)
	}

	// Apply limit
	limit := listReq.Limit
	if limit <= 0 {
		limit = gatewayDefaultLimit
	} else if limit > gatewayMaxLimit {
		limit = gatewayMaxLimit
	}

	if int32(len(peers)) > limit {
		peers = peers[:limit]
	}

	resp := &GatewayBGPPeersResponse{
		Peers:     peers,
		Count:     int32(len(peers)),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleAnnouncePrefix announces a prefix via BGP
func (h *GatewayHandler) handleAnnouncePrefix(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var announceReq GatewayAnnouncePrefixRequest
	if err := DecodePayload(req.Payload, &announceReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	if announceReq.Prefix == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayMissingPrefix)
	}

	// Validate prefix format
	_, _, err := net.ParseCIDR(announceReq.Prefix)
	if err != nil {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayInvalidPrefix)
	}

	opts := &AnnouncePrefixOptions{
		NextHop:     announceReq.NextHop,
		LocalPref:   announceReq.LocalPref,
		MED:         announceReq.MED,
		Communities: announceReq.Communities,
		Labels:      announceReq.Labels,
	}

	if err := h.gatewayService.AnnouncePrefix(ctx, announceReq.Prefix, opts); err != nil {
		h.logger.Error(err, "failed to announce prefix")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayAnnouncePrefixResponse{
		Prefix:    announceReq.Prefix,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleWithdrawPrefix withdraws a prefix from BGP
func (h *GatewayHandler) handleWithdrawPrefix(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var withdrawReq GatewayWithdrawPrefixRequest
	if err := DecodePayload(req.Payload, &withdrawReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	if withdrawReq.Prefix == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayMissingPrefix)
	}

	// Validate prefix format
	_, _, err := net.ParseCIDR(withdrawReq.Prefix)
	if err != nil {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayInvalidPrefix)
	}

	if err := h.gatewayService.WithdrawPrefix(ctx, withdrawReq.Prefix); err != nil {
		h.logger.Error(err, "failed to withdraw prefix")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayWithdrawPrefixResponse{
		Prefix:    withdrawReq.Prefix,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleListPrefixes lists announced prefixes
func (h *GatewayHandler) handleListPrefixes(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var listReq GatewayListPrefixesRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	prefixes, err := h.gatewayService.ListPrefixes(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list prefixes")
		return h.gatewayErrorResponse(err)
	}

	// Apply limit
	limit := listReq.Limit
	if limit <= 0 {
		limit = gatewayDefaultLimit
	} else if limit > gatewayMaxLimit {
		limit = gatewayMaxLimit
	}

	if int32(len(prefixes)) > limit {
		prefixes = prefixes[:limit]
	}

	resp := &GatewayListPrefixesResponse{
		Prefixes:  prefixes,
		Count:     int32(len(prefixes)),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleListIPAMPools lists IPAM pools
func (h *GatewayHandler) handleListIPAMPools(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var listReq GatewayListIPAMPoolsRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	pools, err := h.gatewayService.ListIPAMPools(ctx, listReq.Zone)
	if err != nil {
		h.logger.Error(err, "failed to list IPAM pools")
		return h.gatewayErrorResponse(err)
	}

	// Apply limit
	limit := listReq.Limit
	if limit <= 0 {
		limit = gatewayDefaultLimit
	} else if limit > gatewayMaxLimit {
		limit = gatewayMaxLimit
	}

	if int32(len(pools)) > limit {
		pools = pools[:limit]
	}

	resp := &GatewayListIPAMPoolsResponse{
		Pools:     pools,
		Count:     int32(len(pools)),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleCreateIPAMPool creates a new IPAM pool
func (h *GatewayHandler) handleCreateIPAMPool(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var createReq GatewayCreateIPAMPoolRequest
	if err := DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	if createReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayMissingPoolName)
	}

	if createReq.CIDR == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayMissingPoolCIDR)
	}

	// Validate CIDR format
	_, _, err := net.ParseCIDR(createReq.CIDR)
	if err != nil {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayInvalidPoolCIDR)
	}

	opts := &CreateIPAMPoolOptions{
		ID:            createReq.ID,
		Name:          createReq.Name,
		CIDR:          createReq.CIDR,
		Gateway:       createReq.Gateway,
		Zone:          createReq.Zone,
		Description:   createReq.Description,
		LeaseDuration: createReq.LeaseDuration,
		Reserved:      createReq.Reserved,
		RangeStart:    createReq.RangeStart,
		RangeEnd:      createReq.RangeEnd,
	}

	pool, err := h.gatewayService.CreateIPAMPool(ctx, opts)
	if err != nil {
		h.logger.Error(err, "failed to create IPAM pool")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayCreateIPAMPoolResponse{
		Pool:      pool,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleDeleteIPAMPool deletes an IPAM pool
func (h *GatewayHandler) handleDeleteIPAMPool(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var deleteReq GatewayDeleteIPAMPoolRequest
	if err := DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	if deleteReq.PoolID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayMissingPoolID)
	}

	if err := h.gatewayService.DeleteIPAMPool(ctx, deleteReq.PoolID); err != nil {
		h.logger.Error(err, "failed to delete IPAM pool")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayDeleteIPAMPoolResponse{
		PoolID:    deleteReq.PoolID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleAllocateIP allocates an IP address from a pool
func (h *GatewayHandler) handleAllocateIP(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var allocReq GatewayAllocateIPRequest
	if err := DecodePayload(req.Payload, &allocReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	if allocReq.PoolID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayMissingPoolID)
	}

	// Validate IP address if provided
	if allocReq.IPAddress != "" {
		if net.ParseIP(allocReq.IPAddress) == nil {
			return h.errorResponse(StatusInvalidArgument, ErrGatewayInvalidIPAddress)
		}
	}

	opts := &AllocateIPOptions{
		IPAddress:  allocReq.IPAddress,
		MACAddress: allocReq.MACAddress,
		Hostname:   allocReq.Hostname,
		Owner:      allocReq.Owner,
		Type:       allocReq.Type,
		TTL:        allocReq.TTL,
		Labels:     allocReq.Labels,
	}

	allocation, err := h.gatewayService.AllocateIP(ctx, allocReq.PoolID, opts)
	if err != nil {
		h.logger.Error(err, "failed to allocate IP")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayAllocateIPResponse{
		Allocation: allocation,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleReleaseIP releases an IP address back to the pool
func (h *GatewayHandler) handleReleaseIP(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var releaseReq GatewayReleaseIPRequest
	if err := DecodePayload(req.Payload, &releaseReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	// pool_id is optional: an address identifies its allocation, and gRPC,
	// REST and the CLI release by address alone. When it is given, the
	// service refuses an address that belongs to another pool.
	if releaseReq.IPAddress == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayMissingIPAddress)
	}

	// Validate IP address
	if net.ParseIP(releaseReq.IPAddress) == nil {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayInvalidIPAddress)
	}

	if err := h.gatewayService.ReleaseIP(ctx, releaseReq.PoolID, releaseReq.IPAddress); err != nil {
		h.logger.Error(err, "failed to release IP")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayReleaseIPResponse{
		PoolID:    releaseReq.PoolID,
		IPAddress: releaseReq.IPAddress,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleListAllocations lists IP allocations in a pool
func (h *GatewayHandler) handleListAllocations(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var listReq GatewayListAllocationsRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	// Empty PoolID lists allocations across all pools (same semantics as gRPC ListAllocations).
	allocations, err := h.gatewayService.ListAllocations(ctx, listReq.PoolID)
	if err != nil {
		h.logger.Error(err, "failed to list allocations")
		return h.gatewayErrorResponse(err)
	}

	// Apply limit
	limit := listReq.Limit
	if limit <= 0 {
		limit = gatewayDefaultLimit
	} else if limit > gatewayMaxLimit {
		limit = gatewayMaxLimit
	}

	if int32(len(allocations)) > limit {
		allocations = allocations[:limit]
	}

	resp := &GatewayListAllocationsResponse{
		Allocations: allocations,
		Count:       int32(len(allocations)),
		Timestamp:   time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleGetIPAMPool returns a single IPAM pool by ID
func (h *GatewayHandler) handleGetIPAMPool(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var getReq GatewayGetIPAMPoolRequest
	if err := DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	if getReq.PoolID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayMissingPoolID)
	}

	pool, err := h.gatewayService.GetIPAMPool(ctx, getReq.PoolID)
	if err != nil {
		h.logger.Error(err, "failed to get IPAM pool")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayGetIPAMPoolResponse{
		Pool:      pool,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleUpdateIPAMPool updates mutable fields of an IPAM pool.
// CIDR is immutable and cannot be changed after creation.
func (h *GatewayHandler) handleUpdateIPAMPool(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var updateReq GatewayUpdateIPAMPoolRequest
	if err := DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	if updateReq.PoolID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayMissingPoolID)
	}

	opts := &UpdateIPAMPoolOptions{
		Name:          updateReq.Name,
		Gateway:       updateReq.Gateway,
		Zone:          updateReq.Zone,
		Description:   updateReq.Description,
		LeaseDuration: updateReq.LeaseDuration,
		UpdateWindow:  updateReq.UpdateWindow,
		Reserved:      updateReq.Reserved,
		RangeStart:    updateReq.RangeStart,
		RangeEnd:      updateReq.RangeEnd,
	}

	pool, err := h.gatewayService.UpdateIPAMPool(ctx, updateReq.PoolID, opts)
	if err != nil {
		h.logger.Error(err, "failed to update IPAM pool")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayUpdateIPAMPoolResponse{
		Pool:      pool,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Helper Methods
// =============================================================================

// errorResponse creates an error response with the given status and error
func (h *GatewayHandler) errorResponse(status byte, err error) *Response {
	return &Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// gatewayErrorResponse maps gateway errors to appropriate status codes
func (h *GatewayHandler) gatewayErrorResponse(err error) *Response {
	var status byte

	switch {
	case errors.Is(err, ErrGatewayPrefixNotFound):
		status = StatusNotFound
	case errors.Is(err, ErrGatewayPoolNotFound):
		status = StatusNotFound
	case errors.Is(err, ErrGatewayAllocationNotFound):
		status = StatusNotFound
	case errors.Is(err, ErrGatewayIPAlreadyAllocated):
		status = StatusAlreadyExists
	case errors.Is(err, ErrGatewayMissingOwner),
		errors.Is(err, ErrGatewayMACNotRecorded),
		errors.Is(err, ErrGatewayInvalidAllocationType):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayBGPPeerNotFound):
		status = StatusNotFound
	case errors.Is(err, ErrGatewayPrefixAlreadyExists):
		status = StatusAlreadyExists
	case errors.Is(err, ErrGatewayPoolAlreadyExists):
		status = StatusAlreadyExists
	case errors.Is(err, ErrGatewayPoolExhausted):
		status = StatusResourceExhausted
	case errors.Is(err, ErrGatewayInvalidMode):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayInvalidPrefix):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayInvalidIPAddress):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayInvalidPoolCIDR):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayIPAMWindow):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayMissingMode):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayMissingPrefix):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayMissingPoolID):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayMissingPoolName):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayMissingPoolCIDR):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayMissingIPAddress):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayBGPNotEnabled):
		status = StatusUnavailable
	case errors.Is(err, ErrGatewayServiceNotAvailable):
		status = StatusUnavailable
	case errors.Is(err, ErrGatewayFeatureNotConfigured):
		status = StatusUnavailable
	case errors.Is(err, ErrGatewayPreconditionFailed):
		status = StatusInvalidRequest
	case errors.Is(err, ErrGatewayVIPNotFound):
		status = StatusNotFound
	case errors.Is(err, ErrGatewayVIPAlreadyExists):
		status = StatusAlreadyExists
	case errors.Is(err, ErrGatewayInvalidVIP):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayMissingVIPTarget):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayZoneNotFound):
		status = StatusNotFound
	case errors.Is(err, ErrGatewayZoneAlreadyExists):
		status = StatusAlreadyExists
	case errors.Is(err, ErrGatewayZoneInvalid):
		status = StatusInvalidArgument
	default:
		status = StatusInternalError
	}

	return h.errorResponse(status, err)
}

// =============================================================================
// Gateway Error Types
// =============================================================================

// ErrGatewayEncodingFailed represents an encoding failure error
type ErrGatewayEncodingFailed struct {
	Cause error
}

func (e ErrGatewayEncodingFailed) Error() string {
	return "failed to encode gateway payload: " + e.Cause.Error()
}

func (e ErrGatewayEncodingFailed) Unwrap() error {
	return e.Cause
}

// GatewayZoneError carries a zone service failure to the QUIC client: Kind
// is the sentinel that selects the status byte (ErrGatewayZoneNotFound,
// ErrGatewayZoneAlreadyExists or ErrGatewayZoneInvalid) and Cause the
// service error whose message the client sees.
type GatewayZoneError struct {
	Kind  error
	Cause error
}

// Error implements the error interface.
func (e GatewayZoneError) Error() string {
	if e.Cause == nil {
		return e.Kind.Error()
	}
	return e.Kind.Error() + ": " + e.Cause.Error()
}

// Is matches the sentinel kind.
func (e GatewayZoneError) Is(target error) bool { return target == e.Kind }

// Unwrap returns the service error.
func (e GatewayZoneError) Unwrap() error { return e.Cause }

// ErrGatewayDecodingFailed represents a decoding failure error
type ErrGatewayDecodingFailed struct {
	Cause error
}

func (e ErrGatewayDecodingFailed) Error() string {
	return "failed to decode gateway payload: " + e.Cause.Error()
}

func (e ErrGatewayDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrGatewayOperationFailed represents a gateway operation failure
type ErrGatewayOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrGatewayOperationFailed) Error() string {
	return "gateway operation " + e.Operation + " failed: " + e.Cause.Error()
}

func (e ErrGatewayOperationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Network Zone Handler Implementations
// =============================================================================

// handleListNetworkZones lists network trust zones.
func (h *GatewayHandler) handleListNetworkZones(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var listReq GatewayListNetworkZonesRequest
	if len(req.Payload) > 0 {
		if err := DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
		}
	}

	zones, err := h.gatewayService.ListNetworkZones(ctx, listReq.LifecycleRole)
	if err != nil {
		h.logger.Error(err, "failed to list network zones")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayListNetworkZonesResponse{
		Zones:     zones,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{Status: StatusOK, Payload: payload}
}

// handleCreateNetworkZone creates a new network trust zone.
func (h *GatewayHandler) handleCreateNetworkZone(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var createReq GatewayCreateNetworkZoneRequest
	if err := DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	if createReq.Opts == nil || createReq.Opts.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayZoneNameRequired)
	}

	z, err := h.gatewayService.CreateNetworkZone(ctx, createReq.Opts)
	if err != nil {
		h.logger.Error(err, "failed to create network zone")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayCreateNetworkZoneResponse{Zone: z}
	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{Status: StatusOK, Payload: payload}
}

// handleUpdateNetworkZone updates an existing network trust zone.
func (h *GatewayHandler) handleUpdateNetworkZone(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var updateReq GatewayUpdateNetworkZoneRequest
	if err := DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	if updateReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayZoneNameRequired)
	}
	if updateReq.Opts == nil {
		updateReq.Opts = &UpdateNetworkZoneOptions{}
	}

	z, err := h.gatewayService.UpdateNetworkZone(ctx, updateReq.Name, updateReq.Opts)
	if err != nil {
		h.logger.Error(err, "failed to update network zone")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayUpdateNetworkZoneResponse{Zone: z}
	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{Status: StatusOK, Payload: payload}
}

// handleDeleteNetworkZone deletes a network trust zone.
func (h *GatewayHandler) handleDeleteNetworkZone(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var deleteReq GatewayDeleteNetworkZoneRequest
	if err := DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	if deleteReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayZoneNameRequired)
	}

	restartRequired, err := h.gatewayService.DeleteNetworkZone(ctx, deleteReq.Name)
	if err != nil {
		h.logger.Error(err, "failed to delete network zone")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayDeleteNetworkZoneResponse{
		RestartRequired: restartRequired,
		Timestamp:       time.Now().Unix(),
	}
	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{Status: StatusOK, Payload: payload}
}

// ErrGatewayIPAMWindowDetail carries why an IPAM window check refused a
// request; errors.Is(err, ErrGatewayIPAMWindow) holds for it.
type ErrGatewayIPAMWindowDetail struct {
	// Reason is the underlying refusal.
	Reason string
}

// Error implements the error interface.
func (e ErrGatewayIPAMWindowDetail) Error() string {
	return ErrGatewayIPAMWindow.Error() + ": " + e.Reason
}

// Unwrap lets errors.Is match ErrGatewayIPAMWindow.
func (e ErrGatewayIPAMWindowDetail) Unwrap() error { return ErrGatewayIPAMWindow }

// ErrGatewayPreconditionDetail carries the host's own reason a gateway
// service cannot run; errors.Is(err, ErrGatewayPreconditionFailed) holds
// for it.
type ErrGatewayPreconditionDetail struct {
	// Reason is the underlying refusal.
	Reason string
}

// Error implements the error interface.
func (e ErrGatewayPreconditionDetail) Error() string {
	return ErrGatewayPreconditionFailed.Error() + ": " + e.Reason
}

// Unwrap lets errors.Is match ErrGatewayPreconditionFailed.
func (e ErrGatewayPreconditionDetail) Unwrap() error { return ErrGatewayPreconditionFailed }
