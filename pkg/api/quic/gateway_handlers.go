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

	// Network Zone Operations (0x10-0x14)
	OpGatewayListNetworkZones  byte = 0x10
	OpGatewayCreateNetworkZone byte = 0x11
	OpGatewayUpdateNetworkZone byte = 0x12
	OpGatewayDeleteNetworkZone byte = 0x13
	OpGatewayAssignNetworkZone byte = 0x14
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

	// ErrGatewayBGPNotEnabled is returned when BGP operations are attempted
	// but BGP is not enabled.
	ErrGatewayBGPNotEnabled = errors.New("BGP is not enabled")

	// ErrGatewayBGPPeerNotFound is returned when a BGP peer is not found.
	ErrGatewayBGPPeerNotFound = errors.New("BGP peer not found")

	// ErrGatewayZoneNameRequired is returned when a zone name is required.
	ErrGatewayZoneNameRequired = errors.New("zone name is required")

	// ErrGatewayZoneNotFound is returned when a zone is not found.
	ErrGatewayZoneNotFound = errors.New("zone not found")

	// ErrGatewayNetworkRequired is returned when a network name is required.
	ErrGatewayNetworkRequired = errors.New("network name is required")

	// ErrGatewayZoneTargetRequired is returned when a target zone is required.
	ErrGatewayZoneTargetRequired = errors.New("target zone name is required")

	// ErrGatewayFeatureNotConfigured is returned when a gateway feature is
	// requested but the backing service or hardware is not configured. Adapters
	// that only support a subset of the GatewayServiceInterface (e.g. zone-only
	// adapters) return this error for every unsupported method so the QUIC
	// handler correctly emits StatusUnavailable to the client.
	ErrGatewayFeatureNotConfigured = errors.New("gateway feature not configured")
)

// GatewayServiceInterface defines the interface for gateway operations.
type GatewayServiceInterface interface {
	// Status returns the current gateway status
	Status(ctx context.Context) (*GatewayStatusInfo, error)

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
	AssignNetworkZone(ctx context.Context, network string, zoneName string) (bool, error)

	// Load balancer VIP operations (sub-opcodes 0x30-0x35)
	AddVIP(ctx context.Context, spec *LBVIPSpec) (*LBVIPInfo, error)
	RemoveVIP(ctx context.Context, protocol, address string, port uint16) error
	GetVIP(ctx context.Context, protocol, address string, port uint16) (*LBVIPInfo, error)
	ListVIPs(ctx context.Context) ([]*LBVIPInfo, error)
	SetVIPBackends(ctx context.Context, protocol, address string, port uint16, backends []*LBBackendSpec) (*LBVIPInfo, error)
	LBStatus(ctx context.Context) (*LBStatusInfo, error)
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
	DNS           []string          `codec:"dns,omitempty"`
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
	ID            string   `codec:"id,omitempty"`
	Name          string   `codec:"name"`
	CIDR          string   `codec:"cidr"`
	Gateway       string   `codec:"gateway,omitempty"`
	Zone          string   `codec:"zone,omitempty"`
	Description   string   `codec:"description,omitempty"`
	DNS           []string `codec:"dns,omitempty"`
	LeaseDuration int64    `codec:"lease_duration_nanos,omitempty"`
}

// UpdateIPAMPoolOptions contains options for updating an IPAM pool.
// CIDR is immutable and must not be specified.
type UpdateIPAMPoolOptions struct {
	Name          string `codec:"name,omitempty"`
	Gateway       string `codec:"gateway,omitempty"`
	Zone          string `codec:"zone,omitempty"`
	Description   string `codec:"description,omitempty"`
	LeaseDuration int64  `codec:"lease_duration_nanos,omitempty"`
}

// NetworkZoneInfo contains network zone information.
type NetworkZoneInfo struct {
	Name             string   `codec:"name"`
	InternetIngress  bool     `codec:"internet_ingress,omitempty"`
	IsolateFrom      []string `codec:"isolate_from,omitempty"`
	Isolate          bool     `codec:"isolate,omitempty"`
	IsolatePerTenant bool     `codec:"isolate_per_tenant,omitempty"`
	OOB              bool     `codec:"oob,omitempty"`
	LifecycleRole    string   `codec:"lifecycle_role,omitempty"`
	RestartRequired  bool     `codec:"restart_required,omitempty"`
	CreatedAt        int64    `codec:"created_at"`
	UpdatedAt        int64    `codec:"updated_at"`
}

// CreateNetworkZoneOptions contains options for creating a network zone.
type CreateNetworkZoneOptions struct {
	Name             string   `codec:"name"`
	InternetIngress  bool     `codec:"internet_ingress,omitempty"`
	IsolateFrom      []string `codec:"isolate_from,omitempty"`
	Isolate          bool     `codec:"isolate,omitempty"`
	IsolatePerTenant bool     `codec:"isolate_per_tenant,omitempty"`
	OOB              bool     `codec:"oob,omitempty"`
	LifecycleRole    string   `codec:"lifecycle_role,omitempty"`
}

// UpdateNetworkZoneOptions contains options for updating a network zone.
type UpdateNetworkZoneOptions struct {
	InternetIngress  bool     `codec:"internet_ingress,omitempty"`
	IsolateFrom      []string `codec:"isolate_from,omitempty"`
	Isolate          bool     `codec:"isolate,omitempty"`
	IsolatePerTenant bool     `codec:"isolate_per_tenant,omitempty"`
	OOB              bool     `codec:"oob,omitempty"`
	LifecycleRole    string   `codec:"lifecycle_role,omitempty"`
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

// GatewayAssignNetworkZoneRequest represents a zone assign request.
type GatewayAssignNetworkZoneRequest struct {
	Network string `codec:"network"`
	Zone    string `codec:"zone"`
}

// GatewayAssignNetworkZoneResponse represents a zone assign response.
type GatewayAssignNetworkZoneResponse struct {
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
	case OpGatewayAssignNetworkZone:
		return h.handleAssignNetworkZone(ctx, req)

	default:
		// Load balancer sub-opcodes (0x30-0x35) dispatch via map lookup.
		if handler, ok := gatewayLBHandlers[req.Opcode]; ok {
			return handler(h, ctx, req)
		}
		// Perf sub-opcodes (0x36-0x38) dispatch via map lookup.
		if handler, ok := gatewayPerfHandlers[req.Opcode]; ok {
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
	ID            string   `codec:"id,omitempty"`
	Name          string   `codec:"name"`
	CIDR          string   `codec:"cidr"`
	Gateway       string   `codec:"gateway,omitempty"`
	Zone          string   `codec:"zone,omitempty"`
	Description   string   `codec:"description,omitempty"`
	DNS           []string `codec:"dns,omitempty"`
	LeaseDuration int64    `codec:"lease_duration_nanos,omitempty"`
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

// GatewayReleaseIPRequest represents an IP release request
type GatewayReleaseIPRequest struct {
	PoolID    string `codec:"pool_id"`
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
		DNS:           createReq.DNS,
		LeaseDuration: createReq.LeaseDuration,
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

	if releaseReq.PoolID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayMissingPoolID)
	}

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
	case errors.Is(err, ErrGatewayVIPNotFound):
		status = StatusNotFound
	case errors.Is(err, ErrGatewayVIPAlreadyExists):
		status = StatusAlreadyExists
	case errors.Is(err, ErrGatewayInvalidVIP):
		status = StatusInvalidArgument
	case errors.Is(err, ErrGatewayMissingVIPTarget):
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

// handleAssignNetworkZone assigns a network segment to a trust zone.
func (h *GatewayHandler) handleAssignNetworkZone(ctx context.Context, req *Request) *Response {
	if h.gatewayService == nil {
		return h.errorResponse(StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var assignReq GatewayAssignNetworkZoneRequest
	if err := DecodePayload(req.Payload, &assignReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	if assignReq.Network == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayNetworkRequired)
	}
	if assignReq.Zone == "" {
		return h.errorResponse(StatusInvalidArgument, ErrGatewayZoneTargetRequired)
	}

	restartRequired, err := h.gatewayService.AssignNetworkZone(ctx, assignReq.Network, assignReq.Zone)
	if err != nil {
		h.logger.Error(err, "failed to assign network zone")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayAssignNetworkZoneResponse{
		RestartRequired: restartRequired,
		Timestamp:       time.Now().Unix(),
	}
	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}

	return &Response{Status: StatusOK, Payload: payload}
}
