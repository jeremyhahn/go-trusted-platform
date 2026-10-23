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

package quicwire

// Wire shapes of the gateway IPAM sub-opcodes (OpGatewayListIPAMPools
// through OpGatewayUpdateIPAMPool). The server handler and the SDK adapter
// share them so the two ends cannot drift.

// IPAMPoolInfo contains IPAM pool information.
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
	UpdatedAt     int64             `codec:"updated_at,omitempty"`
	LastAllocated int64             `codec:"last_allocated,omitempty"`
	// LeaseDuration and InactivityTimeout are nanoseconds; zero means
	// allocations never expire / the allocator default.
	LeaseDuration     int64 `codec:"lease_duration_nanos,omitempty"`
	InactivityTimeout int64 `codec:"inactivity_timeout_nanos,omitempty"`
	// Reserved lists never-allocatable prefixes (CIDR notation); the
	// gateway is always reserved as well.
	Reserved []string `codec:"reserved,omitempty"`
	// RangeStart and RangeEnd bound dynamic allocation; empty means the
	// whole CIDR.
	RangeStart string `codec:"range_start,omitempty"`
	RangeEnd   string `codec:"range_end,omitempty"`
}

// IPAllocationInfo contains IP allocation information.
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

// GatewayListIPAMPoolsRequest represents an IPAM pools list request.
type GatewayListIPAMPoolsRequest struct {
	// Zone filters pools by trust/exposure zone; empty returns all pools.
	Zone  string `codec:"zone,omitempty"`
	Limit int32  `codec:"limit,omitempty"`
}

// GatewayListIPAMPoolsResponse represents an IPAM pools list response.
type GatewayListIPAMPoolsResponse struct {
	Pools     []*IPAMPoolInfo `codec:"pools"`
	Count     int32           `codec:"count"`
	Timestamp int64           `codec:"timestamp"`
}

// GatewayGetIPAMPoolRequest represents an IPAM pool get request.
type GatewayGetIPAMPoolRequest struct {
	PoolID string `codec:"pool_id"`
}

// GatewayGetIPAMPoolResponse represents an IPAM pool get response.
type GatewayGetIPAMPoolResponse struct {
	Pool      *IPAMPoolInfo `codec:"pool"`
	Timestamp int64         `codec:"timestamp"`
}

// GatewayCreateIPAMPoolRequest represents an IPAM pool create request.
type GatewayCreateIPAMPoolRequest struct {
	ID                string `codec:"id,omitempty"`
	Name              string `codec:"name"`
	CIDR              string `codec:"cidr"`
	Gateway           string `codec:"gateway,omitempty"`
	Zone              string `codec:"zone,omitempty"`
	Description       string `codec:"description,omitempty"`
	LeaseDuration     int64  `codec:"lease_duration_nanos,omitempty"`
	InactivityTimeout int64  `codec:"inactivity_timeout_nanos,omitempty"`
	// Reserved lists never-allocatable prefixes (CIDR notation).
	Reserved []string `codec:"reserved,omitempty"`
	// RangeStart and RangeEnd bound dynamic allocation; set both or neither.
	RangeStart string `codec:"range_start,omitempty"`
	RangeEnd   string `codec:"range_end,omitempty"`
}

// GatewayCreateIPAMPoolResponse represents an IPAM pool create response.
type GatewayCreateIPAMPoolResponse struct {
	Pool      *IPAMPoolInfo `codec:"pool"`
	Timestamp int64         `codec:"timestamp"`
}

// GatewayUpdateIPAMPoolRequest represents an IPAM pool update request.
type GatewayUpdateIPAMPoolRequest struct {
	PoolID            string `codec:"pool_id"`
	Name              string `codec:"name,omitempty"`
	Gateway           string `codec:"gateway,omitempty"`
	Zone              string `codec:"zone,omitempty"`
	Description       string `codec:"description,omitempty"`
	LeaseDuration     int64  `codec:"lease_duration_nanos,omitempty"`
	InactivityTimeout int64  `codec:"inactivity_timeout_nanos,omitempty"`
	// UpdateWindow, when true, makes Reserved, RangeStart and RangeEnd
	// replace the pool's allocation window (empty values clear it).
	UpdateWindow bool     `codec:"update_window,omitempty"`
	Reserved     []string `codec:"reserved,omitempty"`
	RangeStart   string   `codec:"range_start,omitempty"`
	RangeEnd     string   `codec:"range_end,omitempty"`
}

// GatewayUpdateIPAMPoolResponse represents an IPAM pool update response.
type GatewayUpdateIPAMPoolResponse struct {
	Pool      *IPAMPoolInfo `codec:"pool"`
	Timestamp int64         `codec:"timestamp"`
}

// GatewayDeleteIPAMPoolRequest represents an IPAM pool delete request.
type GatewayDeleteIPAMPoolRequest struct {
	PoolID string `codec:"pool_id"`
}

// GatewayDeleteIPAMPoolResponse represents an IPAM pool delete response.
type GatewayDeleteIPAMPoolResponse struct {
	PoolID    string `codec:"pool_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// GatewayAllocateIPRequest represents an IP allocation request. Owner is
// the device the address is allocated to.
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

// GatewayAllocateIPResponse represents an IP allocation response.
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

// GatewayReleaseIPResponse represents an IP release response.
type GatewayReleaseIPResponse struct {
	PoolID    string `codec:"pool_id"`
	IPAddress string `codec:"ip_address"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// GatewayListAllocationsRequest represents an allocations list request;
// an empty PoolID lists every pool's allocations.
type GatewayListAllocationsRequest struct {
	PoolID string `codec:"pool_id"`
	Limit  int32  `codec:"limit,omitempty"`
}

// GatewayListAllocationsResponse represents an allocations list response.
type GatewayListAllocationsResponse struct {
	Allocations []*IPAllocationInfo `codec:"allocations"`
	Count       int32               `codec:"count"`
	Timestamp   int64               `codec:"timestamp"`
}
