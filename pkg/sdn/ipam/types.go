// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"net/netip"
	"time"
)

// AllocationStatus represents the current state of an IP allocation.
type AllocationStatus string

const (
	// AllocationStatusActive indicates the allocation is currently in use.
	AllocationStatusActive AllocationStatus = "active"
	// AllocationStatusExpired indicates the allocation has expired due to inactivity.
	AllocationStatusExpired AllocationStatus = "expired"
	// AllocationStatusReleased indicates the allocation was explicitly released.
	AllocationStatusReleased AllocationStatus = "released"
	// AllocationStatusReserved indicates the IP is reserved and cannot be allocated.
	AllocationStatusReserved AllocationStatus = "reserved"
)

// String returns the string representation of AllocationStatus.
func (s AllocationStatus) String() string {
	return string(s)
}

// IsValid returns true if the status is a recognized value.
func (s AllocationStatus) IsValid() bool {
	switch s {
	case AllocationStatusActive, AllocationStatusExpired,
		AllocationStatusReleased, AllocationStatusReserved:
		return true
	default:
		return false
	}
}

// Pool represents an IP address pool for allocation.
type Pool struct {
	// ID is the unique identifier for this pool.
	ID string `json:"id"`
	// Name is the human-readable name for this pool.
	Name string `json:"name"`
	// CIDR is the network prefix defining the pool's address space.
	CIDR netip.Prefix `json:"cidr"`
	// Gateway is the optional gateway address for this pool.
	Gateway netip.Addr `json:"gateway,omitempty"`
	// Description provides optional context about the pool's purpose.
	Description string `json:"description,omitempty"`
	// Tags are optional labels for categorizing and filtering pools.
	Tags []string `json:"tags,omitempty"`

	// TotalIPs is the total number of usable IPs in this pool.
	TotalIPs uint64 `json:"total_ips"`
	// AllocatedIPs is the current number of allocated IPs.
	AllocatedIPs uint64 `json:"allocated_ips"`
	// AvailableIPs is the current number of available IPs.
	AvailableIPs uint64 `json:"available_ips"`

	// DefaultLeaseDuration is the default lease duration for allocations.
	// Zero means allocations never expire.
	DefaultLeaseDuration time.Duration `json:"default_lease_duration"`
	// InactivityTimeout specifies how long an allocation can be inactive
	// before being eligible for expiration. Default is 30 days.
	InactivityTimeout time.Duration `json:"inactivity_timeout"`

	// CreatedAt is when this pool was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when this pool was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// Clone returns a deep copy of the Pool.
func (p *Pool) Clone() *Pool {
	if p == nil {
		return nil
	}
	clone := *p
	if p.Tags != nil {
		clone.Tags = make([]string, len(p.Tags))
		copy(clone.Tags, p.Tags)
	}
	return &clone
}

// Allocation represents an IP address allocation within a pool.
type Allocation struct {
	// ID is the unique identifier for this allocation.
	ID string `json:"id"`
	// PoolID is the ID of the pool this allocation belongs to.
	PoolID string `json:"pool_id"`
	// IP is the allocated IP address.
	IP netip.Addr `json:"ip"`
	// DeviceID is the identifier of the device holding this allocation.
	DeviceID string `json:"device_id"`
	// Hostname is the optional hostname associated with this allocation.
	Hostname string `json:"hostname,omitempty"`
	// Description provides optional context about the allocation.
	Description string `json:"description,omitempty"`
	// Tags are optional labels for categorizing allocations.
	Tags []string `json:"tags,omitempty"`
	// Metadata contains optional key-value pairs for custom data.
	Metadata map[string]string `json:"metadata,omitempty"`

	// AllocatedAt is when this allocation was created.
	AllocatedAt time.Time `json:"allocated_at"`
	// LastSeen is when the device was last seen using this allocation.
	LastSeen time.Time `json:"last_seen"`
	// ExpiresAt is when this allocation expires. Zero means never expires.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// ReleasedAt is when this allocation was released. Zero if not released.
	ReleasedAt time.Time `json:"released_at,omitempty"`

	// Status is the current state of this allocation.
	Status AllocationStatus `json:"status"`
}

// Clone returns a deep copy of the Allocation.
func (a *Allocation) Clone() *Allocation {
	if a == nil {
		return nil
	}
	clone := *a
	if a.Tags != nil {
		clone.Tags = make([]string, len(a.Tags))
		copy(clone.Tags, a.Tags)
	}
	if a.Metadata != nil {
		clone.Metadata = make(map[string]string, len(a.Metadata))
		for k, v := range a.Metadata {
			clone.Metadata[k] = v
		}
	}
	return &clone
}

// IsExpired returns true if the allocation has expired.
func (a *Allocation) IsExpired() bool {
	if a.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(a.ExpiresAt)
}

// IsActive returns true if the allocation is currently active.
func (a *Allocation) IsActive() bool {
	return a.Status == AllocationStatusActive && !a.IsExpired()
}

// AllocationRequest contains the parameters for requesting an IP allocation.
type AllocationRequest struct {
	// PoolID is the ID of the pool to allocate from.
	PoolID string `json:"pool_id"`
	// DeviceID is the identifier of the device requesting the allocation.
	DeviceID string `json:"device_id"`
	// Hostname is the optional hostname to associate with the allocation.
	Hostname string `json:"hostname,omitempty"`
	// Description provides optional context about the allocation.
	Description string `json:"description,omitempty"`
	// Tags are optional labels for the allocation.
	Tags []string `json:"tags,omitempty"`
	// Metadata contains optional key-value pairs for custom data.
	Metadata map[string]string `json:"metadata,omitempty"`

	// RequestedIP is an optional specific IP to allocate.
	// If not set, the next available IP will be allocated.
	RequestedIP netip.Addr `json:"requested_ip,omitempty"`

	// LeaseDuration overrides the pool's default lease duration.
	// Zero means use the pool's default.
	LeaseDuration time.Duration `json:"lease_duration,omitempty"`
}

// Validate checks if the allocation request is valid.
func (r *AllocationRequest) Validate() error {
	if r.PoolID == "" {
		return ErrPoolIDRequired
	}
	if r.DeviceID == "" {
		return ErrDeviceIDRequired
	}
	return nil
}

// Clone returns a deep copy of the AllocationRequest.
func (r *AllocationRequest) Clone() *AllocationRequest {
	if r == nil {
		return nil
	}
	clone := *r
	if r.Tags != nil {
		clone.Tags = make([]string, len(r.Tags))
		copy(clone.Tags, r.Tags)
	}
	if r.Metadata != nil {
		clone.Metadata = make(map[string]string, len(r.Metadata))
		for k, v := range r.Metadata {
			clone.Metadata[k] = v
		}
	}
	return &clone
}

// PoolStats provides statistics about a pool's utilization.
type PoolStats struct {
	// PoolID is the ID of the pool these stats are for.
	PoolID string `json:"pool_id"`
	// TotalIPs is the total number of usable IPs in the pool.
	TotalIPs uint64 `json:"total_ips"`
	// AllocatedIPs is the number of currently allocated IPs.
	AllocatedIPs uint64 `json:"allocated_ips"`
	// AvailableIPs is the number of IPs available for allocation.
	AvailableIPs uint64 `json:"available_ips"`
	// ExpiredIPs is the number of allocations that have expired.
	ExpiredIPs uint64 `json:"expired_ips"`
	// ReservedIPs is the number of reserved IPs.
	ReservedIPs uint64 `json:"reserved_ips"`
	// UtilizationPct is the percentage of the pool that is allocated.
	UtilizationPct float64 `json:"utilization_pct"`
}

// CalculateUtilization computes the utilization percentage.
func (s *PoolStats) CalculateUtilization() {
	if s.TotalIPs == 0 {
		s.UtilizationPct = 0
		return
	}
	s.UtilizationPct = float64(s.AllocatedIPs) / float64(s.TotalIPs) * 100
}
