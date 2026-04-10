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

package vlan

import (
	"context"
	"fmt"
	"time"
)

const (
	// MinVLANID is the minimum valid VLAN ID (VLAN 0 is reserved)
	MinVLANID uint16 = 1

	// MaxVLANID is the maximum valid VLAN ID (4095 is reserved)
	MaxVLANID uint16 = 4094

	// DefaultRangeSize is the default number of VLANs allocated per tenant
	DefaultRangeSize uint16 = 100
)

// Range represents a VLAN ID range
type Range struct {
	Start uint16
	End   uint16
}

// Contains returns true if the specified VLAN is within this range
func (r Range) Contains(vlan uint16) bool {
	return vlan >= r.Start && vlan <= r.End
}

// Size returns the number of VLANs in this range
func (r Range) Size() int {
	if r.End < r.Start {
		return 0
	}
	return int(r.End-r.Start) + 1
}

// Validate checks if the range is valid according to VLAN specifications
func (r Range) Validate() error {
	if r.Start < MinVLANID {
		return &ErrInvalidVLANRange{
			Start:  r.Start,
			End:    r.End,
			Reason: fmt.Sprintf("start VLAN %d is below minimum %d", r.Start, MinVLANID),
		}
	}
	if r.End > MaxVLANID {
		return &ErrInvalidVLANRange{
			Start:  r.Start,
			End:    r.End,
			Reason: fmt.Sprintf("end VLAN %d exceeds maximum %d", r.End, MaxVLANID),
		}
	}
	if r.Start > r.End {
		return &ErrInvalidVLANRange{
			Start:  r.Start,
			End:    r.End,
			Reason: "start VLAN exceeds end VLAN",
		}
	}
	return nil
}

// Overlaps returns true if this range overlaps with another range
func (r Range) Overlaps(other Range) bool {
	return r.Start <= other.End && other.Start <= r.End
}

// String returns a string representation of the range
func (r Range) String() string {
	return fmt.Sprintf("%d-%d", r.Start, r.End)
}

// IsEmpty returns true if the range has no VLANs
func (r Range) IsEmpty() bool {
	return r.Size() == 0
}

// Allocation represents a tenant's VLAN allocation
type Allocation struct {
	TenantID    string
	Range       Range
	AllocatedAt time.Time
}

// IsValid checks if the allocation is valid
func (a *Allocation) IsValid() bool {
	if a == nil {
		return false
	}
	if a.TenantID == "" {
		return false
	}
	return a.Range.Validate() == nil
}

// Contains returns true if this allocation contains the specified VLAN
func (a *Allocation) Contains(vlan uint16) bool {
	if a == nil {
		return false
	}
	return a.Range.Contains(vlan)
}

// Store is the interface for persisting VLAN allocations
type Store interface {
	// GetAllocation retrieves a tenant's VLAN allocation
	GetAllocation(ctx context.Context, tenantID string) (*Allocation, error)

	// SaveAllocation persists a VLAN allocation
	SaveAllocation(ctx context.Context, alloc *Allocation) error

	// DeleteAllocation removes a tenant's VLAN allocation
	DeleteAllocation(ctx context.Context, tenantID string) error

	// ListAllocations returns all VLAN allocations
	ListAllocations(ctx context.Context) ([]*Allocation, error)
}

// Config holds the allocator configuration
type Config struct {
	GlobalRangeStart uint16
	GlobalRangeEnd   uint16
	DefaultRangeSize uint16
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.GlobalRangeStart < MinVLANID {
		return &ErrInvalidVLANRange{
			Start:  c.GlobalRangeStart,
			End:    c.GlobalRangeEnd,
			Reason: fmt.Sprintf("global range start %d is below minimum %d", c.GlobalRangeStart, MinVLANID),
		}
	}
	if c.GlobalRangeEnd > MaxVLANID {
		return &ErrInvalidVLANRange{
			Start:  c.GlobalRangeStart,
			End:    c.GlobalRangeEnd,
			Reason: fmt.Sprintf("global range end %d exceeds maximum %d", c.GlobalRangeEnd, MaxVLANID),
		}
	}
	if c.GlobalRangeStart > c.GlobalRangeEnd {
		return &ErrInvalidVLANRange{
			Start:  c.GlobalRangeStart,
			End:    c.GlobalRangeEnd,
			Reason: "global range start exceeds end",
		}
	}
	if c.DefaultRangeSize == 0 {
		return &ErrInvalidVLANRange{
			Start:  c.GlobalRangeStart,
			End:    c.GlobalRangeEnd,
			Reason: "default range size cannot be zero",
		}
	}
	globalSize := int(c.GlobalRangeEnd-c.GlobalRangeStart) + 1
	if int(c.DefaultRangeSize) > globalSize {
		return &ErrInvalidVLANRange{
			Start:  c.GlobalRangeStart,
			End:    c.GlobalRangeEnd,
			Reason: fmt.Sprintf("default range size %d exceeds global range size %d", c.DefaultRangeSize, globalSize),
		}
	}
	return nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		GlobalRangeStart: 100,
		GlobalRangeEnd:   4000,
		DefaultRangeSize: DefaultRangeSize,
	}
}
