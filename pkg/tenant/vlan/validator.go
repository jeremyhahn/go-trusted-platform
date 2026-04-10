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
	"log/slog"
)

// Validator validates VLAN usage and access
type Validator struct {
	allocator *Allocator
	logger    *slog.Logger
}

// NewValidator creates a new VLAN validator
func NewValidator(allocator *Allocator, logger *slog.Logger) *Validator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Validator{
		allocator: allocator,
		logger:    logger,
	}
}

// ValidateTenantVLAN checks if a tenant can use a specific VLAN
// Returns nil if the tenant owns the VLAN, otherwise returns an error
func (v *Validator) ValidateTenantVLAN(ctx context.Context, tenantID string, vlan uint16) error {
	if tenantID == "" {
		return &ErrEmptyTenantID{}
	}

	// Validate VLAN is in valid IEEE 802.1Q range
	if vlan < MinVLANID || vlan > MaxVLANID {
		return &ErrVLANOutOfRange{
			VLAN: vlan,
			Min:  MinVLANID,
			Max:  MaxVLANID,
		}
	}

	// Get the tenant's allocation
	alloc, err := v.allocator.Get(ctx, tenantID)
	if err != nil {
		return err
	}

	// Check if VLAN is within the tenant's allocated range
	if !alloc.Range.Contains(vlan) {
		// Find who owns this VLAN
		owner, _ := v.allocator.GetByVLAN(ctx, vlan)
		if owner != "" {
			return &ErrVLANInUse{
				VLAN:     vlan,
				TenantID: owner,
			}
		}
		return &ErrVLANOutOfRange{
			VLAN: vlan,
			Min:  alloc.Range.Start,
			Max:  alloc.Range.End,
		}
	}

	return nil
}

// ValidatePortVLAN validates VLAN assignment for a port
// This is a convenience method that combines VLAN validation with port context
func (v *Validator) ValidatePortVLAN(ctx context.Context, tenantID string, portVLAN uint16) error {
	if tenantID == "" {
		return &ErrEmptyTenantID{}
	}

	// Validate the VLAN ID is in valid range
	if portVLAN < MinVLANID || portVLAN > MaxVLANID {
		return &ErrVLANOutOfRange{
			VLAN: portVLAN,
			Min:  MinVLANID,
			Max:  MaxVLANID,
		}
	}

	// Check if tenant has a VLAN allocation
	alloc, err := v.allocator.Get(ctx, tenantID)
	if err != nil {
		return err
	}

	// Verify the port VLAN is within tenant's allocation
	if !alloc.Range.Contains(portVLAN) {
		return &ErrVLANOutOfRange{
			VLAN: portVLAN,
			Min:  alloc.Range.Start,
			Max:  alloc.Range.End,
		}
	}

	v.logger.Debug("validated port VLAN",
		slog.String("tenant_id", tenantID),
		slog.Uint64("vlan", uint64(portVLAN)),
	)

	return nil
}

// ValidateRange validates a VLAN range configuration
func (v *Validator) ValidateRange(ctx context.Context, r Range) error {
	// Validate basic range properties
	if err := r.Validate(); err != nil {
		return err
	}

	// Check if range is within allocator's global range
	globalRange := v.allocator.GetGlobalRange()
	if r.Start < globalRange.Start {
		return &ErrVLANOutOfRange{
			VLAN: r.Start,
			Min:  globalRange.Start,
			Max:  globalRange.End,
		}
	}
	if r.End > globalRange.End {
		return &ErrVLANOutOfRange{
			VLAN: r.End,
			Min:  globalRange.Start,
			Max:  globalRange.End,
		}
	}

	return nil
}

// CheckOverlap checks if a range would overlap with existing allocations
// The tenantID parameter allows excluding a specific tenant's existing allocation
// from the overlap check (useful when expanding a tenant's range)
func (v *Validator) CheckOverlap(ctx context.Context, tenantID string, r Range) error {
	if err := r.Validate(); err != nil {
		return err
	}

	// Get all allocations
	allocations, err := v.allocator.ListAllocations(ctx)
	if err != nil {
		return err
	}

	// Check for overlaps with other tenants
	for _, alloc := range allocations {
		// Skip the tenant we're checking for (allows expanding existing allocation)
		if alloc.TenantID == tenantID {
			continue
		}

		if r.Overlaps(alloc.Range) {
			return &ErrVLANRangeOverlap{
				Existing:  alloc.Range,
				Requested: r,
			}
		}
	}

	return nil
}

// IsVLANAvailable checks if a specific VLAN is available for allocation
func (v *Validator) IsVLANAvailable(ctx context.Context, vlan uint16) bool {
	if vlan < MinVLANID || vlan > MaxVLANID {
		return false
	}

	owner, _ := v.allocator.GetByVLAN(ctx, vlan)
	return owner == ""
}

// IsRangeAvailable checks if a VLAN range is available for allocation
func (v *Validator) IsRangeAvailable(ctx context.Context, r Range) bool {
	return v.allocator.IsAvailable(ctx, r)
}

// GetTenantForVLAN returns the tenant ID that owns a specific VLAN
// Returns empty string if the VLAN is not allocated
func (v *Validator) GetTenantForVLAN(ctx context.Context, vlan uint16) (string, error) {
	return v.allocator.GetByVLAN(ctx, vlan)
}

// ValidateVLANBoundary checks if a VLAN crosses tenant boundaries
// This is useful for validating VLAN trunk configurations
func (v *Validator) ValidateVLANBoundary(ctx context.Context, tenantID string, vlans []uint16) error {
	if tenantID == "" {
		return &ErrEmptyTenantID{}
	}

	alloc, err := v.allocator.Get(ctx, tenantID)
	if err != nil {
		return err
	}

	for _, vlan := range vlans {
		if !alloc.Range.Contains(vlan) {
			// Check if it belongs to another tenant
			owner, _ := v.allocator.GetByVLAN(ctx, vlan)
			if owner != "" && owner != tenantID {
				return &ErrVLANInUse{
					VLAN:     vlan,
					TenantID: owner,
				}
			}
			return &ErrVLANOutOfRange{
				VLAN: vlan,
				Min:  alloc.Range.Start,
				Max:  alloc.Range.End,
			}
		}
	}

	return nil
}
