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

package tenant

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// PlatformRecordKey is the IAM tenant metadata key that holds the platform's
// own part of a tenant - lifecycle state, quotas, labels and annotations - for
// which the IAM tenant has no field (docs/tenant/engineering.md §6).
const PlatformRecordKey = "platform.tenant"

// platformRecord is the platform-owned part of a tenant, stored as one JSON
// value under PlatformRecordKey so an update always replaces it whole.
type platformRecord struct {
	DisplayName  string            `json:"display_name,omitempty"`
	State        State             `json:"state"`
	ComputeQuota ComputeQuota      `json:"compute_quota"`
	NetworkQuota NetworkQuota      `json:"network_quota"`
	StorageQuota StorageQuota      `json:"storage_quota"`
	Labels       map[string]string `json:"labels,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// TenantEntity represents a tenant with platform-specific extensions.
// It extends the QuicBaaS IAM Tenant with DEK management and resource
// quotas. It carries no network identity: the routing domain of a tenant is a
// VRF (plan §5.3), not a VLAN range or an OVS bridge.
type TenantEntity struct {
	// From QuicBaaS IAM
	ID          string
	Name        string
	DisplayName string
	State       State

	// Platform-specific extensions
	DEKPath string // KMS DEK path: /tenant/{tenant-id}/default

	// Quotas
	ComputeQuota ComputeQuota
	NetworkQuota NetworkQuota
	StorageQuota StorageQuota

	// Metadata
	Labels      map[string]string
	Annotations map[string]string

	// Timestamps
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// FromIAM converts a QuicBaaS IAM SDK Tenant to a TenantEntity.
// Platform-specific fields are initialized with defaults.
func FromIAM(t *iam.Tenant) *TenantEntity {
	if t == nil {
		return nil
	}

	entity := &TenantEntity{
		ID:          t.ID,
		Name:        t.Name,
		DisplayName: t.DisplayName,
		State:       StateCreated,
		Labels:      make(map[string]string),
		Annotations: make(map[string]string),
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}

	// Use Name as DisplayName fallback
	if entity.DisplayName == "" {
		entity.DisplayName = t.Name
	}

	return entity
}

// ToIAM converts a TenantEntity to a QuicBaaS IAM SDK Tenant.
// Note: Platform-specific fields are not included in the SDK type.
func (e *TenantEntity) ToIAM() *iam.Tenant {
	if e == nil {
		return nil
	}

	return &iam.Tenant{
		ID:          e.ID,
		Name:        e.Name,
		DisplayName: e.DisplayName,
		CreatedAt:   e.CreatedAt,
		UpdatedAt:   e.UpdatedAt,
	}
}

// platformMetadata encodes the entity's platform record as the IAM tenant
// metadata that persists it.
func (e *TenantEntity) platformMetadata() (map[string]string, error) {
	data, err := json.Marshal(platformRecord{
		DisplayName:  e.DisplayName,
		State:        e.State,
		ComputeQuota: e.ComputeQuota,
		NetworkQuota: e.NetworkQuota,
		StorageQuota: e.StorageQuota,
		Labels:       e.Labels,
		Annotations:  e.Annotations,
	})
	if err != nil {
		return nil, err
	}
	return map[string]string{PlatformRecordKey: string(data)}, nil
}

// restorePlatformRecord applies the platform record an IAM tenant carries. A
// tenant without one was created outside the tenant manager: it keeps the
// defaults FromIAM gave it, suspended when IAM says so.
func (e *TenantEntity) restorePlatformRecord(t *iam.Tenant) error {
	data, ok := t.Metadata[PlatformRecordKey]
	if !ok {
		if t.Status == iam.TenantStatusSuspended {
			e.State = StateSuspended
		}
		return nil
	}

	var record platformRecord
	if err := json.Unmarshal([]byte(data), &record); err != nil {
		return err
	}
	if !record.State.IsValid() {
		return ErrInvalidState{Current: record.State}
	}

	if record.DisplayName != "" {
		e.DisplayName = record.DisplayName
	}
	e.State = record.State
	e.ComputeQuota = record.ComputeQuota
	e.NetworkQuota = record.NetworkQuota
	e.StorageQuota = record.StorageQuota
	if record.Labels != nil {
		e.Labels = record.Labels
	}
	if record.Annotations != nil {
		e.Annotations = record.Annotations
	}
	return nil
}

// iamStatus is the IAM tenant status that mirrors the lifecycle state. IAM has
// no created or deleting status, so those states leave it unchanged (nil).
func (e *TenantEntity) iamStatus() *iam.TenantStatus {
	var status iam.TenantStatus
	switch e.State {
	case StateActive:
		status = iam.TenantStatusActive
	case StateSuspended:
		status = iam.TenantStatusSuspended
	default:
		return nil
	}
	return &status
}

// Clone creates a deep copy of the TenantEntity.
func (e *TenantEntity) Clone() *TenantEntity {
	if e == nil {
		return nil
	}

	clone := &TenantEntity{
		ID:           e.ID,
		Name:         e.Name,
		DisplayName:  e.DisplayName,
		State:        e.State,
		DEKPath:      e.DEKPath,
		ComputeQuota: e.ComputeQuota,
		NetworkQuota: e.NetworkQuota,
		StorageQuota: e.StorageQuota,
		CreatedAt:    e.CreatedAt,
		UpdatedAt:    e.UpdatedAt,
	}

	// Deep copy Labels
	if e.Labels != nil {
		clone.Labels = make(map[string]string, len(e.Labels))
		for k, v := range e.Labels {
			clone.Labels[k] = v
		}
	}

	// Deep copy Annotations
	if e.Annotations != nil {
		clone.Annotations = make(map[string]string, len(e.Annotations))
		for k, v := range e.Annotations {
			clone.Annotations[k] = v
		}
	}

	// Deep copy DeletedAt
	if e.DeletedAt != nil {
		deletedAt := *e.DeletedAt
		clone.DeletedAt = &deletedAt
	}

	return clone
}

// Validate validates the TenantEntity fields.
func (e *TenantEntity) Validate() error {
	if e.ID == "" {
		return ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	if e.Name == "" {
		return ErrInvalidRequest{Reason: "tenant name is required"}
	}

	if !e.State.IsValid() {
		return ErrInvalidState{Current: e.State}
	}

	return nil
}

// IsDeleted checks if the tenant has been deleted.
func (e *TenantEntity) IsDeleted() bool {
	return e.State == StateDeleted || e.DeletedAt != nil
}

// IsActive checks if the tenant is in an active state.
func (e *TenantEntity) IsActive() bool {
	return e.State == StateActive
}

// CanCreateResources checks if resources can be created for this tenant.
func (e *TenantEntity) CanCreateResources() bool {
	return e.State.AllowsResourceCreation()
}

// CanDeleteResources checks if resources can be deleted for this tenant.
func (e *TenantEntity) CanDeleteResources() bool {
	return e.State.AllowsResourceDeletion()
}

// SetState transitions the tenant to a new state.
// Returns an error if the transition is not allowed.
func (e *TenantEntity) SetState(newState State) error {
	if !e.State.CanTransitionTo(newState) {
		return ErrInvalidTransition{
			From: e.State,
			To:   newState,
		}
	}

	e.State = newState
	e.UpdatedAt = time.Now()

	if newState == StateDeleted {
		now := time.Now()
		e.DeletedAt = &now
	}

	return nil
}

// GetLabel returns the value of a label or empty string if not found.
func (e *TenantEntity) GetLabel(key string) string {
	if e.Labels == nil {
		return ""
	}
	return e.Labels[key]
}

// SetLabel sets a label on the tenant.
func (e *TenantEntity) SetLabel(key, value string) {
	if e.Labels == nil {
		e.Labels = make(map[string]string)
	}
	e.Labels[key] = value
	e.UpdatedAt = time.Now()
}

// GetAnnotation returns the value of an annotation or empty string if not found.
func (e *TenantEntity) GetAnnotation(key string) string {
	if e.Annotations == nil {
		return ""
	}
	return e.Annotations[key]
}

// SetAnnotation sets an annotation on the tenant.
func (e *TenantEntity) SetAnnotation(key, value string) {
	if e.Annotations == nil {
		e.Annotations = make(map[string]string)
	}
	e.Annotations[key] = value
	e.UpdatedAt = time.Now()
}

// DEKHandle extracts a numeric handle from the DEK path for backward compatibility.
// Returns 0 if the path is empty or cannot be parsed.
// The handle is extracted from the path suffix if it contains a numeric component,
// otherwise it returns a hash-based identifier derived from the path.
func (e *TenantEntity) DEKHandle() uint32 {
	if e.DEKPath == "" {
		return 0
	}

	// Try to extract numeric suffix from path (e.g., "/tenant/123/default" -> 123)
	parts := strings.Split(e.DEKPath, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == "" {
			continue
		}
		if n, err := strconv.ParseUint(parts[i], 10, 32); err == nil {
			return uint32(n)
		}
		// If we find a non-numeric part that's not empty, try to find tenant ID
		// Format: /tenant/{tenant-id}/default
		if i > 0 && parts[i-1] == "tenant" {
			// Return a hash of the tenant ID for backward compat
			return hashStringToUint32(parts[i])
		}
	}

	// Fallback: hash the entire path
	return hashStringToUint32(e.DEKPath)
}

// hashStringToUint32 creates a simple hash of a string for backward compatibility.
func hashStringToUint32(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// HasDEK returns true if the tenant has a DEK configured.
func (e *TenantEntity) HasDEK() bool {
	return e.DEKPath != ""
}

// BuildDEKPath constructs the standard DEK path for a tenant.
// The path follows the convention: /tenant/{tenant-id}/default
func BuildDEKPath(tenantID string) string {
	return "/tenant/" + tenantID + "/default"
}
