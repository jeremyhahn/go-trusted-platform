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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

func TestVLANRange_Contains(t *testing.T) {
	tests := []struct {
		name     string
		vlanR    VLANRange
		vlan     uint16
		expected bool
	}{
		{"vlan at start of range", VLANRange{Start: 100, End: 200}, 100, true},
		{"vlan at end of range", VLANRange{Start: 100, End: 200}, 200, true},
		{"vlan in middle of range", VLANRange{Start: 100, End: 200}, 150, true},
		{"vlan below range", VLANRange{Start: 100, End: 200}, 99, false},
		{"vlan above range", VLANRange{Start: 100, End: 200}, 201, false},
		{"single vlan range contains itself", VLANRange{Start: 100, End: 100}, 100, true},
		{"single vlan range excludes others", VLANRange{Start: 100, End: 100}, 101, false},
		{"zero range", VLANRange{Start: 0, End: 0}, 0, true},
		{"max vlan in range", VLANRange{Start: 4090, End: 4094}, 4094, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.vlanR.Contains(tt.vlan); got != tt.expected {
				t.Errorf("VLANRange.Contains(%d) = %v, want %v", tt.vlan, got, tt.expected)
			}
		})
	}
}

func TestVLANRange_Size(t *testing.T) {
	tests := []struct {
		name     string
		vlanR    VLANRange
		expected int
	}{
		{"normal range", VLANRange{Start: 100, End: 199}, 100},
		{"single vlan", VLANRange{Start: 100, End: 100}, 1},
		{"zero range", VLANRange{Start: 0, End: 0}, 1},
		{"inverted range returns 0", VLANRange{Start: 200, End: 100}, 0},
		{"max range", VLANRange{Start: 1, End: 4094}, 4094},
		{"two vlans", VLANRange{Start: 100, End: 101}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.vlanR.Size(); got != tt.expected {
				t.Errorf("VLANRange.Size() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestVLANRange_Validate(t *testing.T) {
	tests := []struct {
		name      string
		vlanR     VLANRange
		expectErr bool
		errReason string
	}{
		{"valid range", VLANRange{Start: 100, End: 200}, false, ""},
		{"valid single vlan", VLANRange{Start: 100, End: 100}, false, ""},
		{"valid min boundary", VLANRange{Start: 1, End: 100}, false, ""},
		{"valid max boundary", VLANRange{Start: 4000, End: 4094}, false, ""},
		{"valid full range", VLANRange{Start: 1, End: 4094}, false, ""},
		{"start too low", VLANRange{Start: 0, End: 100}, true, "start VLAN must be between 1 and 4094"},
		{"start too high", VLANRange{Start: 4095, End: 4095}, true, "start VLAN must be between 1 and 4094"},
		{"end too low", VLANRange{Start: 1, End: 0}, true, "end VLAN must be greater than or equal to start VLAN"},
		{"end too high", VLANRange{Start: 100, End: 5000}, true, "end VLAN must be between 1 and 4094"},
		{"inverted range", VLANRange{Start: 200, End: 100}, true, "end VLAN must be greater than or equal to start VLAN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.vlanR.Validate()

			if tt.expectErr {
				if err == nil {
					t.Errorf("VLANRange.Validate() expected error, got nil")
					return
				}
				var vlanErr ErrInvalidVLANRange
				if !errors.As(err, &vlanErr) {
					t.Errorf("VLANRange.Validate() error type = %T, want ErrInvalidVLANRange", err)
				}
			} else {
				if err != nil {
					t.Errorf("VLANRange.Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVLANRange_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		vlanR    VLANRange
		expected bool
	}{
		{"zero range is empty", VLANRange{Start: 0, End: 0}, true},
		{"non-zero start is not empty", VLANRange{Start: 1, End: 0}, false},
		{"non-zero end is not empty", VLANRange{Start: 0, End: 1}, false},
		{"normal range is not empty", VLANRange{Start: 100, End: 200}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.vlanR.IsEmpty(); got != tt.expected {
				t.Errorf("VLANRange.IsEmpty() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestVLANRange_Overlaps(t *testing.T) {
	tests := []struct {
		name     string
		range1   VLANRange
		range2   VLANRange
		expected bool
	}{
		{"identical ranges", VLANRange{Start: 100, End: 200}, VLANRange{Start: 100, End: 200}, true},
		{"range2 inside range1", VLANRange{Start: 100, End: 200}, VLANRange{Start: 120, End: 180}, true},
		{"range1 inside range2", VLANRange{Start: 120, End: 180}, VLANRange{Start: 100, End: 200}, true},
		{"overlapping at end", VLANRange{Start: 100, End: 150}, VLANRange{Start: 150, End: 200}, true},
		{"overlapping at start", VLANRange{Start: 150, End: 200}, VLANRange{Start: 100, End: 150}, true},
		{"partial overlap", VLANRange{Start: 100, End: 150}, VLANRange{Start: 125, End: 200}, true},
		{"no overlap range2 after", VLANRange{Start: 100, End: 150}, VLANRange{Start: 151, End: 200}, false},
		{"no overlap range2 before", VLANRange{Start: 151, End: 200}, VLANRange{Start: 100, End: 150}, false},
		{"adjacent ranges no overlap", VLANRange{Start: 100, End: 149}, VLANRange{Start: 150, End: 200}, false},
		{"single vlan overlap", VLANRange{Start: 100, End: 100}, VLANRange{Start: 100, End: 100}, true},
		{"single vlan no overlap", VLANRange{Start: 100, End: 100}, VLANRange{Start: 101, End: 101}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.range1.Overlaps(tt.range2); got != tt.expected {
				t.Errorf("VLANRange.Overlaps() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFromIAM_NilInput(t *testing.T) {
	result := FromIAM(nil)
	if result != nil {
		t.Errorf("FromIAM(nil) = %v, want nil", result)
	}
}

func TestFromIAM_ValidInput(t *testing.T) {
	now := time.Now()
	proto := &iam.Tenant{
		ID:        "tenant-123",
		Name:      "test-tenant",
		CreatedAt: now,
		UpdatedAt: now,
	}

	result := FromIAM(proto)

	if result == nil {
		t.Fatal("FromIAM() returned nil for valid input")
	}
	if result.ID != proto.ID {
		t.Errorf("FromIAM().ID = %q, want %q", result.ID, proto.ID)
	}
	if result.Name != proto.Name {
		t.Errorf("FromIAM().Name = %q, want %q", result.Name, proto.Name)
	}
	if result.DisplayName != proto.Name {
		t.Errorf("FromIAM().DisplayName = %q, want %q", result.DisplayName, proto.Name)
	}
	if result.State != StateCreated {
		t.Errorf("FromIAM().State = %q, want %q", result.State, StateCreated)
	}
	if result.Labels == nil {
		t.Error("FromIAM().Labels should be initialized")
	}
	if result.Annotations == nil {
		t.Error("FromIAM().Annotations should be initialized")
	}
}

func TestFromIAM_NilTimestamps(t *testing.T) {
	proto := &iam.Tenant{
		ID:        "tenant-123",
		Name:      "test-tenant",
		CreatedAt: time.Time{},
		UpdatedAt: time.Time{},
	}

	result := FromIAM(proto)

	if result == nil {
		t.Fatal("FromIAM() returned nil for valid input")
	}
	if !result.CreatedAt.IsZero() {
		t.Errorf("FromIAM().CreatedAt should be zero time when nil")
	}
	if !result.UpdatedAt.IsZero() {
		t.Errorf("FromIAM().UpdatedAt should be zero time when nil")
	}
}

func TestTenantEntity_ToProto_NilReceiver(t *testing.T) {
	var entity *TenantEntity
	result := entity.ToIAM()
	if result != nil {
		t.Errorf("ToProto() on nil receiver = %v, want nil", result)
	}
}

func TestTenantEntity_ToProto_ValidEntity(t *testing.T) {
	now := time.Now()
	entity := &TenantEntity{
		ID:        "tenant-123",
		Name:      "test-tenant",
		CreatedAt: now,
		UpdatedAt: now,
	}

	result := entity.ToIAM()

	if result == nil {
		t.Fatal("ToProto() returned nil for valid entity")
	}
	if result.ID != entity.ID {
		t.Errorf("ToProto().Id = %q, want %q", result.ID, entity.ID)
	}
	if result.Name != entity.Name {
		t.Errorf("ToProto().Name = %q, want %q", result.Name, entity.Name)
	}
	if result.CreatedAt.IsZero() {
		t.Error("ToProto().CreatedAt should not be zero")
	}
	if result.UpdatedAt.IsZero() {
		t.Error("ToProto().UpdatedAt should not be zero")
	}
}

func TestTenantEntity_Clone_NilReceiver(t *testing.T) {
	var entity *TenantEntity
	result := entity.Clone()
	if result != nil {
		t.Errorf("Clone() on nil receiver = %v, want nil", result)
	}
}

func TestTenantEntity_Clone_ValidEntity(t *testing.T) {
	now := time.Now()
	deletedAt := now.Add(-time.Hour)
	entity := &TenantEntity{
		ID:           "tenant-123",
		Name:         "test-tenant",
		DisplayName:  "Test Tenant",
		State:        StateActive,
		OVSBridge:    "br-tenant-test",
		VLANRange:    VLANRange{Start: 100, End: 199},
		DEKPath:      "/tenant/tenant-123/default",
		ComputeQuota: ComputeQuota{MaxVMs: 10, UsedVMs: 5},
		NetworkQuota: NetworkQuota{MaxBridges: 5, UsedBridges: 2},
		StorageQuota: StorageQuota{MaxVolumesGB: 100, UsedVolumesGB: 50},
		Labels:       map[string]string{"env": "prod"},
		Annotations:  map[string]string{"note": "test"},
		CreatedAt:    now,
		UpdatedAt:    now,
		DeletedAt:    &deletedAt,
	}

	clone := entity.Clone()

	if clone == nil {
		t.Fatal("Clone() returned nil for valid entity")
	}
	if clone == entity {
		t.Error("Clone() should return a different pointer")
	}
	if clone.ID != entity.ID {
		t.Errorf("Clone().ID = %q, want %q", clone.ID, entity.ID)
	}
	if clone.Name != entity.Name {
		t.Errorf("Clone().Name = %q, want %q", clone.Name, entity.Name)
	}
	if clone.State != entity.State {
		t.Errorf("Clone().State = %q, want %q", clone.State, entity.State)
	}
	if clone.VLANRange != entity.VLANRange {
		t.Errorf("Clone().VLANRange = %v, want %v", clone.VLANRange, entity.VLANRange)
	}
}

func TestTenantEntity_Clone_DeepCopyMaps(t *testing.T) {
	entity := &TenantEntity{
		ID:          "tenant-123",
		Name:        "test-tenant",
		State:       StateActive,
		Labels:      map[string]string{"key1": "value1"},
		Annotations: map[string]string{"anno1": "value1"},
	}

	clone := entity.Clone()

	// Modify original maps
	entity.Labels["key2"] = "value2"
	entity.Annotations["anno2"] = "value2"

	// Clone maps should not be affected
	if _, exists := clone.Labels["key2"]; exists {
		t.Error("Clone() should deep copy Labels map")
	}
	if _, exists := clone.Annotations["anno2"]; exists {
		t.Error("Clone() should deep copy Annotations map")
	}
}

func TestTenantEntity_Clone_DeepCopyDeletedAt(t *testing.T) {
	now := time.Now()
	entity := &TenantEntity{
		ID:        "tenant-123",
		Name:      "test-tenant",
		State:     StateDeleted,
		DeletedAt: &now,
	}

	clone := entity.Clone()

	if clone.DeletedAt == entity.DeletedAt {
		t.Error("Clone() should deep copy DeletedAt pointer")
	}
	if *clone.DeletedAt != *entity.DeletedAt {
		t.Error("Clone() should preserve DeletedAt value")
	}
}

func TestTenantEntity_Clone_NilMaps(t *testing.T) {
	entity := &TenantEntity{
		ID:          "tenant-123",
		Name:        "test-tenant",
		State:       StateActive,
		Labels:      nil,
		Annotations: nil,
	}

	clone := entity.Clone()

	if clone.Labels != nil {
		t.Error("Clone() should preserve nil Labels")
	}
	if clone.Annotations != nil {
		t.Error("Clone() should preserve nil Annotations")
	}
}

func TestTenantEntity_Validate_Success(t *testing.T) {
	entity := &TenantEntity{
		ID:        "tenant-123",
		Name:      "test-tenant",
		State:     StateActive,
		VLANRange: VLANRange{Start: 100, End: 199},
	}

	if err := entity.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestTenantEntity_Validate_EmptyVLANRange(t *testing.T) {
	entity := &TenantEntity{
		ID:        "tenant-123",
		Name:      "test-tenant",
		State:     StateActive,
		VLANRange: VLANRange{}, // Empty range is valid
	}

	if err := entity.Validate(); err != nil {
		t.Errorf("Validate() with empty VLAN range unexpected error: %v", err)
	}
}

func TestTenantEntity_Validate_Errors(t *testing.T) {
	tests := []struct {
		name      string
		entity    *TenantEntity
		expectErr error
	}{
		{
			name:      "empty ID",
			entity:    &TenantEntity{ID: "", Name: "test", State: StateActive},
			expectErr: ErrInvalidRequest{},
		},
		{
			name:      "empty name",
			entity:    &TenantEntity{ID: "123", Name: "", State: StateActive},
			expectErr: ErrInvalidRequest{},
		},
		{
			name:      "invalid state",
			entity:    &TenantEntity{ID: "123", Name: "test", State: State("invalid")},
			expectErr: ErrInvalidState{},
		},
		{
			name:      "invalid VLAN range",
			entity:    &TenantEntity{ID: "123", Name: "test", State: StateActive, VLANRange: VLANRange{Start: 200, End: 100}},
			expectErr: ErrInvalidVLANRange{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entity.Validate()
			if err == nil {
				t.Error("Validate() expected error, got nil")
				return
			}

			switch tt.expectErr.(type) {
			case ErrInvalidRequest:
				var e ErrInvalidRequest
				if !errors.As(err, &e) {
					t.Errorf("Validate() error type = %T, want ErrInvalidRequest", err)
				}
			case ErrInvalidState:
				var e ErrInvalidState
				if !errors.As(err, &e) {
					t.Errorf("Validate() error type = %T, want ErrInvalidState", err)
				}
			case ErrInvalidVLANRange:
				var e ErrInvalidVLANRange
				if !errors.As(err, &e) {
					t.Errorf("Validate() error type = %T, want ErrInvalidVLANRange", err)
				}
			}
		})
	}
}

func TestTenantEntity_IsDeleted(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		entity   *TenantEntity
		expected bool
	}{
		{
			name:     "deleted state",
			entity:   &TenantEntity{State: StateDeleted},
			expected: true,
		},
		{
			name:     "with deleted timestamp",
			entity:   &TenantEntity{State: StateActive, DeletedAt: &now},
			expected: true,
		},
		{
			name:     "active state no timestamp",
			entity:   &TenantEntity{State: StateActive, DeletedAt: nil},
			expected: false,
		},
		{
			name:     "created state",
			entity:   &TenantEntity{State: StateCreated},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entity.IsDeleted(); got != tt.expected {
				t.Errorf("IsDeleted() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTenantEntity_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		entity   *TenantEntity
		expected bool
	}{
		{"active state", &TenantEntity{State: StateActive}, true},
		{"created state", &TenantEntity{State: StateCreated}, false},
		{"suspended state", &TenantEntity{State: StateSuspended}, false},
		{"deleting state", &TenantEntity{State: StateDeleting}, false},
		{"deleted state", &TenantEntity{State: StateDeleted}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entity.IsActive(); got != tt.expected {
				t.Errorf("IsActive() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTenantEntity_CanCreateResources(t *testing.T) {
	tests := []struct {
		name     string
		entity   *TenantEntity
		expected bool
	}{
		{"active can create", &TenantEntity{State: StateActive}, true},
		{"created cannot create", &TenantEntity{State: StateCreated}, false},
		{"suspended cannot create", &TenantEntity{State: StateSuspended}, false},
		{"deleting cannot create", &TenantEntity{State: StateDeleting}, false},
		{"deleted cannot create", &TenantEntity{State: StateDeleted}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entity.CanCreateResources(); got != tt.expected {
				t.Errorf("CanCreateResources() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTenantEntity_CanDeleteResources(t *testing.T) {
	tests := []struct {
		name     string
		entity   *TenantEntity
		expected bool
	}{
		{"active can delete", &TenantEntity{State: StateActive}, true},
		{"deleting can delete", &TenantEntity{State: StateDeleting}, true},
		{"created cannot delete", &TenantEntity{State: StateCreated}, false},
		{"suspended cannot delete", &TenantEntity{State: StateSuspended}, false},
		{"deleted cannot delete", &TenantEntity{State: StateDeleted}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entity.CanDeleteResources(); got != tt.expected {
				t.Errorf("CanDeleteResources() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTenantEntity_SetState_ValidTransitions(t *testing.T) {
	tests := []struct {
		name     string
		from     State
		to       State
		checkDel bool
	}{
		{"created to active", StateCreated, StateActive, false},
		{"active to suspended", StateActive, StateSuspended, false},
		{"suspended to active", StateSuspended, StateActive, false},
		{"active to deleting", StateActive, StateDeleting, false},
		{"deleting to deleted", StateDeleting, StateDeleted, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entity := &TenantEntity{
				ID:    "tenant-123",
				Name:  "test",
				State: tt.from,
			}
			beforeUpdate := entity.UpdatedAt

			err := entity.SetState(tt.to)

			if err != nil {
				t.Errorf("SetState(%s) unexpected error: %v", tt.to, err)
			}
			if entity.State != tt.to {
				t.Errorf("SetState(%s) state = %s, want %s", tt.to, entity.State, tt.to)
			}
			if !entity.UpdatedAt.After(beforeUpdate) && entity.UpdatedAt != beforeUpdate {
				t.Error("SetState should update UpdatedAt")
			}
			if tt.checkDel && entity.DeletedAt == nil {
				t.Error("SetState to deleted should set DeletedAt")
			}
		})
	}
}

func TestTenantEntity_SetState_InvalidTransitions(t *testing.T) {
	tests := []struct {
		name string
		from State
		to   State
	}{
		{"created to deleted", StateCreated, StateDeleted},
		{"active to created", StateActive, StateCreated},
		{"deleted to active", StateDeleted, StateActive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entity := &TenantEntity{
				ID:    "tenant-123",
				Name:  "test",
				State: tt.from,
			}

			err := entity.SetState(tt.to)

			if err == nil {
				t.Errorf("SetState(%s) expected error for invalid transition", tt.to)
				return
			}

			var transErr ErrInvalidTransition
			if !errors.As(err, &transErr) {
				t.Errorf("SetState(%s) error type = %T, want ErrInvalidTransition", tt.to, err)
			}
		})
	}
}

func TestTenantEntity_SetState_SameState(t *testing.T) {
	entity := &TenantEntity{
		ID:    "tenant-123",
		Name:  "test",
		State: StateActive,
	}

	err := entity.SetState(StateActive)

	if err != nil {
		t.Errorf("SetState with same state should succeed: %v", err)
	}
}

func TestTenantEntity_GetLabel(t *testing.T) {
	tests := []struct {
		name     string
		entity   *TenantEntity
		key      string
		expected string
	}{
		{
			name:     "existing label",
			entity:   &TenantEntity{Labels: map[string]string{"env": "prod"}},
			key:      "env",
			expected: "prod",
		},
		{
			name:     "non-existing label",
			entity:   &TenantEntity{Labels: map[string]string{"env": "prod"}},
			key:      "tier",
			expected: "",
		},
		{
			name:     "nil labels map",
			entity:   &TenantEntity{Labels: nil},
			key:      "env",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entity.GetLabel(tt.key); got != tt.expected {
				t.Errorf("GetLabel(%q) = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}

func TestTenantEntity_SetLabel(t *testing.T) {
	t.Run("set on nil map", func(t *testing.T) {
		entity := &TenantEntity{Labels: nil}
		entity.SetLabel("env", "prod")

		if entity.Labels == nil {
			t.Error("SetLabel should initialize Labels map")
		}
		if entity.Labels["env"] != "prod" {
			t.Errorf("SetLabel: Labels[env] = %q, want %q", entity.Labels["env"], "prod")
		}
	})

	t.Run("set on existing map", func(t *testing.T) {
		entity := &TenantEntity{Labels: map[string]string{"existing": "value"}}
		entity.SetLabel("new", "value")

		if entity.Labels["new"] != "value" {
			t.Errorf("SetLabel: Labels[new] = %q, want %q", entity.Labels["new"], "value")
		}
		if entity.Labels["existing"] != "value" {
			t.Error("SetLabel should preserve existing labels")
		}
	})

	t.Run("updates UpdatedAt", func(t *testing.T) {
		entity := &TenantEntity{}
		beforeUpdate := entity.UpdatedAt
		entity.SetLabel("key", "value")

		if !entity.UpdatedAt.After(beforeUpdate) && entity.UpdatedAt.Equal(beforeUpdate) {
			t.Error("SetLabel should update UpdatedAt")
		}
	})
}

func TestTenantEntity_GetAnnotation(t *testing.T) {
	tests := []struct {
		name     string
		entity   *TenantEntity
		key      string
		expected string
	}{
		{
			name:     "existing annotation",
			entity:   &TenantEntity{Annotations: map[string]string{"note": "test"}},
			key:      "note",
			expected: "test",
		},
		{
			name:     "non-existing annotation",
			entity:   &TenantEntity{Annotations: map[string]string{"note": "test"}},
			key:      "other",
			expected: "",
		},
		{
			name:     "nil annotations map",
			entity:   &TenantEntity{Annotations: nil},
			key:      "note",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entity.GetAnnotation(tt.key); got != tt.expected {
				t.Errorf("GetAnnotation(%q) = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}

func TestTenantEntity_SetAnnotation(t *testing.T) {
	t.Run("set on nil map", func(t *testing.T) {
		entity := &TenantEntity{Annotations: nil}
		entity.SetAnnotation("note", "value")

		if entity.Annotations == nil {
			t.Error("SetAnnotation should initialize Annotations map")
		}
		if entity.Annotations["note"] != "value" {
			t.Errorf("SetAnnotation: Annotations[note] = %q, want %q", entity.Annotations["note"], "value")
		}
	})

	t.Run("set on existing map", func(t *testing.T) {
		entity := &TenantEntity{Annotations: map[string]string{"existing": "value"}}
		entity.SetAnnotation("new", "value")

		if entity.Annotations["new"] != "value" {
			t.Errorf("SetAnnotation: Annotations[new] = %q, want %q", entity.Annotations["new"], "value")
		}
		if entity.Annotations["existing"] != "value" {
			t.Error("SetAnnotation should preserve existing annotations")
		}
	})

	t.Run("updates UpdatedAt", func(t *testing.T) {
		entity := &TenantEntity{}
		beforeUpdate := entity.UpdatedAt
		entity.SetAnnotation("key", "value")

		if !entity.UpdatedAt.After(beforeUpdate) && entity.UpdatedAt.Equal(beforeUpdate) {
			t.Error("SetAnnotation should update UpdatedAt")
		}
	})
}

func TestFromIAM_ToProto_RoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Microsecond) // Truncate for timestamp precision
	original := &iam.Tenant{
		ID:        "tenant-roundtrip",
		Name:      "roundtrip-test",
		CreatedAt: now,
		UpdatedAt: now,
	}

	entity := FromIAM(original)
	result := entity.ToIAM()

	if result.ID != original.ID {
		t.Errorf("RoundTrip Id = %q, want %q", result.ID, original.ID)
	}
	if result.Name != original.Name {
		t.Errorf("RoundTrip Name = %q, want %q", result.Name, original.Name)
	}
}

// Tests for DEKPath and DEKHandle

func TestBuildDEKPath(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		expected string
	}{
		{"simple tenant ID", "tenant-123", "/tenant/tenant-123/default"},
		{"UUID tenant ID", "550e8400-e29b-41d4-a716-446655440000", "/tenant/550e8400-e29b-41d4-a716-446655440000/default"},
		{"empty tenant ID", "", "/tenant//default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildDEKPath(tt.tenantID)
			if got != tt.expected {
				t.Errorf("BuildDEKPath(%q) = %q, want %q", tt.tenantID, got, tt.expected)
			}
		})
	}
}

func TestTenantEntity_DEKHandle(t *testing.T) {
	tests := []struct {
		name     string
		dekPath  string
		wantZero bool
	}{
		{"empty path returns 0", "", true},
		{"standard path returns hash", "/tenant/tenant-123/default", false},
		{"numeric path extracts number", "/tenant/12345/default", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entity := &TenantEntity{DEKPath: tt.dekPath}
			got := entity.DEKHandle()
			if tt.wantZero && got != 0 {
				t.Errorf("DEKHandle() = %d, want 0", got)
			}
			if !tt.wantZero && got == 0 {
				t.Errorf("DEKHandle() = 0, want non-zero")
			}
		})
	}
}

func TestTenantEntity_DEKHandle_Consistency(t *testing.T) {
	// Ensure same path always produces same handle
	entity := &TenantEntity{DEKPath: "/tenant/test-tenant/default"}
	handle1 := entity.DEKHandle()
	handle2 := entity.DEKHandle()

	if handle1 != handle2 {
		t.Errorf("DEKHandle() not consistent: got %d and %d", handle1, handle2)
	}

	// Different paths should produce different handles
	entity2 := &TenantEntity{DEKPath: "/tenant/other-tenant/default"}
	handle3 := entity2.DEKHandle()

	if handle1 == handle3 {
		t.Error("Expected different handles for different paths")
	}
}

func TestTenantEntity_HasDEK(t *testing.T) {
	tests := []struct {
		name     string
		dekPath  string
		expected bool
	}{
		{"with DEK path", "/tenant/tenant-123/default", true},
		{"empty DEK path", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entity := &TenantEntity{DEKPath: tt.dekPath}
			if got := entity.HasDEK(); got != tt.expected {
				t.Errorf("HasDEK() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTenantEntity_Clone_DEKPath(t *testing.T) {
	entity := &TenantEntity{
		ID:      "tenant-123",
		Name:    "test-tenant",
		State:   StateActive,
		DEKPath: "/tenant/tenant-123/default",
	}

	clone := entity.Clone()

	if clone.DEKPath != entity.DEKPath {
		t.Errorf("Clone().DEKPath = %q, want %q", clone.DEKPath, entity.DEKPath)
	}

	// Modifying clone should not affect original
	clone.DEKPath = "/different/path"
	if entity.DEKPath == clone.DEKPath {
		t.Error("Modifying clone affected original")
	}
}

func TestHashStringToUint32(t *testing.T) {
	// Test that hash function is deterministic
	hash1 := hashStringToUint32("test-string")
	hash2 := hashStringToUint32("test-string")
	if hash1 != hash2 {
		t.Errorf("Hash not deterministic: %d != %d", hash1, hash2)
	}

	// Different strings should produce different hashes
	hash3 := hashStringToUint32("different-string")
	if hash1 == hash3 {
		t.Error("Expected different hashes for different strings")
	}

	// Empty string should produce a hash
	hashEmpty := hashStringToUint32("")
	if hashEmpty == 0 {
		t.Error("Empty string should produce non-zero hash")
	}
}
