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

package compute

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

func TestComputeType_String(t *testing.T) {
	tests := []struct {
		name string
		ct   ComputeType
		want string
	}{
		{"VM", ComputeTypeVM, "vm"},
		{"Container", ComputeTypeContainer, "container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ct.String(); got != tt.want {
				t.Errorf("ComputeType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComputeType_IsValid(t *testing.T) {
	tests := []struct {
		name string
		ct   ComputeType
		want bool
	}{
		{"Valid VM", ComputeTypeVM, true},
		{"Valid Container", ComputeTypeContainer, true},
		{"Invalid", ComputeType("invalid"), false},
		{"Empty", ComputeType(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ct.IsValid(); got != tt.want {
				t.Errorf("ComputeType.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInstanceFilter_Matches(t *testing.T) {
	now := time.Now()
	before := now.Add(-1 * time.Hour)
	after := now.Add(1 * time.Hour)

	vmType := ComputeTypeVM
	runningState := StateRunning
	stoppedState := StateStopped
	profileID := uint64(123)

	testInstance := &Instance{
		ID:        "test-instance",
		Name:      "test-vm",
		Type:      ComputeTypeVM,
		State:     StateRunning,
		Profile:   &entities.DeviceProfile{ID: 123},
		CreatedAt: now,
	}

	tests := []struct {
		name     string
		filter   *InstanceFilter
		instance *Instance
		want     bool
	}{
		{
			name:     "Empty filter matches all",
			filter:   &InstanceFilter{},
			instance: testInstance,
			want:     true,
		},
		{
			name:     "Nil instance doesn't match",
			filter:   &InstanceFilter{},
			instance: nil,
			want:     false,
		},
		{
			name:     "Match by type",
			filter:   &InstanceFilter{Type: &vmType},
			instance: testInstance,
			want:     true,
		},
		{
			name: "No match by type",
			filter: &InstanceFilter{
				Type: func() *ComputeType { ct := ComputeTypeContainer; return &ct }(),
			},
			instance: testInstance,
			want:     false,
		},
		{
			name:     "Match by state",
			filter:   &InstanceFilter{State: &runningState},
			instance: testInstance,
			want:     true,
		},
		{
			name:     "No match by state",
			filter:   &InstanceFilter{State: &stoppedState},
			instance: testInstance,
			want:     false,
		},
		{
			name:     "Match by name",
			filter:   &InstanceFilter{Name: "test-vm"},
			instance: testInstance,
			want:     true,
		},
		{
			name:     "No match by name",
			filter:   &InstanceFilter{Name: "other-vm"},
			instance: testInstance,
			want:     false,
		},
		{
			name:     "Match by profile ID",
			filter:   &InstanceFilter{ProfileID: &profileID},
			instance: testInstance,
			want:     true,
		},
		{
			name: "No match by profile ID",
			filter: &InstanceFilter{
				ProfileID: func() *uint64 { id := uint64(999); return &id }(),
			},
			instance: testInstance,
			want:     false,
		},
		{
			name:     "Match by created after",
			filter:   &InstanceFilter{CreatedAfter: &before},
			instance: testInstance,
			want:     true,
		},
		{
			name:     "No match by created after",
			filter:   &InstanceFilter{CreatedAfter: &after},
			instance: testInstance,
			want:     false,
		},
		{
			name:     "Match by created before",
			filter:   &InstanceFilter{CreatedBefore: &after},
			instance: testInstance,
			want:     true,
		},
		{
			name:     "No match by created before",
			filter:   &InstanceFilter{CreatedBefore: &before},
			instance: testInstance,
			want:     false,
		},
		{
			name: "Multiple filters all match",
			filter: &InstanceFilter{
				Type:  &vmType,
				State: &runningState,
				Name:  "test-vm",
			},
			instance: testInstance,
			want:     true,
		},
		{
			name: "Multiple filters one doesn't match",
			filter: &InstanceFilter{
				Type:  &vmType,
				State: &stoppedState,
				Name:  "test-vm",
			},
			instance: testInstance,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.Matches(tt.instance); got != tt.want {
				t.Errorf("InstanceFilter.Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInstanceFilter_MatchesNilProfile(t *testing.T) {
	profileID := uint64(123)
	filter := &InstanceFilter{ProfileID: &profileID}

	instance := &Instance{
		ID:      "test-instance",
		Name:    "test-vm",
		Type:    ComputeTypeVM,
		State:   StateRunning,
		Profile: nil, // nil profile
	}

	if filter.Matches(instance) {
		t.Error("Filter should not match instance with nil profile when ProfileID filter is set")
	}
}
