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

func TestNetworkAttachment(t *testing.T) {
	attachment := NetworkAttachment{
		PortName:   "test-port",
		BridgeName: "br-int",
		VLAN:       100,
		MACAddress: "52:54:00:12:34:56",
		IPAddress:  "192.168.1.100",
		AttachedAt: time.Now(),
	}

	if attachment.PortName != "test-port" {
		t.Errorf("Expected PortName test-port, got %s", attachment.PortName)
	}
	if attachment.BridgeName != "br-int" {
		t.Errorf("Expected BridgeName br-int, got %s", attachment.BridgeName)
	}
	if attachment.VLAN != 100 {
		t.Errorf("Expected VLAN 100, got %d", attachment.VLAN)
	}
}

func TestInstance(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID:   123,
		Name: "test-profile",
	}

	config := &InstanceConfig{
		Memory:   4096,
		CPUs:     4,
		DiskPath: "/var/lib/compute/disk.qcow2",
		DiskSize: "20G",
	}

	instance := &Instance{
		ID:      "test-instance",
		Name:    "test-vm",
		Type:    ComputeTypeVM,
		State:   StateRunning,
		Profile: profile,
		Config:  config,
		NetworkAttachments: []NetworkAttachment{
			{
				PortName:   "test-port",
				BridgeName: "br-int",
				VLAN:       100,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata: map[string]string{
			"owner": "test-user",
		},
		PID: 12345,
	}

	if instance.ID != "test-instance" {
		t.Errorf("Expected ID test-instance, got %s", instance.ID)
	}
	if instance.Type != ComputeTypeVM {
		t.Errorf("Expected Type VM, got %s", instance.Type)
	}
	if instance.State != StateRunning {
		t.Errorf("Expected State Running, got %s", instance.State)
	}
	if instance.Profile.ID != 123 {
		t.Errorf("Expected Profile ID 123, got %d", instance.Profile.ID)
	}
	if instance.Config.Memory != 4096 {
		t.Errorf("Expected Memory 4096, got %d", instance.Config.Memory)
	}
	if len(instance.NetworkAttachments) != 1 {
		t.Errorf("Expected 1 network attachment, got %d", len(instance.NetworkAttachments))
	}
	if instance.PID != 12345 {
		t.Errorf("Expected PID 12345, got %d", instance.PID)
	}
}

func TestInstanceConfig(t *testing.T) {
	config := &InstanceConfig{
		Memory:      4096,
		CPUs:        4,
		DiskPath:    "/var/lib/compute/disk.qcow2",
		DiskSize:    "20G",
		WorkDir:     "/var/lib/compute/work",
		SecureBoot:  true,
		EnableKVM:   true,
		TPMEnabled:  true,
		NetworkMode: "bridge",
		MACAddress:  "52:54:00:12:34:56",
		BootMode:    "boot",
		ISOPath:     "/path/to/installer.iso",
		AdditionalDisks: []string{
			"/var/lib/compute/data.qcow2",
		},
		Environment: map[string]string{
			"ENV_VAR": "value",
		},
	}

	if config.Memory != 4096 {
		t.Errorf("Expected Memory 4096, got %d", config.Memory)
	}
	if config.CPUs != 4 {
		t.Errorf("Expected CPUs 4, got %d", config.CPUs)
	}
	if !config.SecureBoot {
		t.Error("Expected SecureBoot to be true")
	}
	if !config.EnableKVM {
		t.Error("Expected EnableKVM to be true")
	}
	if !config.TPMEnabled {
		t.Error("Expected TPMEnabled to be true")
	}
	if len(config.AdditionalDisks) != 1 {
		t.Errorf("Expected 1 additional disk, got %d", len(config.AdditionalDisks))
	}
	if config.Environment["ENV_VAR"] != "value" {
		t.Errorf("Expected ENV_VAR=value, got %s", config.Environment["ENV_VAR"])
	}
}
