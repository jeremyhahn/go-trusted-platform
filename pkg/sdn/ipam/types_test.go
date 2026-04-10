// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"net/netip"
	"testing"
	"time"
)

func TestAllocationStatus_String(t *testing.T) {
	tests := []struct {
		name   string
		status AllocationStatus
		want   string
	}{
		{"active", AllocationStatusActive, "active"},
		{"expired", AllocationStatusExpired, "expired"},
		{"released", AllocationStatusReleased, "released"},
		{"reserved", AllocationStatusReserved, "reserved"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Errorf("AllocationStatus.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllocationStatus_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		status AllocationStatus
		want   bool
	}{
		{"valid active", AllocationStatusActive, true},
		{"valid expired", AllocationStatusExpired, true},
		{"valid released", AllocationStatusReleased, true},
		{"valid reserved", AllocationStatusReserved, true},
		{"invalid empty", AllocationStatus(""), false},
		{"invalid unknown", AllocationStatus("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.IsValid(); got != tt.want {
				t.Errorf("AllocationStatus.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPool_Clone(t *testing.T) {
	t.Run("clone non-nil pool", func(t *testing.T) {
		original := &Pool{
			ID:           "pool-1",
			Name:         "test-pool",
			CIDR:         netip.MustParsePrefix("192.168.1.0/24"),
			Gateway:      netip.MustParseAddr("192.168.1.1"),
			Description:  "Test pool",
			Tags:         []string{"test", "dev"},
			TotalIPs:     254,
			AllocatedIPs: 10,
			AvailableIPs: 244,
		}

		clone := original.Clone()

		// Verify clone is not nil
		if clone == nil {
			t.Fatal("Clone() returned nil")
		}

		// Verify clone is not the same pointer
		if clone == original {
			t.Error("Clone() returned same pointer")
		}

		// Verify values are equal
		if clone.ID != original.ID {
			t.Errorf("Clone().ID = %v, want %v", clone.ID, original.ID)
		}
		if clone.Name != original.Name {
			t.Errorf("Clone().Name = %v, want %v", clone.Name, original.Name)
		}

		// Verify tags are independent
		if &clone.Tags == &original.Tags {
			t.Error("Clone().Tags points to same slice")
		}
		clone.Tags[0] = "modified"
		if original.Tags[0] == "modified" {
			t.Error("Modifying clone.Tags affected original")
		}
	})

	t.Run("clone nil pool", func(t *testing.T) {
		var p *Pool
		clone := p.Clone()
		if clone != nil {
			t.Error("Clone() of nil should return nil")
		}
	})
}

func TestAllocation_Clone(t *testing.T) {
	t.Run("clone non-nil allocation", func(t *testing.T) {
		original := &Allocation{
			ID:       "alloc-1",
			PoolID:   "pool-1",
			IP:       netip.MustParseAddr("192.168.1.10"),
			DeviceID: "device-1",
			Tags:     []string{"tag1", "tag2"},
			Metadata: map[string]string{"key": "value"},
			Status:   AllocationStatusActive,
		}

		clone := original.Clone()

		// Verify clone is not nil
		if clone == nil {
			t.Fatal("Clone() returned nil")
		}

		// Verify clone is not the same pointer
		if clone == original {
			t.Error("Clone() returned same pointer")
		}

		// Verify metadata is independent
		clone.Metadata["key"] = "modified"
		if original.Metadata["key"] == "modified" {
			t.Error("Modifying clone.Metadata affected original")
		}
	})

	t.Run("clone nil allocation", func(t *testing.T) {
		var a *Allocation
		clone := a.Clone()
		if clone != nil {
			t.Error("Clone() of nil should return nil")
		}
	})
}

func TestAllocation_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{"zero time never expires", time.Time{}, false},
		{"future time not expired", time.Now().Add(time.Hour), false},
		{"past time is expired", time.Now().Add(-time.Hour), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Allocation{ExpiresAt: tt.expiresAt}
			if got := a.IsExpired(); got != tt.want {
				t.Errorf("Allocation.IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllocation_IsActive(t *testing.T) {
	tests := []struct {
		name      string
		status    AllocationStatus
		expiresAt time.Time
		want      bool
	}{
		{"active and not expired", AllocationStatusActive, time.Time{}, true},
		{"active but expired", AllocationStatusActive, time.Now().Add(-time.Hour), false},
		{"expired status", AllocationStatusExpired, time.Time{}, false},
		{"released status", AllocationStatusReleased, time.Time{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Allocation{Status: tt.status, ExpiresAt: tt.expiresAt}
			if got := a.IsActive(); got != tt.want {
				t.Errorf("Allocation.IsActive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllocationRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     *AllocationRequest
		wantErr error
	}{
		{
			name:    "valid request",
			req:     &AllocationRequest{PoolID: "pool-1", DeviceID: "device-1"},
			wantErr: nil,
		},
		{
			name:    "missing pool ID",
			req:     &AllocationRequest{DeviceID: "device-1"},
			wantErr: ErrPoolIDRequired,
		},
		{
			name:    "missing device ID",
			req:     &AllocationRequest{PoolID: "pool-1"},
			wantErr: ErrDeviceIDRequired,
		},
		{
			name:    "both missing",
			req:     &AllocationRequest{},
			wantErr: ErrPoolIDRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if err != tt.wantErr {
				t.Errorf("AllocationRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAllocationRequest_Clone(t *testing.T) {
	t.Run("clone non-nil request", func(t *testing.T) {
		original := &AllocationRequest{
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			Tags:        []string{"tag1"},
			Metadata:    map[string]string{"key": "value"},
			RequestedIP: netip.MustParseAddr("192.168.1.10"),
		}

		clone := original.Clone()

		if clone == nil {
			t.Fatal("Clone() returned nil")
		}

		if clone == original {
			t.Error("Clone() returned same pointer")
		}

		// Verify metadata independence
		clone.Metadata["key"] = "modified"
		if original.Metadata["key"] == "modified" {
			t.Error("Modifying clone.Metadata affected original")
		}
	})

	t.Run("clone nil request", func(t *testing.T) {
		var r *AllocationRequest
		clone := r.Clone()
		if clone != nil {
			t.Error("Clone() of nil should return nil")
		}
	})
}

func TestPoolStats_CalculateUtilization(t *testing.T) {
	tests := []struct {
		name         string
		totalIPs     uint64
		allocatedIPs uint64
		wantPct      float64
	}{
		{"zero total", 0, 0, 0},
		{"50% utilized", 100, 50, 50.0},
		{"100% utilized", 100, 100, 100.0},
		{"0% utilized", 100, 0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &PoolStats{
				TotalIPs:     tt.totalIPs,
				AllocatedIPs: tt.allocatedIPs,
			}
			s.CalculateUtilization()
			if s.UtilizationPct != tt.wantPct {
				t.Errorf("CalculateUtilization() = %v, want %v", s.UtilizationPct, tt.wantPct)
			}
		})
	}
}
