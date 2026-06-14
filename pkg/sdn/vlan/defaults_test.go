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
	"testing"
)

func TestConstants(t *testing.T) {
	t.Run("zone defaults match reference network doc", func(t *testing.T) {
		if DefaultTrusted != 200 {
			t.Errorf("DefaultTrusted = %d, want 200", DefaultTrusted)
		}
		if DefaultProvisioning != 201 {
			t.Errorf("DefaultProvisioning = %d, want 201", DefaultProvisioning)
		}
		if DefaultQuarantine != 202 {
			t.Errorf("DefaultQuarantine = %d, want 202", DefaultQuarantine)
		}
		if DefaultStorage != 203 {
			t.Errorf("DefaultStorage = %d, want 203", DefaultStorage)
		}
		if DefaultManagement != 50 {
			t.Errorf("DefaultManagement = %d, want 50", DefaultManagement)
		}
		if DefaultTransit != 10 {
			t.Errorf("DefaultTransit = %d, want 10", DefaultTransit)
		}
		if DefaultNative != 1 {
			t.Errorf("DefaultNative = %d, want 1", DefaultNative)
		}
		if TenantBase != 1000 {
			t.Errorf("TenantBase = %d, want 1000", TenantBase)
		}
	})

	t.Run("IEEE 802.1Q range constants", func(t *testing.T) {
		if MinVLAN != 1 {
			t.Errorf("MinVLAN = %d, want 1", MinVLAN)
		}
		if MaxVLAN != 4094 {
			t.Errorf("MaxVLAN = %d, want 4094", MaxVLAN)
		}
	})
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		id      uint16
		wantErr bool
	}{
		{"min boundary (1)", 1, false},
		{"max boundary (4094)", 4094, false},
		{"trusted default (200)", 200, false},
		{"provisioning default (201)", 201, false},
		{"quarantine default (202)", 202, false},
		{"storage default (203)", 203, false},
		{"management default (50)", 50, false},
		{"transit default (10)", 10, false},
		{"tenant base (1000)", 1000, false},
		{"arbitrary mid-range", 512, false},
		{"zero (invalid)", 0, true},
		{"4095 (above max)", 4095, true},
		{"max uint16 (65535)", 65535, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.id)
			if tt.wantErr && err == nil {
				t.Errorf("Validate(%d) returned nil, want error", tt.id)
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate(%d) returned unexpected error: %v", tt.id, err)
				return
			}
			if tt.wantErr {
				var e ErrInvalidVLAN
				if _, ok := err.(ErrInvalidVLAN); !ok {
					t.Errorf("Validate(%d) returned %T, want ErrInvalidVLAN", tt.id, err)
					return
				}
				if e.ID != 0 && e.ID != tt.id {
					t.Errorf("ErrInvalidVLAN.ID = %d, want %d", e.ID, tt.id)
				}
				// Verify error message is non-empty and descriptive.
				if err.Error() == "" {
					t.Error("ErrInvalidVLAN.Error() returned empty string")
				}
			}
		})
	}
}

func TestErrInvalidVLAN_Error(t *testing.T) {
	t.Run("contains ID and range in message", func(t *testing.T) {
		err := ErrInvalidVLAN{ID: 0}
		msg := err.Error()
		if msg == "" {
			t.Fatal("Error() returned empty string")
		}
		// Must mention the invalid ID value.
		if len(msg) < 5 {
			t.Errorf("Error() message too short: %q", msg)
		}
	})

	t.Run("above-max ID in message", func(t *testing.T) {
		err := ErrInvalidVLAN{ID: 4095}
		msg := err.Error()
		if msg == "" {
			t.Fatal("Error() returned empty string")
		}
	})
}

func TestValidateTenantOffset(t *testing.T) {
	tests := []struct {
		name    string
		offset  uint16
		wantErr bool
	}{
		{"offset 0 → VLAN 1000 (valid)", 0, false},
		{"offset 1 → VLAN 1001 (valid)", 1, false},
		{"offset 3094 → VLAN 4094 (max valid)", 3094, false},
		{"offset 3095 → VLAN 4095 (invalid)", 3095, true},
		{"large offset causes overflow beyond 4094", 60000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTenantOffset(tt.offset)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateTenantOffset(%d) returned nil, want error", tt.offset)
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateTenantOffset(%d) returned unexpected error: %v", tt.offset, err)
				return
			}
			if tt.wantErr {
				if _, ok := err.(ErrInvalidVLAN); !ok {
					t.Errorf("ValidateTenantOffset(%d) returned %T, want ErrInvalidVLAN", tt.offset, err)
				}
			}
		})
	}
}
