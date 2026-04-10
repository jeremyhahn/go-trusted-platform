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

package baremetal

import "testing"

func TestProvisioningStatus_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		status ProvisioningStatus
		want   bool
	}{
		{"pending", StatusPending, true},
		{"connecting", StatusConnecting, true},
		{"setting_boot", StatusSettingBoot, true},
		{"mounting_iso", StatusMountingISO, true},
		{"powering_on", StatusPoweringOn, true},
		{"installing", StatusInstalling, true},
		{"finalizing", StatusFinalizing, true},
		{"complete", StatusComplete, true},
		{"failed", StatusFailed, true},
		{"empty", ProvisioningStatus(""), false},
		{"invalid", ProvisioningStatus("bogus"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProvisioningStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		name   string
		status ProvisioningStatus
		want   bool
	}{
		{"pending", StatusPending, false},
		{"connecting", StatusConnecting, false},
		{"installing", StatusInstalling, false},
		{"finalizing", StatusFinalizing, false},
		{"complete", StatusComplete, true},
		{"failed", StatusFailed, true},
		{"invalid", ProvisioningStatus("bogus"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.IsTerminal(); got != tt.want {
				t.Errorf("IsTerminal() = %v, want %v", got, tt.want)
			}
		})
	}
}
