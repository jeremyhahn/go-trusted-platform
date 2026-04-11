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
	"strings"
	"testing"
	"time"

	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

func TestFormatVMState_AllStates(t *testing.T) {
	tests := []struct {
		state    computesvc.VMState
		expected string
	}{
		{computesvc.StateStopped, "STOPPED"},
		{computesvc.StateStarting, "STARTING"},
		{computesvc.StateRunning, "RUNNING"},
		{computesvc.StatePaused, "PAUSED"},
		{computesvc.StateStopping, "STOPPING"},
		{computesvc.StateRebooting, "REBOOTING"},
		{computesvc.StateMigrating, "MIGRATING"},
		{computesvc.StateError, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatVMState(tt.state)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestFormatVMState_Unspecified(t *testing.T) {
	// Empty string triggers UNKNOWN; StateUnspecified ("UNSPECIFIED") passes through.
	result := formatVMState("")
	if result != "UNKNOWN" {
		t.Errorf("expected 'UNKNOWN' for empty state, got %q", result)
	}
}

func TestFormatVMState_InvalidValue(t *testing.T) {
	// Non-empty unknown values pass through as-is; only empty string returns "UNKNOWN".
	result := formatVMState(computesvc.VMState("BOGUS_999"))
	if result != "BOGUS_999" {
		t.Errorf("expected %q for unknown state value, got %q", "BOGUS_999", result)
	}
}

func TestFormatTimestamp_Zero(t *testing.T) {
	result := formatTimestamp(time.Time{})
	if result != "N/A" {
		t.Errorf("expected 'N/A' for zero time, got %q", result)
	}
}

func TestFormatTimestamp_Valid(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 30, 0, 0, time.UTC)

	result := formatTimestamp(ts)

	// Should be RFC3339 format
	_, err := time.Parse(time.RFC3339, result)
	if err != nil {
		t.Errorf("expected RFC3339 format, got %q: %v", result, err)
	}

	if !strings.Contains(result, "2025-06-15") {
		t.Errorf("expected date 2025-06-15 in output, got %q", result)
	}
}

func TestFormatTimestamp_Epoch(t *testing.T) {
	ts := time.Unix(1, 0).UTC() // epoch+1s to avoid zero-time short-circuit

	result := formatTimestamp(ts)

	_, err := time.Parse(time.RFC3339, result)
	if err != nil {
		t.Errorf("expected valid RFC3339 for near-epoch time, got %q: %v", result, err)
	}
}

func TestFormatBool(t *testing.T) {
	if formatBool(true) != "Yes" {
		t.Errorf("expected 'Yes' for true, got %q", formatBool(true))
	}
	if formatBool(false) != "No" {
		t.Errorf("expected 'No' for false, got %q", formatBool(false))
	}
}

func TestFormatBytes_Units(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.00 KB"},
		{1048576, "1.00 MB"},
		{1073741824, "1.00 GB"},
		{1099511627776, "1.00 TB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatBytes(%d): expected %q, got %q", tt.bytes, tt.expected, result)
			}
		})
	}
}

func TestFormatBytes_FractionalValues(t *testing.T) {
	// 1.5 GB
	result := formatBytes(1610612736)
	if !strings.Contains(result, "GB") {
		t.Errorf("expected GB unit for 1.5GB, got %q", result)
	}

	// 2.5 MB
	result = formatBytes(2621440)
	if !strings.Contains(result, "MB") {
		t.Errorf("expected MB unit for 2.5MB, got %q", result)
	}
}

func TestFormatDuration_Ranges(t *testing.T) {
	tests := []struct {
		seconds  uint32
		expected string
	}{
		{0, "0s"},
		{30, "30s"},
		{59, "59s"},
		{60, "1m0s"},
		{90, "1m30s"},
		{3599, "59m59s"},
		{3600, "1h0m"},
		{3661, "1h1m"},
		{7200, "2h0m"},
		{86400, "24h0m"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatDuration(tt.seconds)
			if result != tt.expected {
				t.Errorf("formatDuration(%d): expected %q, got %q", tt.seconds, tt.expected, result)
			}
		})
	}
}

func TestTruncateID_Short(t *testing.T) {
	tests := []string{"abc", "12345678", "exactly12ch"}

	for _, id := range tests {
		t.Run(id, func(t *testing.T) {
			result := truncateID(id)
			if result != id {
				t.Errorf("expected %q (unchanged), got %q", id, result)
			}
		})
	}
}

func TestTruncateID_Long(t *testing.T) {
	id := "abcdef1234567890"
	result := truncateID(id)

	if len(result) != 12 {
		t.Errorf("expected truncated length 12, got %d", len(result))
	}

	if result != "abcdef123456" {
		t.Errorf("expected 'abcdef123456', got %q", result)
	}
}

func TestTruncateID_ExactlyTwelve(t *testing.T) {
	id := "123456789012"
	result := truncateID(id)
	if result != id {
		t.Errorf("12-char ID should not be truncated, got %q", result)
	}
}

func TestTruncateID_Empty(t *testing.T) {
	result := truncateID("")
	if result != "" {
		t.Errorf("empty ID should return empty, got %q", result)
	}
}

func TestFormatFirmwareType_AllTypes(t *testing.T) {
	tests := []struct {
		fw       computesvc.FirmwareType
		expected string
	}{
		{computesvc.FirmwareBIOS, "BIOS"},
		{computesvc.FirmwareUEFI, "UEFI"},
		{computesvc.FirmwareUEFISecureBoot, "UEFI Secure Boot"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatFirmwareType(tt.fw)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestFormatFirmwareType_Unspecified(t *testing.T) {
	// Empty string triggers "Unknown"; FirmwareUnspecified ("UNSPECIFIED") passes through.
	result := formatFirmwareType("")
	if result != "Unknown" {
		t.Errorf("expected 'Unknown' for empty firmware type, got %q", result)
	}
}

func TestFormatFirmwareType_InvalidValue(t *testing.T) {
	// Non-empty unknown values pass through as-is.
	result := formatFirmwareType(computesvc.FirmwareType("BOGUS"))
	if result != "BOGUS" {
		t.Errorf("expected %q for unknown firmware type, got %q", "BOGUS", result)
	}
}
