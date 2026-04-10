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

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

func TestFormatVMState_AllStates(t *testing.T) {
	tests := []struct {
		state    platformv1.VMState
		expected string
	}{
		{platformv1.VMState_VM_STATE_STOPPED, "STOPPED"},
		{platformv1.VMState_VM_STATE_STARTING, "STARTING"},
		{platformv1.VMState_VM_STATE_RUNNING, "RUNNING"},
		{platformv1.VMState_VM_STATE_PAUSED, "PAUSED"},
		{platformv1.VMState_VM_STATE_STOPPING, "STOPPING"},
		{platformv1.VMState_VM_STATE_REBOOTING, "REBOOTING"},
		{platformv1.VMState_VM_STATE_MIGRATING, "MIGRATING"},
		{platformv1.VMState_VM_STATE_ERROR, "ERROR"},
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
	result := formatVMState(platformv1.VMState_VM_STATE_UNSPECIFIED)
	if result != "UNKNOWN" {
		t.Errorf("expected 'UNKNOWN' for unspecified state, got %q", result)
	}
}

func TestFormatVMState_InvalidValue(t *testing.T) {
	result := formatVMState(platformv1.VMState(999))
	if result != "UNKNOWN" {
		t.Errorf("expected 'UNKNOWN' for invalid state value, got %q", result)
	}
}

func TestParseVMState_AllStates(t *testing.T) {
	tests := []struct {
		input    string
		expected platformv1.VMState
	}{
		{"STOPPED", platformv1.VMState_VM_STATE_STOPPED},
		{"STARTING", platformv1.VMState_VM_STATE_STARTING},
		{"RUNNING", platformv1.VMState_VM_STATE_RUNNING},
		{"PAUSED", platformv1.VMState_VM_STATE_PAUSED},
		{"STOPPING", platformv1.VMState_VM_STATE_STOPPING},
		{"REBOOTING", platformv1.VMState_VM_STATE_REBOOTING},
		{"MIGRATING", platformv1.VMState_VM_STATE_MIGRATING},
		{"ERROR", platformv1.VMState_VM_STATE_ERROR},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			state, ok := parseVMState(tt.input)
			if !ok {
				t.Fatalf("parseVMState(%q) returned false", tt.input)
			}
			if state != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, state)
			}
		})
	}
}

func TestParseVMState_CaseInsensitive(t *testing.T) {
	tests := []string{"running", "Running", "RUNNING", "rUnNiNg"}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			state, ok := parseVMState(input)
			if !ok {
				t.Fatalf("parseVMState(%q) should succeed", input)
			}
			if state != platformv1.VMState_VM_STATE_RUNNING {
				t.Errorf("expected VM_STATE_RUNNING, got %v", state)
			}
		})
	}
}

func TestParseVMState_WithWhitespace(t *testing.T) {
	state, ok := parseVMState("  STOPPED  ")
	if !ok {
		t.Fatal("parseVMState should trim whitespace")
	}
	if state != platformv1.VMState_VM_STATE_STOPPED {
		t.Errorf("expected VM_STATE_STOPPED, got %v", state)
	}
}

func TestParseVMState_Invalid(t *testing.T) {
	invalidStates := []string{"invalid", "BOGUS", "", "UNKNOWN", "ready"}

	for _, input := range invalidStates {
		t.Run(input, func(t *testing.T) {
			_, ok := parseVMState(input)
			if ok {
				t.Errorf("parseVMState(%q) should return false", input)
			}
		})
	}
}

func TestFormatTimestamp_Nil(t *testing.T) {
	result := formatTimestamp(nil)
	if result != "N/A" {
		t.Errorf("expected 'N/A' for nil timestamp, got %q", result)
	}
}

func TestFormatTimestamp_Valid(t *testing.T) {
	ts := timestamppb.New(time.Date(2025, 6, 15, 12, 30, 0, 0, time.UTC))

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
	ts := timestamppb.New(time.Unix(0, 0))

	result := formatTimestamp(ts)

	_, err := time.Parse(time.RFC3339, result)
	if err != nil {
		t.Errorf("expected valid RFC3339 for epoch, got %q: %v", result, err)
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
		fw       platformv1.FirmwareType
		expected string
	}{
		{platformv1.FirmwareType_FIRMWARE_TYPE_BIOS, "BIOS"},
		{platformv1.FirmwareType_FIRMWARE_TYPE_UEFI, "UEFI"},
		{platformv1.FirmwareType_FIRMWARE_TYPE_UEFI_SECURE_BOOT, "UEFI Secure Boot"},
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
	result := formatFirmwareType(platformv1.FirmwareType_FIRMWARE_TYPE_UNSPECIFIED)
	if result != "Unknown" {
		t.Errorf("expected 'Unknown' for unspecified firmware, got %q", result)
	}
}

func TestFormatFirmwareType_InvalidValue(t *testing.T) {
	result := formatFirmwareType(platformv1.FirmwareType(999))
	if result != "Unknown" {
		t.Errorf("expected 'Unknown' for invalid firmware type, got %q", result)
	}
}

func TestVMStateToString_MapCompleteness(t *testing.T) {
	expectedCount := 8 // STOPPED, STARTING, RUNNING, PAUSED, STOPPING, REBOOTING, MIGRATING, ERROR
	if len(vmStateToString) != expectedCount {
		t.Errorf("vmStateToString should have %d entries, got %d", expectedCount, len(vmStateToString))
	}
}

func TestStringToVMState_MapCompleteness(t *testing.T) {
	expectedCount := 8
	if len(stringToVMState) != expectedCount {
		t.Errorf("stringToVMState should have %d entries, got %d", expectedCount, len(stringToVMState))
	}
}

func TestFirmwareTypeToString_MapCompleteness(t *testing.T) {
	expectedCount := 3 // BIOS, UEFI, UEFI_SECURE_BOOT
	if len(firmwareTypeToString) != expectedCount {
		t.Errorf("firmwareTypeToString should have %d entries, got %d", expectedCount, len(firmwareTypeToString))
	}
}
