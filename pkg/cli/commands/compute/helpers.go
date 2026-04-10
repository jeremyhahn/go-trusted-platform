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
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// vmStateToString maps VMState enum values to human-readable strings
var vmStateToString = map[platformv1.VMState]string{
	platformv1.VMState_VM_STATE_STOPPED:    "STOPPED",
	platformv1.VMState_VM_STATE_STARTING:   "STARTING",
	platformv1.VMState_VM_STATE_RUNNING:    "RUNNING",
	platformv1.VMState_VM_STATE_PAUSED:     "PAUSED",
	platformv1.VMState_VM_STATE_STOPPING:   "STOPPING",
	platformv1.VMState_VM_STATE_REBOOTING:  "REBOOTING",
	platformv1.VMState_VM_STATE_MIGRATING:  "MIGRATING",
	platformv1.VMState_VM_STATE_ERROR:      "ERROR",
}

// stringToVMState maps human-readable strings to VMState enum values
var stringToVMState = map[string]platformv1.VMState{
	"STOPPED":   platformv1.VMState_VM_STATE_STOPPED,
	"STARTING":  platformv1.VMState_VM_STATE_STARTING,
	"RUNNING":   platformv1.VMState_VM_STATE_RUNNING,
	"PAUSED":    platformv1.VMState_VM_STATE_PAUSED,
	"STOPPING":  platformv1.VMState_VM_STATE_STOPPING,
	"REBOOTING": platformv1.VMState_VM_STATE_REBOOTING,
	"MIGRATING": platformv1.VMState_VM_STATE_MIGRATING,
	"ERROR":     platformv1.VMState_VM_STATE_ERROR,
}

// firmwareTypeToString maps FirmwareType enum values to human-readable strings
var firmwareTypeToString = map[platformv1.FirmwareType]string{
	platformv1.FirmwareType_FIRMWARE_TYPE_BIOS:             "BIOS",
	platformv1.FirmwareType_FIRMWARE_TYPE_UEFI:             "UEFI",
	platformv1.FirmwareType_FIRMWARE_TYPE_UEFI_SECURE_BOOT: "UEFI Secure Boot",
}

// formatVMState formats a VMState enum to a human-readable string
func formatVMState(state platformv1.VMState) string {
	if s, ok := vmStateToString[state]; ok {
		return s
	}
	return "UNKNOWN"
}

// parseVMState parses a human-readable state string to a VMState enum
func parseVMState(state string) (platformv1.VMState, bool) {
	s, ok := stringToVMState[strings.ToUpper(strings.TrimSpace(state))]
	return s, ok
}

// formatTimestamp formats a protobuf timestamp for display
func formatTimestamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "N/A"
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
}

// formatBool formats a boolean for display
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// formatBytes formats byte count for human-readable display
func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return strconv.FormatFloat(float64(bytes)/float64(TB), 'f', 2, 64) + " TB"
	case bytes >= GB:
		return strconv.FormatFloat(float64(bytes)/float64(GB), 'f', 2, 64) + " GB"
	case bytes >= MB:
		return strconv.FormatFloat(float64(bytes)/float64(MB), 'f', 2, 64) + " MB"
	case bytes >= KB:
		return strconv.FormatFloat(float64(bytes)/float64(KB), 'f', 2, 64) + " KB"
	default:
		return strconv.FormatUint(bytes, 10) + " B"
	}
}

// formatDuration formats a duration in seconds for human-readable display
func formatDuration(seconds uint32) string {
	d := time.Duration(seconds) * time.Second
	if d < time.Minute {
		return d.String()
	}
	if d < time.Hour {
		return d.Round(time.Second).String()
	}
	hours := d / time.Hour
	minutes := (d % time.Hour) / time.Minute
	return strconv.FormatInt(int64(hours), 10) + "h" + strconv.FormatInt(int64(minutes), 10) + "m"
}

// truncateID truncates a VM ID for display
func truncateID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// formatFirmwareType formats a FirmwareType enum to a human-readable string
func formatFirmwareType(fw platformv1.FirmwareType) string {
	if s, ok := firmwareTypeToString[fw]; ok {
		return s
	}
	return "Unknown"
}
