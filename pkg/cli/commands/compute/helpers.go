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
	"time"

	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// formatVMState formats a domain VMState for display.
func formatVMState(state computesvc.VMState) string {
	if state == "" {
		return "UNKNOWN"
	}
	return string(state)
}

// formatFirmwareType formats a domain FirmwareType for display.
func formatFirmwareType(fw computesvc.FirmwareType) string {
	if fw == "" {
		return "Unknown"
	}
	return string(fw)
}

// formatTimestamp formats a time.Time for display.
func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return t.UTC().Format(time.RFC3339)
}

// formatBool formats a boolean for display.
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// formatBytes formats byte count for human-readable display.
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

// formatDuration formats a duration in seconds for human-readable display.
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

// truncateID truncates a VM ID for display.
func truncateID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
