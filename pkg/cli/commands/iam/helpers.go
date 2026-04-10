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

package iam

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// formatTimestamp formats a protobuf timestamp for display
func formatTimestamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "N/A"
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
}

// formatTimestampProto is an alias for formatTimestamp for consistency
func formatTimestampProto(ts *timestamppb.Timestamp) string {
	return formatTimestamp(ts)
}

// formatBool formats a boolean for display
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// formatStringSlice formats a string slice for display
func formatStringSlice(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

// formatAttributes formats a map of attributes for display
func formatAttributes(attrs map[string]string) string {
	if len(attrs) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(attrs))
	for k, v := range attrs {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ", ")
}

// parseStringSlice parses a comma-separated string into a slice
func parseStringSlice(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// parseAttributes parses a comma-separated key=value string into a map
func parseAttributes(s string) map[string]string {
	if s == "" {
		return nil
	}
	result := make(map[string]string)
	parts := strings.Split(s, ",")
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		kv := strings.SplitN(trimmed, "=", 2)
		if len(kv) == 2 {
			result[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return result
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
