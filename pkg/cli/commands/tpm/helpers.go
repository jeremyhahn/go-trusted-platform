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

package tpm

import (
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

// formatBool formats a boolean for display
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
