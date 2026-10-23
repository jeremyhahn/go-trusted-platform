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

package registry

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// imageRefRegex validates image references
// Supports:
// - Simple names: alpine
// - With tag: alpine:latest
// - With repository: myrepo/myimage, myrepo/myimage:v1
// - With registry: registry.example.com/myrepo/myimage:v1
// - With port: localhost:5000/myimage:v1
// - With digest: myrepo/myimage@sha256:abc123...
var imageRefRegex = regexp.MustCompile(`^(?:(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?)/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[a-zA-Z0-9_][a-zA-Z0-9._-]*)?(?:@sha256:[a-f0-9]{64})?$`)

// validateImageRef validates an image reference format
func validateImageRef(ref string) error {
	if ref == "" {
		return ErrInvalidImageReference{Reference: ref, Reason: "reference cannot be empty"}
	}

	// Check for overly long references
	if len(ref) > 256 {
		return ErrInvalidImageReference{Reference: ref, Reason: "reference too long"}
	}

	// Validate the reference format
	if !imageRefRegex.MatchString(ref) {
		return ErrInvalidImageReference{Reference: ref, Reason: "invalid format"}
	}

	return nil
}

// formatTimestamp formats a Unix timestamp for display
func formatTimestamp(ts int64) string {
	if ts == 0 {
		return "N/A"
	}
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}

// unixSeconds is a Unix timestamp in seconds that renders as an RFC 3339 UTC
// string in --output json and yaml, the form every platformctl timestamp
// takes; the table renderer formats it with formatTimestamp.
type unixSeconds int64

// rfc3339 returns the timestamp as an RFC 3339 UTC string.
func (s unixSeconds) rfc3339() string {
	return time.Unix(int64(s), 0).UTC().Format(time.RFC3339)
}

// MarshalJSON renders the timestamp as an RFC 3339 JSON string.
func (s unixSeconds) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.rfc3339())
}

// MarshalYAML renders the timestamp as an RFC 3339 YAML string.
func (s unixSeconds) MarshalYAML() (interface{}, error) {
	return s.rfc3339(), nil
}

// formatTimePtr formats a time pointer for display
func formatTimePtr(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "N/A"
	}
	return t.UTC().Format(time.RFC3339)
}

// formatBool formats a boolean for display
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// formatBytes formats byte count for human-readable display
func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/TB)
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// formatHealthStatus formats a health status for display
func formatHealthStatus(healthy bool) string {
	if healthy {
		return "[HEALTHY]"
	}
	return "[UNHEALTHY]"
}

// formatEncryptionStatus formats encryption status for display
func formatEncryptionStatus(encrypted bool) string {
	if encrypted {
		return "Encrypted"
	}
	return "Unencrypted"
}

// truncateDigest truncates a digest for display (shows first 12 chars)
func truncateDigest(digest string) string {
	if len(digest) <= 19 { // "sha256:" + 12 chars
		return digest
	}
	// Format: sha256:abc123...
	if len(digest) > 7 && digest[:7] == "sha256:" {
		return digest[:19] + "..."
	}
	if len(digest) > 12 {
		return digest[:12] + "..."
	}
	return digest
}

// parseImageRef parses an image reference into repository and tag components
func parseImageRef(ref string) (repository, tag string) {
	// Check for digest reference
	if atIdx := findLastByte(ref, '@'); atIdx != -1 {
		return ref[:atIdx], ref[atIdx+1:]
	}

	// Check for tag reference
	if colonIdx := findLastByte(ref, ':'); colonIdx != -1 {
		// Make sure we're not matching a port number
		slashIdx := findLastByte(ref, '/')
		if slashIdx == -1 || colonIdx > slashIdx {
			return ref[:colonIdx], ref[colonIdx+1:]
		}
	}

	// No tag specified, default to latest
	return ref, "latest"
}

// findLastByte finds the last occurrence of a byte in a string
func findLastByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
