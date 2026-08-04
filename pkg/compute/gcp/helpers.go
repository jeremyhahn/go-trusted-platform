//go:build gcpcompute

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

package gcp

import (
	"errors"
	"strings"

	"google.golang.org/api/googleapi"
)

// isNotFound reports whether a GCE API error is a "resource not found"
// condition. The Compute REST transport surfaces these as googleapi errors
// with HTTP status 404.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var gErr *googleapi.Error
	if errors.As(err, &gErr) && gErr.Code == 404 {
		return true
	}
	return strings.Contains(err.Error(), "notFound") ||
		strings.Contains(err.Error(), "404")
}

// resourceName returns the final path segment of a GCE resource self-link or
// partial URL (e.g. ".../disks/boot-01" -> "boot-01"). A value with no slash
// is returned unchanged.
func resourceName(selfLink string) string {
	if i := strings.LastIndex(selfLink, "/"); i >= 0 {
		return selfLink[i+1:]
	}
	return selfLink
}

// sanitizeInstanceName coerces an arbitrary profile name into a GCE-valid
// instance name: lowercase RFC1035 (a letter, then letters/digits/hyphens).
// Invalid runes become hyphens; an empty or non-letter start is prefixed with
// "vm-". GCE rejects out-of-spec names, so normalizing keeps Create honest.
func sanitizeInstanceName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" || out[0] < 'a' || out[0] > 'z' {
		out = "vm-" + out
	}
	if len(out) > 63 {
		out = strings.TrimRight(out[:63], "-")
	}
	return out
}
