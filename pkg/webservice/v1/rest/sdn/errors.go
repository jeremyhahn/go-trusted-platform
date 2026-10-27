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

package sdn

import "fmt"

// ErrInvalidRequestBody is returned when the request body cannot be parsed
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("invalid request body: %s", e.Reason)
}

// ErrMissingZoneName is returned when a zone request omits the zone name.
type ErrMissingZoneName struct{}

func (e ErrMissingZoneName) Error() string {
	return "zone name is required"
}

// ErrZoneNameMismatch is returned when an update body names a different
// zone than the URL path.
type ErrZoneNameMismatch struct {
	Path string
	Body string
}

func (e ErrZoneNameMismatch) Error() string {
	return fmt.Sprintf("zone name mismatch: path=%s, body=%s", e.Path, e.Body)
}
