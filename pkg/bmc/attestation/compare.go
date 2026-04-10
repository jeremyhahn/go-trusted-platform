// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

// CompareResult is the output of [AttestationProvider.Compare]. A match
// means every field the backend deemed significant is equal between the
// live evidence and the reference; Differences enumerates the fields
// that diverged for audit and debugging.
type CompareResult struct {
	// Match is true when the live evidence is equivalent to the
	// reference under the backend's comparison rules.
	Match bool

	// Differences is a list of human-readable descriptions of each
	// field that did not match. Empty when Match is true.
	Differences []Difference
}

// Difference describes a single mismatched field.
type Difference struct {
	Field string
	Live  string
	Ref   string
}
