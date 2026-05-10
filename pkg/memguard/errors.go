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

package memguard

import "fmt"

// ErrDestroyed indicates an operation was attempted on a Secret whose
// backing memory has been wiped and freed.
type ErrDestroyed struct{}

func (ErrDestroyed) Error() string {
	return "secure: secret has been destroyed"
}

// ErrInvalidSize indicates a non-negative size was required.
type ErrInvalidSize struct {
	Size int
}

func (e ErrInvalidSize) Error() string {
	return fmt.Sprintf("secure: invalid size: %d", e.Size)
}

// ErrInvalidEncoding indicates the input could not be decoded into a Secret.
type ErrInvalidEncoding struct {
	Reason string
}

func (e ErrInvalidEncoding) Error() string {
	return "secure: invalid encoding: " + e.Reason
}

// ErrRedactedInput indicates the unmarshal input was the redacted
// placeholder, which would silently lose the original value.
type ErrRedactedInput struct{}

func (ErrRedactedInput) Error() string {
	return "secure: refusing to unmarshal redacted placeholder as secret"
}
