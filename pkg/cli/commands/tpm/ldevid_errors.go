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

import "fmt"

// ErrCreateLDevIDFailed is returned when LDevID provisioning fails.
type ErrCreateLDevIDFailed struct {
	Reason string
}

func (e ErrCreateLDevIDFailed) Error() string {
	return fmt.Sprintf("failed to create LDevID: %s", e.Reason)
}

// ErrInvalidTPMHandle is returned when a persistent TPM handle flag cannot be
// parsed as a hex (0x...) or decimal 32-bit value.
type ErrInvalidTPMHandle struct {
	Handle string
}

func (e ErrInvalidTPMHandle) Error() string {
	return fmt.Sprintf("invalid TPM handle %q: expected hex (0x...) or decimal uint32", e.Handle)
}
