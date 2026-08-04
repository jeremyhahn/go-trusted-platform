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

import "fmt"

// ErrAttestContainerFailed is returned when container attestation fails.
type ErrAttestContainerFailed struct {
	ID    string
	Cause error
}

func (e *ErrAttestContainerFailed) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("failed to attest container %s: %v", e.ID, e.Cause)
	}
	return fmt.Sprintf("failed to attest container: %v", e.Cause)
}

func (e *ErrAttestContainerFailed) Unwrap() error {
	return e.Cause
}
