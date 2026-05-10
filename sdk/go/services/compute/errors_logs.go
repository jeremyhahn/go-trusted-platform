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
	"errors"
	"fmt"
)

// ErrContainerIDRequired indicates that a container ID is required.
var ErrContainerIDRequired = errors.New("container ID is required")

// ErrGetContainerLogsFailed is returned when getting container logs fails.
type ErrGetContainerLogsFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetContainerLogsFailed) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("failed to get container logs for %s: %v", e.ID, e.Cause)
	}
	return fmt.Sprintf("failed to get container logs: %v", e.Cause)
}

func (e *ErrGetContainerLogsFailed) Unwrap() error {
	return e.Cause
}
