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

package db

import "fmt"

// ErrListEntityTypesFailed indicates a failure to list entity types.
type ErrListEntityTypesFailed struct {
	Cause error
}

func (e *ErrListEntityTypesFailed) Error() string {
	return fmt.Sprintf("db: failed to list entity types: %v", e.Cause)
}

func (e *ErrListEntityTypesFailed) Unwrap() error { return e.Cause }

// ErrDumpFailed indicates a failure to start the dump stream.
type ErrDumpFailed struct {
	Cause error
}

func (e *ErrDumpFailed) Error() string {
	return fmt.Sprintf("db: failed to start dump: %v", e.Cause)
}

func (e *ErrDumpFailed) Unwrap() error { return e.Cause }

// ErrDumpStreamFailed indicates a failure during the dump stream.
type ErrDumpStreamFailed struct {
	Cause error
}

func (e *ErrDumpStreamFailed) Error() string {
	return fmt.Sprintf("db: dump stream error: %v", e.Cause)
}

func (e *ErrDumpStreamFailed) Unwrap() error { return e.Cause }
