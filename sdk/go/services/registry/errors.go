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

import "fmt"

// ErrStatusFailed is returned when getting registry status fails.
type ErrStatusFailed struct {
	Cause error
}

func (e *ErrStatusFailed) Error() string {
	return fmt.Sprintf("failed to get registry status: %v", e.Cause)
}

func (e *ErrStatusFailed) Unwrap() error { return e.Cause }

// ErrListFailed is returned when listing artifacts fails.
type ErrListFailed struct {
	Cause error
}

func (e *ErrListFailed) Error() string {
	return fmt.Sprintf("failed to list artifacts: %v", e.Cause)
}

func (e *ErrListFailed) Unwrap() error { return e.Cause }

// ErrInspectFailed is returned when inspecting an artifact fails.
type ErrInspectFailed struct {
	Reference string
	Cause     error
}

func (e *ErrInspectFailed) Error() string {
	return fmt.Sprintf("failed to inspect artifact %s: %v", e.Reference, e.Cause)
}

func (e *ErrInspectFailed) Unwrap() error { return e.Cause }

// ErrDeleteFailed is returned when deleting an artifact fails.
type ErrDeleteFailed struct {
	Reference string
	Cause     error
}

func (e *ErrDeleteFailed) Error() string {
	return fmt.Sprintf("failed to delete artifact %s: %v", e.Reference, e.Cause)
}

func (e *ErrDeleteFailed) Unwrap() error { return e.Cause }

// ErrPushFailed is returned when pushing an artifact fails.
type ErrPushFailed struct {
	Cause error
}

func (e *ErrPushFailed) Error() string {
	return fmt.Sprintf("failed to push artifact: %v", e.Cause)
}

func (e *ErrPushFailed) Unwrap() error { return e.Cause }

// ErrPullFailed is returned when pulling an artifact fails.
type ErrPullFailed struct {
	Cause error
}

func (e *ErrPullFailed) Error() string {
	return fmt.Sprintf("failed to pull artifact: %v", e.Cause)
}

func (e *ErrPullFailed) Unwrap() error { return e.Cause }
