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

package cluster

import "fmt"

// ErrGetStatusFailed is returned when getting cluster status fails.
type ErrGetStatusFailed struct {
	Cause error
}

func (e *ErrGetStatusFailed) Error() string {
	return fmt.Sprintf("failed to get cluster status: %v", e.Cause)
}

func (e *ErrGetStatusFailed) Unwrap() error { return e.Cause }

// ErrListNodesFailed is returned when listing cluster nodes fails.
type ErrListNodesFailed struct {
	Cause error
}

func (e *ErrListNodesFailed) Error() string {
	return fmt.Sprintf("failed to list cluster nodes: %v", e.Cause)
}

func (e *ErrListNodesFailed) Unwrap() error { return e.Cause }

// ErrBootstrapFailed is returned when cluster bootstrap fails.
type ErrBootstrapFailed struct {
	Cause error
}

func (e *ErrBootstrapFailed) Error() string {
	return fmt.Sprintf("failed to bootstrap cluster: %v", e.Cause)
}

func (e *ErrBootstrapFailed) Unwrap() error { return e.Cause }

// ErrJoinFailed is returned when joining a cluster fails.
type ErrJoinFailed struct {
	Cause error
}

func (e *ErrJoinFailed) Error() string {
	return fmt.Sprintf("failed to join cluster: %v", e.Cause)
}

func (e *ErrJoinFailed) Unwrap() error { return e.Cause }

// ErrLeaveFailed is returned when leaving a cluster fails.
type ErrLeaveFailed struct {
	Cause error
}

func (e *ErrLeaveFailed) Error() string {
	return fmt.Sprintf("failed to leave cluster: %v", e.Cause)
}

func (e *ErrLeaveFailed) Unwrap() error { return e.Cause }
