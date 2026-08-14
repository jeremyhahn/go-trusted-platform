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

package proxy

import "fmt"

// Route errors

// ErrCreateRouteFailed indicates a route create operation failed.
type ErrCreateRouteFailed struct {
	ID    string
	Cause error
}

func (e *ErrCreateRouteFailed) Error() string {
	return fmt.Sprintf("failed to create proxy route %q: %v", e.ID, e.Cause)
}

func (e *ErrCreateRouteFailed) Unwrap() error { return e.Cause }

// ErrGetRouteFailed indicates a route get operation failed.
type ErrGetRouteFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetRouteFailed) Error() string {
	return fmt.Sprintf("failed to get proxy route %q: %v", e.ID, e.Cause)
}

func (e *ErrGetRouteFailed) Unwrap() error { return e.Cause }

// ErrUpdateRouteFailed indicates a route update operation failed.
type ErrUpdateRouteFailed struct {
	ID    string
	Cause error
}

func (e *ErrUpdateRouteFailed) Error() string {
	return fmt.Sprintf("failed to update proxy route %q: %v", e.ID, e.Cause)
}

func (e *ErrUpdateRouteFailed) Unwrap() error { return e.Cause }

// ErrDeleteRouteFailed indicates a route delete operation failed.
type ErrDeleteRouteFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteRouteFailed) Error() string {
	return fmt.Sprintf("failed to delete proxy route %q: %v", e.ID, e.Cause)
}

func (e *ErrDeleteRouteFailed) Unwrap() error { return e.Cause }

// ErrListRoutesFailed indicates a route list operation failed.
type ErrListRoutesFailed struct {
	Cause error
}

func (e *ErrListRoutesFailed) Error() string {
	return fmt.Sprintf("failed to list proxy routes: %v", e.Cause)
}

func (e *ErrListRoutesFailed) Unwrap() error { return e.Cause }

// Pool errors

// ErrCreatePoolFailed indicates a pool create operation failed.
type ErrCreatePoolFailed struct {
	ID    string
	Cause error
}

func (e *ErrCreatePoolFailed) Error() string {
	return fmt.Sprintf("failed to create proxy pool %q: %v", e.ID, e.Cause)
}

func (e *ErrCreatePoolFailed) Unwrap() error { return e.Cause }

// ErrGetPoolFailed indicates a pool get operation failed.
type ErrGetPoolFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetPoolFailed) Error() string {
	return fmt.Sprintf("failed to get proxy pool %q: %v", e.ID, e.Cause)
}

func (e *ErrGetPoolFailed) Unwrap() error { return e.Cause }

// ErrUpdatePoolFailed indicates a pool update operation failed.
type ErrUpdatePoolFailed struct {
	ID    string
	Cause error
}

func (e *ErrUpdatePoolFailed) Error() string {
	return fmt.Sprintf("failed to update proxy pool %q: %v", e.ID, e.Cause)
}

func (e *ErrUpdatePoolFailed) Unwrap() error { return e.Cause }

// ErrDeletePoolFailed indicates a pool delete operation failed.
type ErrDeletePoolFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeletePoolFailed) Error() string {
	return fmt.Sprintf("failed to delete proxy pool %q: %v", e.ID, e.Cause)
}

func (e *ErrDeletePoolFailed) Unwrap() error { return e.Cause }

// ErrListPoolsFailed indicates a pool list operation failed.
type ErrListPoolsFailed struct {
	Cause error
}

func (e *ErrListPoolsFailed) Error() string {
	return fmt.Sprintf("failed to list proxy pools: %v", e.Cause)
}

func (e *ErrListPoolsFailed) Unwrap() error { return e.Cause }

// Config / status / reload / zone matrix errors

// ErrGetConfigFailed indicates a config fetch failed.
type ErrGetConfigFailed struct {
	Cause error
}

func (e *ErrGetConfigFailed) Error() string {
	return fmt.Sprintf("failed to get proxy config: %v", e.Cause)
}

func (e *ErrGetConfigFailed) Unwrap() error { return e.Cause }

// ErrGetStatusFailed indicates a status fetch failed.
type ErrGetStatusFailed struct {
	Cause error
}

func (e *ErrGetStatusFailed) Error() string {
	return fmt.Sprintf("failed to get proxy status: %v", e.Cause)
}

func (e *ErrGetStatusFailed) Unwrap() error { return e.Cause }

// ErrReloadFailed indicates a config reload failed.
type ErrReloadFailed struct {
	Cause error
}

func (e *ErrReloadFailed) Error() string {
	return fmt.Sprintf("failed to reload proxy config: %v", e.Cause)
}

func (e *ErrReloadFailed) Unwrap() error { return e.Cause }

// ErrZoneMatrixFailed indicates a zone matrix fetch failed.
type ErrZoneMatrixFailed struct {
	Cause error
}

func (e *ErrZoneMatrixFailed) Error() string {
	return fmt.Sprintf("failed to get proxy zone matrix: %v", e.Cause)
}

func (e *ErrZoneMatrixFailed) Unwrap() error { return e.Cause }
