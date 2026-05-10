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

package barrier

import "fmt"

// ErrInitFailed indicates a failure to initialize the barrier.
type ErrInitFailed struct {
	Cause error
}

func (e *ErrInitFailed) Error() string {
	return fmt.Sprintf("barrier: failed to initialize: %v", e.Cause)
}

func (e *ErrInitFailed) Unwrap() error { return e.Cause }

// ErrStatusFailed indicates a failure to retrieve barrier status.
type ErrStatusFailed struct {
	Cause error
}

func (e *ErrStatusFailed) Error() string {
	return fmt.Sprintf("barrier: failed to get status: %v", e.Cause)
}

func (e *ErrStatusFailed) Unwrap() error { return e.Cause }

// ErrUnsealFailed indicates a failure to unseal the barrier.
type ErrUnsealFailed struct {
	Cause error
}

func (e *ErrUnsealFailed) Error() string {
	return fmt.Sprintf("barrier: failed to unseal: %v", e.Cause)
}

func (e *ErrUnsealFailed) Unwrap() error { return e.Cause }

// ErrSealFailed indicates a failure to seal the barrier.
type ErrSealFailed struct {
	Cause error
}

func (e *ErrSealFailed) Error() string {
	return fmt.Sprintf("barrier: failed to seal: %v", e.Cause)
}

func (e *ErrSealFailed) Unwrap() error { return e.Cause }

// ErrRekeyFailed indicates a failure to rekey the barrier.
type ErrRekeyFailed struct {
	Cause error
}

func (e *ErrRekeyFailed) Error() string {
	return fmt.Sprintf("barrier: failed to rekey: %v", e.Cause)
}

func (e *ErrRekeyFailed) Unwrap() error { return e.Cause }
