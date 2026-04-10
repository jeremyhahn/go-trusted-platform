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

// ErrComputeClientNotInitialized is returned when the compute client is not initialized
type ErrComputeClientNotInitialized struct{}

// Error returns the error message
func (e ErrComputeClientNotInitialized) Error() string {
	return "compute client not initialized"
}

// ErrVMOperationFailed is returned when a VM operation fails
type ErrVMOperationFailed struct {
	Operation string
	ID        string
	Err       error
}

// Error returns the error message
func (e ErrVMOperationFailed) Error() string {
	return fmt.Sprintf("compute %s failed for %s: %v", e.Operation, e.ID, e.Err)
}

// Unwrap returns the underlying error
func (e ErrVMOperationFailed) Unwrap() error {
	return e.Err
}

// ErrVMNotFound is returned when a virtual machine cannot be found
type ErrVMNotFound struct {
	ID string
}

// Error returns the error message
func (e ErrVMNotFound) Error() string {
	return fmt.Sprintf("virtual machine not found: %s", e.ID)
}

// ErrInvalidVMConfig is returned when VM configuration is invalid
type ErrInvalidVMConfig struct {
	Field  string
	Reason string
}

// Error returns the error message
func (e ErrInvalidVMConfig) Error() string {
	return fmt.Sprintf("invalid vm config: %s - %s", e.Field, e.Reason)
}

// ErrInvalidVMState is returned when an invalid VM state is specified
type ErrInvalidVMState struct {
	State string
}

// Error returns the error message
func (e ErrInvalidVMState) Error() string {
	return fmt.Sprintf("invalid vm state: %s", e.State)
}

// ErrInvalidFilter is returned when an invalid filter is specified
type ErrInvalidFilter struct {
	Filter string
}

// Error returns the error message
func (e ErrInvalidFilter) Error() string {
	return fmt.Sprintf("invalid filter: %s (expected format: key=value)", e.Filter)
}
