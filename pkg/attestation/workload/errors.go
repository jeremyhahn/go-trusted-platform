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

package workload

import "fmt"

// ErrChainNotInitialized indicates the chain manager has not been initialized.
type ErrChainNotInitialized struct{}

func (e ErrChainNotInitialized) Error() string {
	return "workload: chain manager not initialized"
}

// ErrInvalidWorkloadType indicates an invalid workload type was provided.
type ErrInvalidWorkloadType struct {
	Type string
}

func (e ErrInvalidWorkloadType) Error() string {
	if e.Type != "" {
		return fmt.Sprintf("workload: invalid workload type %q, must be 'vm' or 'container'", e.Type)
	}
	return "workload: invalid workload type, must be 'vm' or 'container'"
}

// ErrInvalidWorkloadID indicates an invalid workload ID was provided.
type ErrInvalidWorkloadID struct {
	Reason string
}

func (e ErrInvalidWorkloadID) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("workload: invalid workload ID: %s", e.Reason)
	}
	return "workload: invalid workload ID"
}

// ErrPCRExtensionFailed indicates a PCR extension operation failed.
type ErrPCRExtensionFailed struct {
	PCR   int
	Cause error
}

func (e ErrPCRExtensionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("workload: PCR %d extension failed: %v", e.PCR, e.Cause)
	}
	return fmt.Sprintf("workload: PCR %d extension failed", e.PCR)
}

func (e ErrPCRExtensionFailed) Unwrap() error {
	return e.Cause
}

// ErrChainVerificationFailed indicates the measurement chain verification failed.
type ErrChainVerificationFailed struct {
	Reason string
	Cause  error
}

func (e ErrChainVerificationFailed) Error() string {
	msg := "workload: chain verification failed"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrChainVerificationFailed) Unwrap() error {
	return e.Cause
}

// ErrTPMNotAvailable indicates the TPM is not available.
type ErrTPMNotAvailable struct {
	Cause error
}

func (e ErrTPMNotAvailable) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("workload: TPM not available: %v", e.Cause)
	}
	return "workload: TPM not available"
}

func (e ErrTPMNotAvailable) Unwrap() error {
	return e.Cause
}

// ErrInvalidConfig indicates invalid configuration.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("workload: invalid config for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("workload: invalid config: %s", e.Reason)
}

// ErrPCRReadFailed indicates a PCR read operation failed.
type ErrPCRReadFailed struct {
	PCR   int
	Cause error
}

func (e ErrPCRReadFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("workload: PCR %d read failed: %v", e.PCR, e.Cause)
	}
	return fmt.Sprintf("workload: PCR %d read failed", e.PCR)
}

func (e ErrPCRReadFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidHashAlgorithm indicates an invalid hash algorithm was specified.
type ErrInvalidHashAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidHashAlgorithm) Error() string {
	if e.Algorithm != "" {
		return fmt.Sprintf("workload: invalid hash algorithm %q", e.Algorithm)
	}
	return "workload: invalid hash algorithm"
}

// ErrContextCanceled indicates the operation was canceled via context.
type ErrContextCanceled struct {
	Operation string
}

func (e ErrContextCanceled) Error() string {
	if e.Operation != "" {
		return fmt.Sprintf("workload: %s canceled", e.Operation)
	}
	return "workload: operation canceled"
}

// ErrChainEmpty indicates the chain has no entries.
type ErrChainEmpty struct{}

func (e ErrChainEmpty) Error() string {
	return "workload: chain has no entries"
}

// ErrChainAlreadyInitialized indicates the chain has already been initialized.
type ErrChainAlreadyInitialized struct{}

func (e ErrChainAlreadyInitialized) Error() string {
	return "workload: chain already initialized"
}

// ErrLifecycleNotInitialized indicates the lifecycle manager has not been initialized.
type ErrLifecycleNotInitialized struct{}

func (e ErrLifecycleNotInitialized) Error() string {
	return "workload: lifecycle manager not initialized"
}

// ErrWorkloadNotFound indicates the workload was not found.
type ErrWorkloadNotFound struct {
	WorkloadID string
}

func (e ErrWorkloadNotFound) Error() string {
	if e.WorkloadID != "" {
		return fmt.Sprintf("workload: workload %q not found", e.WorkloadID)
	}
	return "workload: workload not found"
}
