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

import "errors"

var (
	// ErrInstanceNotFound is returned when an instance cannot be found
	ErrInstanceNotFound = errors.New("instance not found")

	// ErrInstanceAlreadyExists is returned when creating an instance that already exists
	ErrInstanceAlreadyExists = errors.New("instance already exists")

	// ErrInstanceNotRunning is returned when attempting an operation on a stopped instance
	ErrInstanceNotRunning = errors.New("instance is not running")

	// ErrInstanceAlreadyRunning is returned when attempting to start an already running instance
	ErrInstanceAlreadyRunning = errors.New("instance is already running")

	// ErrInstanceNotSuspended is returned when resuming an instance that is
	// not suspended
	ErrInstanceNotSuspended = errors.New("instance is not suspended")

	// ErrVMExitedDuringStart is returned when QEMU exits before its QMP
	// monitor accepts a connection; the cause carries QEMU's reason
	ErrVMExitedDuringStart = errors.New("QEMU exited during start")

	// ErrMonitorNotReady is returned when QEMU keeps running but its QMP
	// monitor does not accept a connection within the start deadline
	ErrMonitorNotReady = errors.New("QMP monitor not ready")

	// ErrInvalidConfiguration is returned when the configuration is invalid
	ErrInvalidConfiguration = errors.New("invalid configuration")

	// ErrUnsupportedHostArch is returned when the local QEMU defaults are
	// derived from a host architecture with no compute VM guest mapping
	ErrUnsupportedHostArch = errors.New("unsupported host architecture for compute VMs")

	// ErrInvalidInstanceID is returned when an instance ID is invalid
	ErrInvalidInstanceID = errors.New("invalid instance ID")

	// ErrInvalidProfile is returned when a device profile is invalid
	ErrInvalidProfile = errors.New("invalid device profile")

	// ErrNetworkAttachmentFailed is returned when network attachment fails
	ErrNetworkAttachmentFailed = errors.New("network attachment failed")

	// ErrNetworkDetachmentFailed is returned when network detachment fails
	ErrNetworkDetachmentFailed = errors.New("network detachment failed")

	// ErrOrchestratorNotInitialized is returned when orchestrator is not properly initialized
	ErrOrchestratorNotInitialized = errors.New("orchestrator not initialized")

	// ErrUnsupportedOperation is returned when an operation is not supported
	ErrUnsupportedOperation = errors.New("unsupported operation")

	// ErrInvalidState is returned when an instance is in an invalid state for the requested operation
	ErrInvalidState = errors.New("invalid instance state")

	// ErrTimeout is returned when an operation times out
	ErrTimeout = errors.New("operation timeout")

	// ErrResourceExhausted is returned when system resources are exhausted
	ErrResourceExhausted = errors.New("resource exhausted")

	// ErrUnsupportedDiskFormat is returned when an internal snapshot is
	// requested for an instance whose disk image is not qcow2
	ErrUnsupportedDiskFormat = errors.New("unsupported disk format: internal snapshots require qcow2")

	// ErrInvalidSnapshotName is returned when a snapshot name fails validation
	ErrInvalidSnapshotName = errors.New("invalid snapshot name")

	// ErrSnapshotNotFound is returned when a snapshot does not exist
	ErrSnapshotNotFound = errors.New("snapshot not found")

	// ErrVTPMNotAvailable is returned when an instance has no vTPM to attest
	ErrVTPMNotAvailable = errors.New("vTPM not available for instance")

	// ErrInvalidAttestationEvidence is returned when attestation evidence
	// submitted for verification is missing required fields
	ErrInvalidAttestationEvidence = errors.New("invalid attestation evidence")

	// ErrVTPMIdentityRequired is returned when a device profile requires a
	// hardware-rooted vTPM identity — because Secure Boot is enabled for the
	// instance, or the profile has a prestaged EK certificate / EK serial —
	// but no vTPM generator is wired into the orchestrator, so a
	// profile-bound, CA-issued EK bundle cannot be provisioned. The VM is NOT
	// booted with an anonymous swtpm in this case: falling back silently to an
	// identity-less TPM would defeat the profile's attestation contract. The
	// operator must wire the vTPM subsystem (and its CA) or clear the
	// profile's identity requirement.
	ErrVTPMIdentityRequired = errors.New("device profile requires a CA-issued vTPM identity but no vTPM generator is configured")
)

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}
