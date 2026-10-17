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

// Package container provides container orchestration with TPM-based attestation,
// OPA policy enforcement, and multi-protocol API exposure for the trusted platform.
package container

import "errors"

// Container lifecycle errors
var (
	// ErrContainerNotFound is returned when a container cannot be found.
	ErrContainerNotFound = errors.New("container not found")

	// ErrContainerExists is returned when attempting to create a container
	// that already exists.
	ErrContainerExists = errors.New("container already exists")

	// ErrContainerRunning is returned when an operation requires the container
	// to be stopped, but it is running.
	ErrContainerRunning = errors.New("container is running")

	// ErrContainerStopped is returned when an operation requires the container
	// to be running, but it is stopped.
	ErrContainerStopped = errors.New("container is stopped")
)

// Configuration and specification errors
var (
	// ErrInvalidSpec is returned when a container specification is invalid.
	ErrInvalidSpec = errors.New("invalid container specification")

	// ErrInvalidName is returned when a container name is invalid.
	ErrInvalidName = errors.New("invalid container name")

	// ErrInvalidImage is returned when an image reference is invalid.
	ErrInvalidImage = errors.New("invalid image reference")

	// ErrInvalidNetworkMode is returned when an unsupported network mode is specified.
	ErrInvalidNetworkMode = errors.New("invalid network mode")

	// ErrInvalidServiceMode is returned when an unsupported service mode is specified.
	ErrInvalidServiceMode = errors.New("invalid service mode")

	// ErrInvalidResourceConfig is returned when resource configuration is invalid.
	ErrInvalidResourceConfig = errors.New("invalid resource configuration")

	// ErrInvalidMountConfig is returned when a mount configuration is invalid.
	ErrInvalidMountConfig = errors.New("invalid mount configuration")

	// ErrNilContainerConfig is returned when a nil container configuration is provided.
	ErrNilContainerConfig = errors.New("container configuration is nil")

	// ErrEmptyContainerName is returned when an empty container name is provided.
	ErrEmptyContainerName = errors.New("container name is empty")

	// ErrInvalidEventType is returned when an invalid measurement event type is provided.
	ErrInvalidEventType = errors.New("invalid event type")
)

// Policy and attestation errors
var (
	// ErrPolicyDenied is returned when OPA policy evaluation denies an operation.
	ErrPolicyDenied = errors.New("policy denied operation")

	// ErrPolicyLoadFailed is returned when policy loading fails.
	ErrPolicyLoadFailed = errors.New("policy loading failed")

	// ErrPolicyEvaluationFailed is returned when policy evaluation fails.
	ErrPolicyEvaluationFailed = errors.New("policy evaluation failed")

	// ErrInvalidPolicyConfig is returned when policy configuration is invalid.
	ErrInvalidPolicyConfig = errors.New("invalid policy configuration")

	// ErrInvalidPolicyFile is returned when a policy file is invalid.
	ErrInvalidPolicyFile = errors.New("invalid policy file")

	// ErrPolicyBundleFetchFailed is returned when fetching a remote policy bundle fails.
	ErrPolicyBundleFetchFailed = errors.New("policy bundle fetch failed")

	// ErrAttestationFailed is returned when TPM attestation fails.
	ErrAttestationFailed = errors.New("attestation failed")

	// ErrAttestationRequired is returned when attestation is required but not provided.
	ErrAttestationRequired = errors.New("attestation required")

	// ErrPCRMismatch is returned when PCR values do not match expected values.
	ErrPCRMismatch = errors.New("PCR value mismatch")

	// ErrMeasurementLogInvalid is returned when the measurement log is corrupted or invalid.
	ErrMeasurementLogInvalid = errors.New("measurement log invalid")

	// ErrQuoteVerificationFailed is returned when TPM quote verification fails.
	ErrQuoteVerificationFailed = errors.New("quote verification failed")

	// ErrInvalidQuote is returned when a quote is nil or malformed.
	ErrInvalidQuote = errors.New("invalid quote")

	// ErrImageDigestResolverUnavailable is returned when a container must
	// be measured but no image digest resolver is configured, so its image
	// identity cannot be established.
	ErrImageDigestResolverUnavailable = errors.New("image digest resolver unavailable")
)

// Network errors
var (
	// ErrNetworkSetupFailed is returned when network configuration fails.
	ErrNetworkSetupFailed = errors.New("network setup failed")

	// ErrNetworkTeardownFailed is returned when network teardown fails.
	ErrNetworkTeardownFailed = errors.New("network teardown failed")

	// ErrOVSConnectionFailed is returned when connection to OVS fails.
	ErrOVSConnectionFailed = errors.New("OVS connection failed")

	// ErrVLANConfigFailed is returned when VLAN configuration fails.
	ErrVLANConfigFailed = errors.New("VLAN configuration failed")

	// ErrOpenFlowRuleFailed is returned when OpenFlow rule installation fails.
	ErrOpenFlowRuleFailed = errors.New("OpenFlow rule installation failed")
)

// Service errors
var (
	// ErrServiceError is returned when service management fails.
	ErrServiceError = errors.New("service error")

	// ErrUnsupportedInitSystem is returned when the init system is not supported.
	ErrUnsupportedInitSystem = errors.New("unsupported init system")

	// ErrServiceFileGeneration is returned when service file generation fails.
	ErrServiceFileGeneration = errors.New("service file generation failed")

	// ErrServiceStart is returned when starting a service fails.
	ErrServiceStart = errors.New("service start failed")

	// ErrServiceStop is returned when stopping a service fails.
	ErrServiceStop = errors.New("service stop failed")
)

// Image errors
var (
	// ErrImageNotFound is returned when a container image cannot be found.
	ErrImageNotFound = errors.New("image not found")

	// ErrImageVerificationFailed is returned when image signature verification fails.
	ErrImageVerificationFailed = errors.New("image verification failed")

	// ErrImagePullFailed is returned when pulling an image fails.
	ErrImagePullFailed = errors.New("image pull failed")

	// ErrImageSignatureRequired is returned when an unsigned image is rejected.
	ErrImageSignatureRequired = errors.New("image signature required")

	// ErrRegistryUnreachable is returned when the container registry is unreachable.
	ErrRegistryUnreachable = errors.New("registry unreachable")

	// ErrRegistryAuthFailed is returned when registry authentication fails.
	ErrRegistryAuthFailed = errors.New("registry authentication failed")

	// ErrImageManagerUnavailable is returned when an image verification was
	// requested but no ImageManager is configured, so neither the image's
	// content digest nor its endorsement can be established. It is an error
	// rather than an "unverified" result: a result naming no digest is not a
	// verdict about any artifact.
	ErrImageManagerUnavailable = errors.New("image manager unavailable")
)

// Orchestrator errors
var (
	// ErrOrchestratorNotInitialized is returned when the orchestrator is not initialized.
	ErrOrchestratorNotInitialized = errors.New("orchestrator not initialized")

	// ErrOrchestratorClosed is returned when operations are attempted on a closed orchestrator.
	ErrOrchestratorClosed = errors.New("orchestrator closed")

	// ErrPodmanNotAvailable is returned when podman is not available on the system.
	ErrPodmanNotAvailable = errors.New("podman not available")

	// ErrOperationTimeout is returned when an operation times out.
	ErrOperationTimeout = errors.New("operation timeout")

	// ErrInvalidContainerID is returned when a container ID is invalid.
	ErrInvalidContainerID = errors.New("invalid container ID")

	// ErrContainerNameRequired is returned when a create request carries no
	// container name. Every transport answers it the same way.
	ErrContainerNameRequired = errors.New("container name is required")
)

// ContainerError wraps an error with container-specific context.
type ContainerError struct {
	// ContainerID is the ID of the container that caused the error.
	ContainerID string

	// ContainerName is the name of the container that caused the error.
	ContainerName string

	// Operation is the operation that was being performed.
	Operation string

	// Err is the underlying error.
	Err error
}

// Error returns the error message.
func (e *ContainerError) Error() string {
	if e.ContainerID != "" {
		return e.Operation + " [" + e.ContainerID + "]: " + e.Err.Error()
	}
	if e.ContainerName != "" {
		return e.Operation + " [" + e.ContainerName + "]: " + e.Err.Error()
	}
	return e.Operation + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ContainerError) Unwrap() error {
	return e.Err
}

// Is reports whether target matches this error.
func (e *ContainerError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// NewContainerError creates a new ContainerError with the given context.
func NewContainerError(containerID, containerName, operation string, err error) *ContainerError {
	return &ContainerError{
		ContainerID:   containerID,
		ContainerName: containerName,
		Operation:     operation,
		Err:           err,
	}
}

// PolicyError wraps a policy denial with additional context.
type PolicyError struct {
	// PolicyName is the name of the policy that denied the operation.
	PolicyName string

	// Reasons contains the denial reasons from policy evaluation.
	Reasons []string

	// Err is the underlying error.
	Err error
}

// Error returns the error message.
func (e *PolicyError) Error() string {
	if len(e.Reasons) > 0 {
		return e.PolicyName + ": " + e.Reasons[0]
	}
	return e.PolicyName + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *PolicyError) Unwrap() error {
	return e.Err
}

// Is reports whether target matches this error.
func (e *PolicyError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// NewPolicyError creates a new PolicyError with the given context.
func NewPolicyError(policyName string, reasons []string) *PolicyError {
	return &PolicyError{
		PolicyName: policyName,
		Reasons:    reasons,
		Err:        ErrPolicyDenied,
	}
}

// AttestationError wraps an attestation failure with additional context.
type AttestationError struct {
	// ContainerID is the ID of the container.
	ContainerID string

	// ExpectedPCR is the expected PCR value.
	ExpectedPCR []byte

	// ActualPCR is the actual PCR value from the quote.
	ActualPCR []byte

	// Err is the underlying error.
	Err error
}

// Error returns the error message.
func (e *AttestationError) Error() string {
	return "attestation [" + e.ContainerID + "]: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *AttestationError) Unwrap() error {
	return e.Err
}

// Is reports whether target matches this error.
func (e *AttestationError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// NewAttestationError creates a new AttestationError with the given context.
func NewAttestationError(containerID string, expected, actual []byte, err error) *AttestationError {
	return &AttestationError{
		ContainerID: containerID,
		ExpectedPCR: expected,
		ActualPCR:   actual,
		Err:         err,
	}
}

// ImageError wraps an image-related error with additional context.
type ImageError struct {
	// ImageRef is the image reference (registry/repo:tag).
	ImageRef string

	// Registry is the registry host.
	Registry string

	// Err is the underlying error.
	Err error
}

// Error returns the error message.
func (e *ImageError) Error() string {
	return "image [" + e.ImageRef + "]: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ImageError) Unwrap() error {
	return e.Err
}

// Is reports whether target matches this error.
func (e *ImageError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// NewImageError creates a new ImageError with the given context.
func NewImageError(imageRef, registry string, err error) *ImageError {
	return &ImageError{
		ImageRef: imageRef,
		Registry: registry,
		Err:      err,
	}
}

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

// ResourceValueError reports a declared resource limit that cannot be applied
// because its value is not a quantity the runtime understands.
//
// It fails the launch rather than dropping the limit: a container that starts
// without the constraint its specification declared is not the container the
// operator asked for.
type ResourceValueError struct {
	// Field is the resource field that carried the value.
	Field string

	// Value is the value as declared.
	Value string
}

// Error implements the error interface.
func (e *ResourceValueError) Error() string {
	return "invalid resource limit " + e.Field + ": " + e.Value
}

// Unwrap reports the sentinel so callers can match the whole class with
// errors.Is(err, ErrInvalidResourceConfig).
func (e *ResourceValueError) Unwrap() error {
	return ErrInvalidResourceConfig
}
