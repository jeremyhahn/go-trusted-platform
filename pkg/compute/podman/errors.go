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

package podman

import "errors"

var (
	// ErrPodmanNotAvailable is returned when the Podman service is not available
	ErrPodmanNotAvailable = errors.New("podman service not available")

	// ErrContainerNotFound is returned when a container cannot be found
	ErrContainerNotFound = errors.New("container not found")

	// ErrContainerAlreadyExists is returned when creating a container that already exists
	ErrContainerAlreadyExists = errors.New("container already exists")

	// ErrContainerNotRunning is returned when attempting an operation on a stopped container
	ErrContainerNotRunning = errors.New("container is not running")

	// ErrContainerAlreadyRunning is returned when attempting to start an already running container
	ErrContainerAlreadyRunning = errors.New("container is already running")

	// ErrImageNotFound is returned when an image cannot be found
	ErrImageNotFound = errors.New("image not found")

	// ErrImagePullFailed is returned when an image pull operation fails
	ErrImagePullFailed = errors.New("image pull failed")

	// ErrInvalidContainerConfig is returned when container configuration is invalid
	ErrInvalidContainerConfig = errors.New("invalid container configuration")

	// ErrConnectionFailed is returned when connection to Podman socket fails
	ErrConnectionFailed = errors.New("connection to podman socket failed")

	// ErrTimeout is returned when an operation times out
	ErrTimeout = errors.New("operation timeout")

	// ErrClientNotConnected is returned when the client is not connected
	ErrClientNotConnected = errors.New("client not connected")

	// ErrInvalidSocketPath is returned when the socket path is invalid
	ErrInvalidSocketPath = errors.New("invalid socket path")

	// ErrAttestationFailed is returned when container attestation fails
	ErrAttestationFailed = errors.New("container attestation failed")

	// ErrTPMNotAvailable is returned when TPM device is not available
	ErrTPMNotAvailable = errors.New("TPM device not available")

	// ErrContainerExecFailed is returned when container exec fails
	ErrContainerExecFailed = errors.New("container exec failed")

	// ErrNilConfig is returned when a nil configuration is provided
	ErrNilConfig = errors.New("configuration is nil")

	// ErrNilLogger is returned when a nil logger is provided
	ErrNilLogger = errors.New("logger is nil")

	// ErrOCIRuntimeNotFound is returned when the configured OCI runtime
	// binary cannot be found in the system PATH.
	ErrOCIRuntimeNotFound = errors.New("OCI runtime not found")
)

// OCIRuntimeNotFoundError provides details about a missing OCI runtime.
type OCIRuntimeNotFoundError struct {
	Runtime string
}

// Error returns the error message.
func (e *OCIRuntimeNotFoundError) Error() string {
	return "OCI runtime " + e.Runtime + " not found in PATH"
}

// Unwrap returns the sentinel error for type matching.
func (e *OCIRuntimeNotFoundError) Unwrap() error {
	return ErrOCIRuntimeNotFound
}

// ContainerError wraps an error with container context
type ContainerError struct {
	ContainerID string
	Operation   string
	Err         error
}

// Error returns the error message
func (e *ContainerError) Error() string {
	var errMsg string
	if e.Err != nil {
		errMsg = e.Err.Error()
	}
	if e.ContainerID != "" {
		if errMsg != "" {
			return "container " + e.ContainerID + ": " + e.Operation + ": " + errMsg
		}
		return "container " + e.ContainerID + ": " + e.Operation
	}
	if errMsg != "" {
		return e.Operation + ": " + errMsg
	}
	return e.Operation
}

// Unwrap returns the underlying error
func (e *ContainerError) Unwrap() error {
	return e.Err
}

// NewContainerError creates a new ContainerError
func NewContainerError(containerID, operation string, err error) *ContainerError {
	return &ContainerError{
		ContainerID: containerID,
		Operation:   operation,
		Err:         err,
	}
}

// ImageError wraps an error with image context
type ImageError struct {
	ImageRef  string
	Operation string
	Err       error
}

// Error returns the error message
func (e *ImageError) Error() string {
	var errMsg string
	if e.Err != nil {
		errMsg = e.Err.Error()
	}
	if e.ImageRef != "" {
		if errMsg != "" {
			return "image " + e.ImageRef + ": " + e.Operation + ": " + errMsg
		}
		return "image " + e.ImageRef + ": " + e.Operation
	}
	if errMsg != "" {
		return e.Operation + ": " + errMsg
	}
	return e.Operation
}

// Unwrap returns the underlying error
func (e *ImageError) Unwrap() error {
	return e.Err
}

// NewImageError creates a new ImageError
func NewImageError(imageRef, operation string, err error) *ImageError {
	return &ImageError{
		ImageRef:  imageRef,
		Operation: operation,
		Err:       err,
	}
}

// ConfigValidationError wraps validation errors with field context
type ConfigValidationError struct {
	Field   string
	Message string
}

// Error returns the error message
func (e *ConfigValidationError) Error() string {
	return "invalid configuration: " + e.Field + ": " + e.Message
}

// NewConfigValidationError creates a new ConfigValidationError
func NewConfigValidationError(field, message string) *ConfigValidationError {
	return &ConfigValidationError{
		Field:   field,
		Message: message,
	}
}
