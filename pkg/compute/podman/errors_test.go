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

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerError_Error(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
		operation   string
		err         error
		expected    string
	}{
		{
			name:        "with container ID",
			containerID: "abc123",
			operation:   "start",
			err:         ErrContainerNotRunning,
			expected:    "container abc123: start: container is not running",
		},
		{
			name:        "without container ID",
			containerID: "",
			operation:   "list",
			err:         ErrConnectionFailed,
			expected:    "list: connection to podman socket failed",
		},
		{
			name:        "with custom error",
			containerID: "xyz789",
			operation:   "stop",
			err:         errors.New("custom error"),
			expected:    "container xyz789: stop: custom error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewContainerError(tt.containerID, tt.operation, tt.err)
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestContainerError_Unwrap(t *testing.T) {
	baseErr := ErrContainerNotFound
	err := NewContainerError("abc123", "inspect", baseErr)

	unwrapped := errors.Unwrap(err)
	assert.Equal(t, baseErr, unwrapped)
	assert.True(t, errors.Is(err, ErrContainerNotFound))
}

func TestImageError_Error(t *testing.T) {
	tests := []struct {
		name      string
		imageRef  string
		operation string
		err       error
		expected  string
	}{
		{
			name:      "with image ref",
			imageRef:  "alpine:latest",
			operation: "pull",
			err:       ErrImagePullFailed,
			expected:  "image alpine:latest: pull: image pull failed",
		},
		{
			name:      "without image ref",
			imageRef:  "",
			operation: "list",
			err:       ErrConnectionFailed,
			expected:  "list: connection to podman socket failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewImageError(tt.imageRef, tt.operation, tt.err)
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestImageError_Unwrap(t *testing.T) {
	baseErr := ErrImageNotFound
	err := NewImageError("nginx:latest", "inspect", baseErr)

	unwrapped := errors.Unwrap(err)
	assert.Equal(t, baseErr, unwrapped)
	assert.True(t, errors.Is(err, ErrImageNotFound))
}

func TestConfigValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		message  string
		expected string
	}{
		{
			name:     "name field",
			field:    "name",
			message:  "container name is required",
			expected: "invalid configuration: name: container name is required",
		},
		{
			name:     "image field",
			field:    "image",
			message:  "image reference is required",
			expected: "invalid configuration: image: image reference is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewConfigValidationError(tt.field, tt.message)
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	// Verify all sentinel errors are properly defined
	sentinelErrors := []error{
		ErrPodmanNotAvailable,
		ErrContainerNotFound,
		ErrContainerAlreadyExists,
		ErrContainerNotRunning,
		ErrContainerAlreadyRunning,
		ErrImageNotFound,
		ErrImagePullFailed,
		ErrInvalidContainerConfig,
		ErrConnectionFailed,
		ErrTimeout,
		ErrClientNotConnected,
		ErrInvalidSocketPath,
		ErrAttestationFailed,
		ErrTPMNotAvailable,
		ErrContainerExecFailed,
		ErrNilConfig,
		ErrNilLogger,
	}

	for _, err := range sentinelErrors {
		require.NotNil(t, err)
		assert.NotEmpty(t, err.Error())
	}
}

func TestContainerError_ErrorChaining(t *testing.T) {
	// Test error chaining with multiple layers
	innerErr := ErrContainerNotFound
	middleErr := NewContainerError("abc123", "inspect", innerErr)
	outerErr := NewContainerError("", "get", middleErr)

	// Should be able to unwrap to find inner error
	assert.True(t, errors.Is(outerErr, ErrContainerNotFound))

	// Error message should include operation context
	assert.Contains(t, outerErr.Error(), "get")
}

func TestImageError_ErrorChaining(t *testing.T) {
	innerErr := ErrConnectionFailed
	middleErr := NewImageError("alpine:latest", "pull", innerErr)

	assert.True(t, errors.Is(middleErr, ErrConnectionFailed))
	assert.Contains(t, middleErr.Error(), "alpine:latest")
	assert.Contains(t, middleErr.Error(), "pull")
}

func TestNewContainerError_NilError(t *testing.T) {
	// Even with nil error, should create valid ContainerError
	err := NewContainerError("abc123", "test", nil)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "abc123")
	assert.Contains(t, err.Error(), "test")
}

func TestNewImageError_NilError(t *testing.T) {
	err := NewImageError("alpine", "test", nil)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "alpine")
	assert.Contains(t, err.Error(), "test")
}

func TestConfigValidationError_Fields(t *testing.T) {
	err := NewConfigValidationError("socket_path", "cannot be empty")

	// Verify fields are accessible
	assert.Equal(t, "socket_path", err.Field)
	assert.Equal(t, "cannot be empty", err.Message)
}

func TestContainerError_Fields(t *testing.T) {
	baseErr := ErrContainerNotRunning
	err := NewContainerError("test-container", "start", baseErr)

	assert.Equal(t, "test-container", err.ContainerID)
	assert.Equal(t, "start", err.Operation)
	assert.Equal(t, baseErr, err.Err)
}

func TestImageError_Fields(t *testing.T) {
	baseErr := ErrImagePullFailed
	err := NewImageError("nginx:alpine", "pull", baseErr)

	assert.Equal(t, "nginx:alpine", err.ImageRef)
	assert.Equal(t, "pull", err.Operation)
	assert.Equal(t, baseErr, err.Err)
}

func TestOCIRuntimeNotFoundError_Error(t *testing.T) {
	err := &OCIRuntimeNotFoundError{Runtime: "crun"}
	assert.Equal(t, "OCI runtime crun not found in PATH", err.Error())
}

func TestOCIRuntimeNotFoundError_Unwrap(t *testing.T) {
	err := &OCIRuntimeNotFoundError{Runtime: "crun"}
	assert.True(t, errors.Is(err, ErrOCIRuntimeNotFound))
}

func TestOCIRuntimeNotFoundError_ErrorAs(t *testing.T) {
	err := &OCIRuntimeNotFoundError{Runtime: "runc"}
	var target *OCIRuntimeNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "runc", target.Runtime)
}
