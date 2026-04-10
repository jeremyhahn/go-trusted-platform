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

package container

import (
	"errors"
	"testing"
)

func TestContainerError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *ContainerError
		expected string
	}{
		{
			name: "with container ID",
			err: &ContainerError{
				ContainerID: "abc123",
				Operation:   "start",
				Err:         ErrContainerStopped,
			},
			expected: "start [abc123]: container is stopped",
		},
		{
			name: "with container name",
			err: &ContainerError{
				ContainerName: "my-container",
				Operation:     "stop",
				Err:           ErrContainerRunning,
			},
			expected: "stop [my-container]: container is running",
		},
		{
			name: "with both ID and name prefers ID",
			err: &ContainerError{
				ContainerID:   "abc123",
				ContainerName: "my-container",
				Operation:     "remove",
				Err:           ErrContainerNotFound,
			},
			expected: "remove [abc123]: container not found",
		},
		{
			name: "without ID or name",
			err: &ContainerError{
				Operation: "create",
				Err:       ErrInvalidSpec,
			},
			expected: "create: invalid container specification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ContainerError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestContainerError_Unwrap(t *testing.T) {
	t.Parallel()

	underlying := ErrContainerNotFound
	err := &ContainerError{
		ContainerID: "abc123",
		Operation:   "get",
		Err:         underlying,
	}

	if unwrapped := err.Unwrap(); unwrapped != underlying {
		t.Errorf("ContainerError.Unwrap() = %v, want %v", unwrapped, underlying)
	}
}

func TestContainerError_Is(t *testing.T) {
	t.Parallel()

	err := &ContainerError{
		ContainerID: "abc123",
		Operation:   "start",
		Err:         ErrContainerStopped,
	}

	if !err.Is(ErrContainerStopped) {
		t.Error("ContainerError.Is() should return true for matching error")
	}

	if err.Is(ErrContainerRunning) {
		t.Error("ContainerError.Is() should return false for non-matching error")
	}
}

func TestContainerError_ErrorsIs(t *testing.T) {
	t.Parallel()

	err := NewContainerError("abc123", "my-container", "start", ErrContainerStopped)

	if !errors.Is(err, ErrContainerStopped) {
		t.Error("errors.Is() should return true for matching error")
	}

	if errors.Is(err, ErrContainerRunning) {
		t.Error("errors.Is() should return false for non-matching error")
	}
}

func TestNewContainerError(t *testing.T) {
	t.Parallel()

	err := NewContainerError("id123", "test-container", "create", ErrContainerExists)

	if err.ContainerID != "id123" {
		t.Errorf("ContainerID = %q, want %q", err.ContainerID, "id123")
	}

	if err.ContainerName != "test-container" {
		t.Errorf("ContainerName = %q, want %q", err.ContainerName, "test-container")
	}

	if err.Operation != "create" {
		t.Errorf("Operation = %q, want %q", err.Operation, "create")
	}

	if err.Err != ErrContainerExists {
		t.Errorf("Err = %v, want %v", err.Err, ErrContainerExists)
	}
}

func TestPolicyError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *PolicyError
		expected string
	}{
		{
			name: "with reasons",
			err: &PolicyError{
				PolicyName: "container.security",
				Reasons:    []string{"image not signed", "privileged not allowed"},
				Err:        ErrPolicyDenied,
			},
			expected: "container.security: image not signed",
		},
		{
			name: "without reasons",
			err: &PolicyError{
				PolicyName: "container.security",
				Reasons:    nil,
				Err:        ErrPolicyDenied,
			},
			expected: "container.security: policy denied operation",
		},
		{
			name: "empty reasons",
			err: &PolicyError{
				PolicyName: "container.security",
				Reasons:    []string{},
				Err:        ErrPolicyDenied,
			},
			expected: "container.security: policy denied operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("PolicyError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestPolicyError_Unwrap(t *testing.T) {
	t.Parallel()

	err := &PolicyError{
		PolicyName: "test",
		Err:        ErrPolicyDenied,
	}

	if unwrapped := err.Unwrap(); unwrapped != ErrPolicyDenied {
		t.Errorf("PolicyError.Unwrap() = %v, want %v", unwrapped, ErrPolicyDenied)
	}
}

func TestPolicyError_Is(t *testing.T) {
	t.Parallel()

	err := &PolicyError{
		PolicyName: "test",
		Err:        ErrPolicyDenied,
	}

	if !err.Is(ErrPolicyDenied) {
		t.Error("PolicyError.Is() should return true for matching error")
	}

	if err.Is(ErrAttestationFailed) {
		t.Error("PolicyError.Is() should return false for non-matching error")
	}
}

func TestNewPolicyError(t *testing.T) {
	t.Parallel()

	reasons := []string{"reason1", "reason2"}
	err := NewPolicyError("container.security", reasons)

	if err.PolicyName != "container.security" {
		t.Errorf("PolicyName = %q, want %q", err.PolicyName, "container.security")
	}

	if len(err.Reasons) != 2 {
		t.Errorf("Reasons length = %d, want 2", len(err.Reasons))
	}

	if err.Err != ErrPolicyDenied {
		t.Errorf("Err = %v, want %v", err.Err, ErrPolicyDenied)
	}
}

func TestAttestationError_Error(t *testing.T) {
	t.Parallel()

	err := &AttestationError{
		ContainerID: "abc123",
		ExpectedPCR: []byte{0x01, 0x02},
		ActualPCR:   []byte{0x03, 0x04},
		Err:         ErrPCRMismatch,
	}

	expected := "attestation [abc123]: PCR value mismatch"
	if got := err.Error(); got != expected {
		t.Errorf("AttestationError.Error() = %q, want %q", got, expected)
	}
}

func TestAttestationError_Unwrap(t *testing.T) {
	t.Parallel()

	err := &AttestationError{
		ContainerID: "abc123",
		Err:         ErrAttestationFailed,
	}

	if unwrapped := err.Unwrap(); unwrapped != ErrAttestationFailed {
		t.Errorf("AttestationError.Unwrap() = %v, want %v", unwrapped, ErrAttestationFailed)
	}
}

func TestAttestationError_Is(t *testing.T) {
	t.Parallel()

	err := &AttestationError{
		ContainerID: "abc123",
		Err:         ErrPCRMismatch,
	}

	if !err.Is(ErrPCRMismatch) {
		t.Error("AttestationError.Is() should return true for matching error")
	}

	if err.Is(ErrQuoteVerificationFailed) {
		t.Error("AttestationError.Is() should return false for non-matching error")
	}
}

func TestNewAttestationError(t *testing.T) {
	t.Parallel()

	expected := []byte{0x01, 0x02}
	actual := []byte{0x03, 0x04}
	err := NewAttestationError("container1", expected, actual, ErrPCRMismatch)

	if err.ContainerID != "container1" {
		t.Errorf("ContainerID = %q, want %q", err.ContainerID, "container1")
	}

	if string(err.ExpectedPCR) != string(expected) {
		t.Errorf("ExpectedPCR = %v, want %v", err.ExpectedPCR, expected)
	}

	if string(err.ActualPCR) != string(actual) {
		t.Errorf("ActualPCR = %v, want %v", err.ActualPCR, actual)
	}

	if err.Err != ErrPCRMismatch {
		t.Errorf("Err = %v, want %v", err.Err, ErrPCRMismatch)
	}
}

func TestImageError_Error(t *testing.T) {
	t.Parallel()

	err := &ImageError{
		ImageRef: "registry.example.com/app:v1",
		Registry: "registry.example.com",
		Err:      ErrImageNotFound,
	}

	expected := "image [registry.example.com/app:v1]: image not found"
	if got := err.Error(); got != expected {
		t.Errorf("ImageError.Error() = %q, want %q", got, expected)
	}
}

func TestImageError_Unwrap(t *testing.T) {
	t.Parallel()

	err := &ImageError{
		ImageRef: "test:latest",
		Err:      ErrImageVerificationFailed,
	}

	if unwrapped := err.Unwrap(); unwrapped != ErrImageVerificationFailed {
		t.Errorf("ImageError.Unwrap() = %v, want %v", unwrapped, ErrImageVerificationFailed)
	}
}

func TestImageError_Is(t *testing.T) {
	t.Parallel()

	err := &ImageError{
		ImageRef: "test:latest",
		Err:      ErrImageNotFound,
	}

	if !err.Is(ErrImageNotFound) {
		t.Error("ImageError.Is() should return true for matching error")
	}

	if err.Is(ErrImageVerificationFailed) {
		t.Error("ImageError.Is() should return false for non-matching error")
	}
}

func TestNewImageError(t *testing.T) {
	t.Parallel()

	err := NewImageError("docker.io/library/nginx:latest", "docker.io", ErrImagePullFailed)

	if err.ImageRef != "docker.io/library/nginx:latest" {
		t.Errorf("ImageRef = %q, want %q", err.ImageRef, "docker.io/library/nginx:latest")
	}

	if err.Registry != "docker.io" {
		t.Errorf("Registry = %q, want %q", err.Registry, "docker.io")
	}

	if err.Err != ErrImagePullFailed {
		t.Errorf("Err = %v, want %v", err.Err, ErrImagePullFailed)
	}
}

func TestSentinelErrors_AreDistinct(t *testing.T) {
	t.Parallel()

	// Ensure all sentinel errors are distinct
	allErrors := []error{
		ErrContainerNotFound,
		ErrContainerExists,
		ErrContainerRunning,
		ErrContainerStopped,
		ErrInvalidSpec,
		ErrInvalidName,
		ErrInvalidImage,
		ErrInvalidNetworkMode,
		ErrInvalidServiceMode,
		ErrInvalidResourceConfig,
		ErrInvalidMountConfig,
		ErrPolicyDenied,
		ErrAttestationFailed,
		ErrAttestationRequired,
		ErrPCRMismatch,
		ErrMeasurementLogInvalid,
		ErrQuoteVerificationFailed,
		ErrNetworkSetupFailed,
		ErrNetworkTeardownFailed,
		ErrOVSConnectionFailed,
		ErrVLANConfigFailed,
		ErrOpenFlowRuleFailed,
		ErrServiceError,
		ErrUnsupportedInitSystem,
		ErrServiceFileGeneration,
		ErrServiceStart,
		ErrServiceStop,
		ErrImageNotFound,
		ErrImageVerificationFailed,
		ErrImagePullFailed,
		ErrImageSignatureRequired,
		ErrRegistryUnreachable,
		ErrRegistryAuthFailed,
		ErrOrchestratorNotInitialized,
		ErrOrchestratorClosed,
		ErrPodmanNotAvailable,
		ErrOperationTimeout,
		ErrInvalidContainerID,
	}

	seen := make(map[string]int)
	for i, err := range allErrors {
		msg := err.Error()
		if prev, exists := seen[msg]; exists {
			t.Errorf("Error at index %d has same message as error at index %d: %q", i, prev, msg)
		}
		seen[msg] = i
	}
}

func TestSentinelErrors_NotNil(t *testing.T) {
	t.Parallel()

	allErrors := []error{
		ErrContainerNotFound,
		ErrContainerExists,
		ErrContainerRunning,
		ErrContainerStopped,
		ErrInvalidSpec,
		ErrPolicyDenied,
		ErrAttestationFailed,
		ErrNetworkSetupFailed,
		ErrServiceError,
		ErrImageNotFound,
		ErrImageVerificationFailed,
	}

	for i, err := range allErrors {
		if err == nil {
			t.Errorf("Error at index %d is nil", i)
		}
	}
}

func TestWrappedErrors_PreserveContext(t *testing.T) {
	t.Parallel()

	containerErr := NewContainerError("id1", "name1", "op1", ErrContainerNotFound)
	policyErr := NewPolicyError("policy1", []string{"reason1"})
	attestErr := NewAttestationError("id2", nil, nil, ErrPCRMismatch)
	imageErr := NewImageError("image1", "registry1", ErrImageNotFound)

	// Verify error wrapping works with errors.Is
	if !errors.Is(containerErr, ErrContainerNotFound) {
		t.Error("ContainerError should wrap ErrContainerNotFound")
	}

	if !errors.Is(policyErr, ErrPolicyDenied) {
		t.Error("PolicyError should wrap ErrPolicyDenied")
	}

	if !errors.Is(attestErr, ErrPCRMismatch) {
		t.Error("AttestationError should wrap ErrPCRMismatch")
	}

	if !errors.Is(imageErr, ErrImageNotFound) {
		t.Error("ImageError should wrap ErrImageNotFound")
	}
}
