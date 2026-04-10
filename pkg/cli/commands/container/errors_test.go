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
	"strings"
	"testing"
)

func TestErrContainerClientNotInitialized_Error(t *testing.T) {
	err := ErrContainerClientNotInitialized{}
	msg := err.Error()

	if !strings.Contains(msg, "container client not initialized") {
		t.Errorf("error message should contain 'container client not initialized', got %q", msg)
	}
}

func TestErrContainerNotFound_Error(t *testing.T) {
	err := ErrContainerNotFound{ID: "test-container-123"}
	msg := err.Error()

	if !strings.Contains(msg, "test-container-123") {
		t.Errorf("error message should contain container ID, got %q", msg)
	}
	if !strings.Contains(msg, "not found") {
		t.Errorf("error message should contain 'not found', got %q", msg)
	}
}

func TestErrContainerOperationFailed_Error(t *testing.T) {
	underlying := errors.New("connection refused")
	err := ErrContainerOperationFailed{
		Operation: "start",
		ID:        "test-container-123",
		Err:       underlying,
	}
	msg := err.Error()

	if !strings.Contains(msg, "start") {
		t.Errorf("error message should contain operation 'start', got %q", msg)
	}
	if !strings.Contains(msg, "test-container-123") {
		t.Errorf("error message should contain container ID, got %q", msg)
	}
	if !strings.Contains(msg, "connection refused") {
		t.Errorf("error message should contain underlying error, got %q", msg)
	}
}

func TestErrContainerOperationFailed_Unwrap(t *testing.T) {
	underlying := errors.New("connection refused")
	err := ErrContainerOperationFailed{
		Operation: "start",
		ID:        "test-container-123",
		Err:       underlying,
	}

	if !errors.Is(err, underlying) {
		t.Error("Unwrap should return the underlying error")
	}
}

func TestErrInvalidContainerConfig_Error(t *testing.T) {
	err := ErrInvalidContainerConfig{
		Field:  "name",
		Reason: "cannot be empty",
	}
	msg := err.Error()

	if !strings.Contains(msg, "name") {
		t.Errorf("error message should contain field 'name', got %q", msg)
	}
	if !strings.Contains(msg, "cannot be empty") {
		t.Errorf("error message should contain reason, got %q", msg)
	}
}

func TestErrInvalidEnvVar_Error(t *testing.T) {
	err := ErrInvalidEnvVar{Spec: "INVALID"}
	msg := err.Error()

	if !strings.Contains(msg, "INVALID") {
		t.Errorf("error message should contain spec, got %q", msg)
	}
	if !strings.Contains(msg, "KEY=value") {
		t.Errorf("error message should contain expected format, got %q", msg)
	}
}

func TestErrInvalidLabel_Error(t *testing.T) {
	err := ErrInvalidLabel{Spec: "invalid"}
	msg := err.Error()

	if !strings.Contains(msg, "invalid") {
		t.Errorf("error message should contain spec, got %q", msg)
	}
	if !strings.Contains(msg, "key=value") {
		t.Errorf("error message should contain expected format, got %q", msg)
	}
}

func TestErrInvalidPortMapping_Error(t *testing.T) {
	err := ErrInvalidPortMapping{Mapping: "8080"}
	msg := err.Error()

	if !strings.Contains(msg, "8080") {
		t.Errorf("error message should contain mapping, got %q", msg)
	}
	if !strings.Contains(msg, "hostPort:containerPort") {
		t.Errorf("error message should contain expected format, got %q", msg)
	}
}

func TestErrInvalidMountSpec_Error(t *testing.T) {
	err := ErrInvalidMountSpec{Spec: "/invalid"}
	msg := err.Error()

	if !strings.Contains(msg, "/invalid") {
		t.Errorf("error message should contain spec, got %q", msg)
	}
	if !strings.Contains(msg, "hostPath:containerPath") {
		t.Errorf("error message should contain expected format, got %q", msg)
	}
}

func TestErrInvalidMemorySpec_Error(t *testing.T) {
	err := ErrInvalidMemorySpec{Spec: "invalid"}
	msg := err.Error()

	if !strings.Contains(msg, "invalid") {
		t.Errorf("error message should contain spec, got %q", msg)
	}
	if !strings.Contains(msg, "512m") {
		t.Errorf("error message should contain example, got %q", msg)
	}
}

func TestErrInvalidCPUSpec_Error(t *testing.T) {
	err := ErrInvalidCPUSpec{Spec: "invalid"}
	msg := err.Error()

	if !strings.Contains(msg, "invalid") {
		t.Errorf("error message should contain spec, got %q", msg)
	}
	if !strings.Contains(msg, "0.5") {
		t.Errorf("error message should contain example, got %q", msg)
	}
}

func TestErrInvalidFilter_Error(t *testing.T) {
	err := ErrInvalidFilter{Filter: "invalid"}
	msg := err.Error()

	if !strings.Contains(msg, "invalid") {
		t.Errorf("error message should contain filter, got %q", msg)
	}
	if !strings.Contains(msg, "key=value") {
		t.Errorf("error message should contain expected format, got %q", msg)
	}
}

func TestErrAttestationFailed_Error(t *testing.T) {
	underlying := errors.New("TPM error")
	err := ErrAttestationFailed{
		ID:  "test-container-123",
		Err: underlying,
	}
	msg := err.Error()

	if !strings.Contains(msg, "test-container-123") {
		t.Errorf("error message should contain container ID, got %q", msg)
	}
	if !strings.Contains(msg, "TPM error") {
		t.Errorf("error message should contain underlying error, got %q", msg)
	}
}

func TestErrAttestationFailed_Unwrap(t *testing.T) {
	underlying := errors.New("TPM error")
	err := ErrAttestationFailed{
		ID:  "test-container-123",
		Err: underlying,
	}

	if !errors.Is(err, underlying) {
		t.Error("Unwrap should return the underlying error")
	}
}

func TestErrContainerAlreadyRunning_Error(t *testing.T) {
	err := ErrContainerAlreadyRunning{ID: "test-container-456"}
	msg := err.Error()

	if !strings.Contains(msg, "test-container-456") {
		t.Errorf("error message should contain container ID, got %q", msg)
	}
	if !strings.Contains(msg, "already running") {
		t.Errorf("error message should contain 'already running', got %q", msg)
	}
}

func TestErrContainerNotRunning_Error(t *testing.T) {
	err := ErrContainerNotRunning{ID: "test-container-789"}
	msg := err.Error()

	if !strings.Contains(msg, "test-container-789") {
		t.Errorf("error message should contain container ID, got %q", msg)
	}
	if !strings.Contains(msg, "not running") {
		t.Errorf("error message should contain 'not running', got %q", msg)
	}
}
