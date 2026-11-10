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

import (
	"errors"
	"strings"
	"testing"
)

func TestErrComputeClientNotInitialized(t *testing.T) {
	err := ErrComputeClientNotInitialized{}

	if err.Error() != "compute client not initialized" {
		t.Errorf("unexpected error message: %q", err.Error())
	}

	// Verify it implements the error interface
	var e error = err
	if e.Error() != "compute client not initialized" {
		t.Errorf("unexpected error message through error interface: %q", e.Error())
	}
}

func TestErrComputeClientNotInitialized_TypeAssertion(t *testing.T) {
	var err error = ErrComputeClientNotInitialized{}

	if _, ok := err.(ErrComputeClientNotInitialized); !ok {
		t.Error("type assertion should succeed")
	}
}

func TestErrVMOperationFailed(t *testing.T) {
	underlying := errors.New("connection refused")
	err := ErrVMOperationFailed{
		Operation: "start",
		ID:        "vm-123",
		Err:       underlying,
	}

	msg := err.Error()
	if !strings.Contains(msg, "start") {
		t.Error("error message should contain operation")
	}
	if !strings.Contains(msg, "vm-123") {
		t.Error("error message should contain ID")
	}
	if !strings.Contains(msg, "connection refused") {
		t.Error("error message should contain underlying error")
	}
}

func TestErrVMOperationFailed_Unwrap(t *testing.T) {
	underlying := errors.New("timeout")
	err := ErrVMOperationFailed{
		Operation: "stop",
		ID:        "vm-456",
		Err:       underlying,
	}

	unwrapped := err.Unwrap()
	if unwrapped != underlying {
		t.Errorf("Unwrap should return underlying error, got %v", unwrapped)
	}

	if !errors.Is(err, underlying) {
		t.Error("errors.Is should match underlying error")
	}
}

func TestErrVMOperationFailed_NilUnderlying(t *testing.T) {
	err := ErrVMOperationFailed{
		Operation: "delete",
		ID:        "vm-789",
		Err:       nil,
	}

	if err.Unwrap() != nil {
		t.Error("Unwrap should return nil when no underlying error")
	}

	// Should not panic
	_ = err.Error()
}

func TestErrVMNotFound(t *testing.T) {
	err := ErrVMNotFound{ID: "missing-vm"}

	msg := err.Error()
	if !strings.Contains(msg, "missing-vm") {
		t.Error("error message should contain VM ID")
	}
	if !strings.Contains(msg, "not found") {
		t.Error("error message should contain 'not found'")
	}
}

func TestErrVMNotFound_EmptyID(t *testing.T) {
	err := ErrVMNotFound{ID: ""}

	msg := err.Error()
	if !strings.Contains(msg, "not found") {
		t.Error("error message should contain 'not found' even with empty ID")
	}
}

func TestErrInvalidVMConfig(t *testing.T) {
	err := ErrInvalidVMConfig{
		Field:  "memory",
		Reason: "must be positive",
	}

	msg := err.Error()
	if !strings.Contains(msg, "memory") {
		t.Error("error message should contain field name")
	}
	if !strings.Contains(msg, "must be positive") {
		t.Error("error message should contain reason")
	}
}

func TestErrInvalidVMConfig_EmptyFields(t *testing.T) {
	err := ErrInvalidVMConfig{}

	// Should not panic
	msg := err.Error()
	if msg == "" {
		t.Error("error message should not be empty")
	}
}

func TestErrInvalidVMState(t *testing.T) {
	err := ErrInvalidVMState{State: "BOGUS"}

	msg := err.Error()
	if !strings.Contains(msg, "BOGUS") {
		t.Error("error message should contain the invalid state")
	}
	if !strings.Contains(msg, "invalid") {
		t.Error("error message should contain 'invalid'")
	}
}

func TestErrInvalidVMState_EmptyState(t *testing.T) {
	err := ErrInvalidVMState{State: ""}

	// Should not panic
	msg := err.Error()
	if !strings.Contains(msg, "invalid") {
		t.Error("error message should contain 'invalid'")
	}
}

func TestErrInvalidFilter(t *testing.T) {
	err := ErrInvalidFilter{Filter: "noseparator"}

	msg := err.Error()
	if !strings.Contains(msg, "noseparator") {
		t.Error("error message should contain the filter string")
	}
	if !strings.Contains(msg, "expected format") {
		t.Error("error message should contain format hint")
	}
}

func TestErrInvalidFilter_EmptyFilter(t *testing.T) {
	err := ErrInvalidFilter{Filter: ""}

	// Should not panic
	msg := err.Error()
	if !strings.Contains(msg, "invalid filter") {
		t.Error("error message should contain 'invalid filter'")
	}
}
