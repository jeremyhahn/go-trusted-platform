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

package tenant

import (
	"errors"
	"testing"
)

func TestErrMissingTenantName(t *testing.T) {
	err := ErrMissingTenantName{}
	expected := "tenant name is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrTenantNotFound(t *testing.T) {
	err := ErrTenantNotFound{Name: "test-tenant"}
	expected := "tenant not found: test-tenant"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidQuotaValue(t *testing.T) {
	err := ErrInvalidQuotaValue{
		Field:  "max_vms",
		Value:  -1,
		Reason: "must be non-negative",
	}
	expected := "invalid quota value for max_vms (-1): must be non-negative"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrOperationFailed(t *testing.T) {
	innerErr := errors.New("connection refused")
	err := ErrOperationFailed{
		Operation: "create",
		TenantID:  "test-tenant",
		Err:       innerErr,
	}
	expected := "tenant operation create failed for test-tenant: connection refused"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}

	// Test Unwrap
	if err.Unwrap() != innerErr {
		t.Error("Unwrap should return the inner error")
	}
}

func TestErrQuotaUpdateFailed(t *testing.T) {
	innerErr := errors.New("quota service unavailable")
	err := ErrQuotaUpdateFailed{
		TenantID: "test-tenant",
		Err:      innerErr,
	}
	expected := "failed to update quotas for tenant test-tenant: quota service unavailable"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}

	// Test Unwrap
	if err.Unwrap() != innerErr {
		t.Error("Unwrap should return the inner error")
	}
}

func TestErrUsageRetrievalFailed(t *testing.T) {
	innerErr := errors.New("usage tracker error")
	err := ErrUsageRetrievalFailed{
		TenantID: "test-tenant",
		Err:      innerErr,
	}
	expected := "failed to retrieve usage for tenant test-tenant: usage tracker error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}

	// Test Unwrap
	if err.Unwrap() != innerErr {
		t.Error("Unwrap should return the inner error")
	}
}

func TestErrTenantSuspended(t *testing.T) {
	err := ErrTenantSuspended{TenantID: "test-tenant"}
	expected := "tenant test-tenant is suspended"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrTenantAlreadyActive(t *testing.T) {
	err := ErrTenantAlreadyActive{TenantID: "test-tenant"}
	expected := "tenant test-tenant is already active"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

// Test that errors implement the error interface
func TestErrorsImplementErrorInterface(t *testing.T) {
	var _ error = ErrMissingTenantName{}
	var _ error = ErrTenantNotFound{}
	var _ error = ErrInvalidQuotaValue{}
	var _ error = ErrOperationFailed{}
	var _ error = ErrQuotaUpdateFailed{}
	var _ error = ErrUsageRetrievalFailed{}
	var _ error = ErrTenantSuspended{}
	var _ error = ErrTenantAlreadyActive{}
}
