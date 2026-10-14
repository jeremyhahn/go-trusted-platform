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

package iam

import (
	"testing"
)

func TestErrMissingTenantID_Error(t *testing.T) {
	err := ErrMissingTenantID{}
	expected := "tenant ID is required"
	if err.Error() != expected {
		t.Errorf("ErrMissingTenantID.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrMissingUserID_Error(t *testing.T) {
	err := ErrMissingUserID{}
	expected := "user ID is required"
	if err.Error() != expected {
		t.Errorf("ErrMissingUserID.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrMissingEmail_Error(t *testing.T) {
	err := ErrMissingEmail{}
	expected := "email is required"
	if err.Error() != expected {
		t.Errorf("ErrMissingEmail.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrMissingRoleID_Error(t *testing.T) {
	err := ErrMissingRoleID{}
	expected := "role ID is required"
	if err.Error() != expected {
		t.Errorf("ErrMissingRoleID.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrMissingRole_Error(t *testing.T) {
	err := ErrMissingRole{}
	expected := "role is required"
	if err.Error() != expected {
		t.Errorf("ErrMissingRole.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrMissingPolicyName_Error(t *testing.T) {
	err := ErrMissingPolicyName{}
	expected := "policy name is required"
	if err.Error() != expected {
		t.Errorf("ErrMissingPolicyName.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrMissingClientID_Error(t *testing.T) {
	err := ErrMissingClientID{}
	expected := "client ID is required"
	if err.Error() != expected {
		t.Errorf("ErrMissingClientID.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrMissingAppName_Error(t *testing.T) {
	err := ErrMissingAppName{}
	expected := "application name is required"
	if err.Error() != expected {
		t.Errorf("ErrMissingAppName.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrUserNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		userID   string
		expected string
	}{
		{
			name:     "basic user not found",
			tenantID: "tenant-1",
			userID:   "user-1",
			expected: "user not found: tenant=tenant-1, user=user-1",
		},
		{
			name:     "empty tenant ID",
			tenantID: "",
			userID:   "user-2",
			expected: "user not found: tenant=, user=user-2",
		},
		{
			name:     "empty user ID",
			tenantID: "tenant-2",
			userID:   "",
			expected: "user not found: tenant=tenant-2, user=",
		},
		{
			name:     "special characters",
			tenantID: "tenant-with-special-chars",
			userID:   "user-123-abc",
			expected: "user not found: tenant=tenant-with-special-chars, user=user-123-abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrUserNotFound{TenantID: tt.tenantID, UserID: tt.userID}
			if err.Error() != tt.expected {
				t.Errorf("ErrUserNotFound.Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}

func TestErrRoleNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		roleID   string
		expected string
	}{
		{
			name:     "basic role not found",
			tenantID: "tenant-1",
			roleID:   "admin",
			expected: "role not found: tenant=tenant-1, role=admin",
		},
		{
			name:     "empty tenant ID",
			tenantID: "",
			roleID:   "viewer",
			expected: "role not found: tenant=, role=viewer",
		},
		{
			name:     "empty role ID",
			tenantID: "tenant-2",
			roleID:   "",
			expected: "role not found: tenant=tenant-2, role=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrRoleNotFound{TenantID: tt.tenantID, RoleID: tt.roleID}
			if err.Error() != tt.expected {
				t.Errorf("ErrRoleNotFound.Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}

func TestErrTenantNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		expected string
	}{
		{
			name:     "basic tenant not found",
			tenantID: "acme",
			expected: "tenant not found: acme",
		},
		{
			name:     "empty tenant ID",
			tenantID: "",
			expected: "tenant not found: ",
		},
		{
			name:     "tenant with special characters",
			tenantID: "tenant-123-abc",
			expected: "tenant not found: tenant-123-abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrTenantNotFound{TenantID: tt.tenantID}
			if err.Error() != tt.expected {
				t.Errorf("ErrTenantNotFound.Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}

func TestErrPolicyNotFound_Error(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		policyName string
		expected   string
	}{
		{
			name:       "basic policy not found",
			tenantID:   "tenant-1",
			policyName: "admin-policy",
			expected:   "policy not found: tenant=tenant-1, policy=admin-policy",
		},
		{
			name:       "empty tenant ID",
			tenantID:   "",
			policyName: "viewer-policy",
			expected:   "policy not found: tenant=, policy=viewer-policy",
		},
		{
			name:       "empty policy name",
			tenantID:   "tenant-2",
			policyName: "",
			expected:   "policy not found: tenant=tenant-2, policy=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrPolicyNotFound{TenantID: tt.tenantID, PolicyName: tt.policyName}
			if err.Error() != tt.expected {
				t.Errorf("ErrPolicyNotFound.Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}

func TestErrAppNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		clientID string
		expected string
	}{
		{
			name:     "basic app not found",
			tenantID: "tenant-1",
			clientID: "client-abc-123",
			expected: "application not found: tenant=tenant-1, client=client-abc-123",
		},
		{
			name:     "empty tenant ID",
			tenantID: "",
			clientID: "client-456",
			expected: "application not found: tenant=, client=client-456",
		},
		{
			name:     "empty client ID",
			tenantID: "tenant-2",
			clientID: "",
			expected: "application not found: tenant=tenant-2, client=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrAppNotFound{TenantID: tt.tenantID, ClientID: tt.clientID}
			if err.Error() != tt.expected {
				t.Errorf("ErrAppNotFound.Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}

func TestErrInvalidPolicySpec_Error(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "basic invalid policy spec",
			reason:   "missing required field",
			expected: "invalid policy spec: missing required field",
		},
		{
			name:     "empty reason",
			reason:   "",
			expected: "invalid policy spec: ",
		},
		{
			name:     "syntax error reason",
			reason:   "syntax error on line 5",
			expected: "invalid policy spec: syntax error on line 5",
		},
		{
			name:     "policy file required",
			reason:   "policy file is required",
			expected: "invalid policy spec: policy file is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidPolicySpec{Reason: tt.reason}
			if err.Error() != tt.expected {
				t.Errorf("ErrInvalidPolicySpec.Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}

func TestErrorTypesImplementError(t *testing.T) {
	// Verify all error types implement the error interface
	var _ error = ErrMissingTenantID{}
	var _ error = ErrMissingUserID{}
	var _ error = ErrMissingEmail{}
	var _ error = ErrMissingRoleID{}
	var _ error = ErrMissingRole{}
	var _ error = ErrMissingPolicyName{}
	var _ error = ErrMissingClientID{}
	var _ error = ErrMissingAppName{}
	var _ error = ErrUserNotFound{}
	var _ error = ErrRoleNotFound{}
	var _ error = ErrTenantNotFound{}
	var _ error = ErrPolicyNotFound{}
	var _ error = ErrAppNotFound{}
	var _ error = ErrInvalidPolicySpec{}
}

func TestErrorTypesAreDistinct(t *testing.T) {
	// Verify error types produce distinct messages
	errors := map[string]error{
		"missing tenant":  ErrMissingTenantID{},
		"missing user":    ErrMissingUserID{},
		"missing email":   ErrMissingEmail{},
		"missing role id": ErrMissingRoleID{},
		"missing role":    ErrMissingRole{},
		"missing policy":  ErrMissingPolicyName{},
		"missing client":  ErrMissingClientID{},
		"missing app":     ErrMissingAppName{},
	}

	seen := make(map[string]string)
	for name, err := range errors {
		msg := err.Error()
		if existing, ok := seen[msg]; ok {
			t.Errorf("duplicate error message %q: %s and %s", msg, existing, name)
		}
		seen[msg] = name
	}
}
