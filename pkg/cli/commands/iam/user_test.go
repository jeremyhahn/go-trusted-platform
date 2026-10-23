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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrTestContext is a test error for context failures
type ErrTestContext struct {
	Message string
}

func (e ErrTestContext) Error() string {
	return e.Message
}

// makeTestFlags creates CommonFlags with a configurable GetContext function
func makeTestFlags(getContextErr error) *cli.CommonFlags {
	return &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		GetContext: func() (*cli.Context, error) {
			if getContextErr != nil {
				return nil, getContextErr
			}
			// Return a minimal context that will fail on actual connection
			// This allows us to test the flow up to the point of connection
			return &cli.Context{
				Name: "test",
				Type: cli.ContextTypeLocal,
				Local: &cli.LocalContext{
					SocketPath: "/nonexistent/socket.sock",
				},
			}, nil
		},
	}
}

// TestRunUserCreate_MissingTenantID tests that runUserCreate returns error when tenant is empty
func TestRunUserCreate_MissingTenantID(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newUserCreateCommand(getFlags)
	cmd.SetArgs([]string{"--email", "test@example.com"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing tenant ID")
	}

	var missingTenantErr ErrMissingTenantID
	if !errors.As(err, &missingTenantErr) {
		t.Errorf("expected ErrMissingTenantID, got %T: %v", err, err)
	}
}

// TestRunUserCreate_MissingEmail tests that runUserCreate returns error when email is empty
func TestRunUserCreate_MissingEmail(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newUserCreateCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing email")
	}

	var missingEmailErr ErrMissingEmail
	if !errors.As(err, &missingEmailErr) {
		t.Errorf("expected ErrMissingEmail, got %T: %v", err, err)
	}
}

// TestRunUserCreate_ContextError tests that runUserCreate propagates context errors
func TestRunUserCreate_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "test context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newUserCreateCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant", "--email", "test@example.com"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	// The error should contain our test error message
	if !containsError(err, "test context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunUserList_MissingTenantID tests that runUserList returns error when tenant is empty
func TestRunUserList_MissingTenantID(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newUserListCommand(getFlags)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing tenant ID")
	}

	var missingTenantErr ErrMissingTenantID
	if !errors.As(err, &missingTenantErr) {
		t.Errorf("expected ErrMissingTenantID, got %T: %v", err, err)
	}
}

// TestRunUserList_ContextError tests that runUserList propagates context errors
func TestRunUserList_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "list context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newUserListCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "list context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunUserUpdate_MissingTenantID tests that runUserUpdate returns error when tenant is empty
func TestRunUserUpdate_MissingTenantID(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newUserUpdateCommand(getFlags)
	cmd.SetArgs([]string{"--user-id", "user-123"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing tenant ID")
	}

	var missingTenantErr ErrMissingTenantID
	if !errors.As(err, &missingTenantErr) {
		t.Errorf("expected ErrMissingTenantID, got %T: %v", err, err)
	}
}

// TestRunUserUpdate_MissingUserID tests that runUserUpdate returns error when user-id is empty
func TestRunUserUpdate_MissingUserID(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newUserUpdateCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing user ID")
	}

	var missingUserErr ErrMissingUserID
	if !errors.As(err, &missingUserErr) {
		t.Errorf("expected ErrMissingUserID, got %T: %v", err, err)
	}
}

// TestRunUserUpdate_ContextError tests that runUserUpdate propagates context errors
func TestRunUserUpdate_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "update context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newUserUpdateCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant", "--user-id", "user-123"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "update context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunUserGet_ArgValidation tests that runUserGet requires 2 arguments
func TestRunUserGet_ArgValidation(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "no arguments",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "one argument",
			args:    []string{"tenant-id"},
			wantErr: true,
		},
		{
			name:    "three arguments",
			args:    []string{"tenant-id", "user-id", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newUserGetCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunUserGet_ContextError tests that runUserGet propagates context errors
func TestRunUserGet_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "get context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newUserGetCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant", "user-123"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "get context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunUserDelete_ArgValidation tests that runUserDelete requires 2 arguments
func TestRunUserDelete_ArgValidation(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "no arguments",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "one argument",
			args:    []string{"tenant-id"},
			wantErr: true,
		},
		{
			name:    "three arguments",
			args:    []string{"tenant-id", "user-id", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newUserDeleteCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunUserDelete_ContextError tests that runUserDelete propagates context errors
func TestRunUserDelete_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "delete context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newUserDeleteCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant", "user-123"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "delete context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunUserAssignRole_ArgValidation tests that runUserAssignRole requires 3 arguments
func TestRunUserAssignRole_ArgValidation(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "no arguments",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "one argument",
			args:    []string{"tenant-id"},
			wantErr: true,
		},
		{
			name:    "two arguments",
			args:    []string{"tenant-id", "user-id"},
			wantErr: true,
		},
		{
			name:    "four arguments",
			args:    []string{"tenant-id", "user-id", "role", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newUserAssignRoleCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunUserAssignRole_ContextError tests that runUserAssignRole propagates context errors
func TestRunUserAssignRole_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "assign role context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newUserAssignRoleCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant", "user-123", "admin"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "assign role context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunUserRevokeRole_ArgValidation tests that runUserRevokeRole requires 3 arguments
func TestRunUserRevokeRole_ArgValidation(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "no arguments",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "one argument",
			args:    []string{"tenant-id"},
			wantErr: true,
		},
		{
			name:    "two arguments",
			args:    []string{"tenant-id", "user-id"},
			wantErr: true,
		},
		{
			name:    "four arguments",
			args:    []string{"tenant-id", "user-id", "role", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newUserRevokeRoleCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunUserRevokeRole_ContextError tests that runUserRevokeRole propagates context errors
func TestRunUserRevokeRole_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "revoke role context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newUserRevokeRoleCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant", "user-123", "admin"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "revoke role context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestUserCreateCommand_AllFlags tests that user create command has all expected flags
func TestUserCreateCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newUserCreateCommand(getFlags)

	expectedFlags := []struct {
		name         string
		defaultValue string
	}{
		{"tenant", ""},
		{"email", ""},
		{"name", ""},
		{"roles", ""},
		{"groups", ""},
		{"attributes", ""},
	}

	for _, ef := range expectedFlags {
		flag := cmd.Flags().Lookup(ef.name)
		if flag == nil {
			t.Errorf("flag --%s not found", ef.name)
			continue
		}
		if flag.DefValue != ef.defaultValue {
			t.Errorf("flag --%s default value = %q, want %q", ef.name, flag.DefValue, ef.defaultValue)
		}
	}
}

// TestUserListCommand_AllFlags tests that user list command has all expected flags
func TestUserListCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newUserListCommand(getFlags)

	expectedFlags := []struct {
		name         string
		defaultValue string
	}{
		{"tenant", ""},
		{"page", "1"},
		{"page-size", "50"},
		{"email", ""},
		{"role", ""},
		{"group", ""},
	}

	for _, ef := range expectedFlags {
		flag := cmd.Flags().Lookup(ef.name)
		if flag == nil {
			t.Errorf("flag --%s not found", ef.name)
			continue
		}
		if flag.DefValue != ef.defaultValue {
			t.Errorf("flag --%s default value = %q, want %q", ef.name, flag.DefValue, ef.defaultValue)
		}
	}
}

// TestUserUpdateCommand_AllFlags tests that user update command has all expected flags
func TestUserUpdateCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newUserUpdateCommand(getFlags)

	expectedFlags := []struct {
		name         string
		defaultValue string
	}{
		{"tenant", ""},
		{"user-id", ""},
		{"email", ""},
		{"name", ""},
		{"roles", ""},
		{"groups", ""},
		{"attributes", ""},
	}

	for _, ef := range expectedFlags {
		flag := cmd.Flags().Lookup(ef.name)
		if flag == nil {
			t.Errorf("flag --%s not found", ef.name)
			continue
		}
		if flag.DefValue != ef.defaultValue {
			t.Errorf("flag --%s default value = %q, want %q", ef.name, flag.DefValue, ef.defaultValue)
		}
	}
}

// Helper function to check if an error contains a specific message
func containsError(err error, msg string) bool {
	if err == nil {
		return false
	}
	return contains(err.Error(), msg)
}

// Helper function for string contains
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
