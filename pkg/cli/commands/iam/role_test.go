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

// TestRunRoleCreate_MissingTenantID tests that runRoleCreate returns error when tenant is empty
func TestRunRoleCreate_MissingTenantID(t *testing.T) {
	flags := makeTestFlags(nil)
	err := runRoleCreate(flags, "", "admin", "Administrator", "Admin role", []string{"read", "write"})
	if err == nil {
		t.Fatal("expected error for missing tenant ID")
	}

	var missingTenantErr ErrMissingTenantID
	if !errors.As(err, &missingTenantErr) {
		t.Errorf("expected ErrMissingTenantID, got %T: %v", err, err)
	}
}

// TestRunRoleCreate_ContextError tests that runRoleCreate propagates context errors
func TestRunRoleCreate_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "role create context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newRoleCreateCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant", "admin"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "role create context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunRoleCreate_ArgValidation tests that runRoleCreate requires 1 argument
func TestRunRoleCreate_ArgValidation(t *testing.T) {
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
			args:    []string{"--tenant", "test-tenant"},
			wantErr: true,
		},
		{
			name:    "two arguments",
			args:    []string{"--tenant", "test-tenant", "admin", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRoleCreateCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunRoleGet_ValidationErrors tests runRoleGet validation
func TestRunRoleGet_ValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		roleID     string
		wantErrMsg string
	}{
		{
			name:       "empty tenant ID",
			tenantID:   "",
			roleID:     "admin",
			wantErrMsg: "tenant ID is required",
		},
		{
			name:       "empty role ID",
			tenantID:   "tenant-1",
			roleID:     "",
			wantErrMsg: "role ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := makeTestFlags(nil)
			err := runRoleGet(flags, tt.tenantID, tt.roleID)
			if err == nil {
				t.Fatal("expected error")
			}
			if !containsError(err, tt.wantErrMsg) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErrMsg, err)
			}
		})
	}
}

// TestRunRoleGet_ArgValidation tests that runRoleGet requires 2 arguments
func TestRunRoleGet_ArgValidation(t *testing.T) {
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
			args:    []string{"tenant-id", "role-id", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRoleGetCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunRoleGet_ContextError tests that runRoleGet propagates context errors
func TestRunRoleGet_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "role get context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newRoleGetCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant", "admin"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "role get context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunRoleList_MissingTenantID tests that runRoleList returns error when tenant is empty
func TestRunRoleList_MissingTenantID(t *testing.T) {
	flags := makeTestFlags(nil)
	err := runRoleList(flags, "", 50, 0)
	if err == nil {
		t.Fatal("expected error for missing tenant ID")
	}

	var missingTenantErr ErrMissingTenantID
	if !errors.As(err, &missingTenantErr) {
		t.Errorf("expected ErrMissingTenantID, got %T: %v", err, err)
	}
}

// TestRunRoleList_ContextError tests that runRoleList propagates context errors
func TestRunRoleList_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "role list context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newRoleListCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "role list context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunRoleUpdate_ValidationErrors tests runRoleUpdate validation
func TestRunRoleUpdate_ValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		roleID     string
		wantErrMsg string
	}{
		{
			name:       "empty tenant ID",
			tenantID:   "",
			roleID:     "admin",
			wantErrMsg: "tenant ID is required",
		},
		{
			name:       "empty role ID",
			tenantID:   "tenant-1",
			roleID:     "",
			wantErrMsg: "role ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := makeTestFlags(nil)
			err := runRoleUpdate(flags, tt.tenantID, tt.roleID, "name", "desc", []string{"read"})
			if err == nil {
				t.Fatal("expected error")
			}
			if !containsError(err, tt.wantErrMsg) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErrMsg, err)
			}
		})
	}
}

// TestRunRoleUpdate_ContextError tests that runRoleUpdate propagates context errors
func TestRunRoleUpdate_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "role update context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newRoleUpdateCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant", "admin"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "role update context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunRoleDelete_ValidationErrors tests runRoleDelete validation
func TestRunRoleDelete_ValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		tenantID   string
		roleID     string
		wantErrMsg string
	}{
		{
			name:       "empty tenant ID",
			tenantID:   "",
			roleID:     "admin",
			wantErrMsg: "tenant ID is required",
		},
		{
			name:       "empty role ID",
			tenantID:   "tenant-1",
			roleID:     "",
			wantErrMsg: "role ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := makeTestFlags(nil)
			err := runRoleDelete(flags, tt.tenantID, tt.roleID)
			if err == nil {
				t.Fatal("expected error")
			}
			if !containsError(err, tt.wantErrMsg) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErrMsg, err)
			}
		})
	}
}

// TestRunRoleDelete_ArgValidation tests that runRoleDelete requires 2 arguments
func TestRunRoleDelete_ArgValidation(t *testing.T) {
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
			args:    []string{"tenant-id", "role-id", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRoleDeleteCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunRoleDelete_ContextError tests that runRoleDelete propagates context errors
func TestRunRoleDelete_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "role delete context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newRoleDeleteCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant", "admin"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "role delete context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRoleCreateCommand_AllFlags tests that role create command has all expected flags
func TestRoleCreateCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newRoleCreateCommand(getFlags)

	expectedFlags := []struct {
		name      string
		shorthand string
	}{
		{"tenant", "t"},
		{"name", "n"},
		{"description", "d"},
		{"permissions", "p"},
	}

	for _, ef := range expectedFlags {
		flag := cmd.Flags().Lookup(ef.name)
		if flag == nil {
			t.Errorf("flag --%s not found", ef.name)
			continue
		}
		if flag.Shorthand != ef.shorthand {
			t.Errorf("flag --%s shorthand = %q, want %q", ef.name, flag.Shorthand, ef.shorthand)
		}
	}
}

// TestRoleListCommand_AllFlags tests that role list command has all expected flags
func TestRoleListCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newRoleListCommand(getFlags)

	expectedFlags := []struct {
		name         string
		shorthand    string
		defaultValue string
	}{
		{"tenant", "t", ""},
		{"page", "p", "1"},
		{"page-size", "s", "50"},
	}

	for _, ef := range expectedFlags {
		flag := cmd.Flags().Lookup(ef.name)
		if flag == nil {
			t.Errorf("flag --%s not found", ef.name)
			continue
		}
		if flag.Shorthand != ef.shorthand {
			t.Errorf("flag --%s shorthand = %q, want %q", ef.name, flag.Shorthand, ef.shorthand)
		}
		if flag.DefValue != ef.defaultValue {
			t.Errorf("flag --%s default value = %q, want %q", ef.name, flag.DefValue, ef.defaultValue)
		}
	}
}

// TestRoleUpdateCommand_AllFlags tests that role update command has all expected flags
func TestRoleUpdateCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newRoleUpdateCommand(getFlags)

	expectedFlags := []struct {
		name      string
		shorthand string
	}{
		{"tenant", "t"},
		{"name", "n"},
		{"description", "d"},
		{"permissions", "p"},
	}

	for _, ef := range expectedFlags {
		flag := cmd.Flags().Lookup(ef.name)
		if flag == nil {
			t.Errorf("flag --%s not found", ef.name)
			continue
		}
		if flag.Shorthand != ef.shorthand {
			t.Errorf("flag --%s shorthand = %q, want %q", ef.name, flag.Shorthand, ef.shorthand)
		}
	}
}
