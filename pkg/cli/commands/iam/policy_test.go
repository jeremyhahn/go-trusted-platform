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
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// TestRunPolicyCreate_ValidationErrors tests runPolicyCreate validation via command
func TestRunPolicyCreate_ValidationErrors(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	tests := []struct {
		name       string
		args       []string
		wantErrMsg string
	}{
		{
			name:       "missing tenant ID",
			args:       []string{"--name", "policy1", "--file", "policy.yaml"},
			wantErrMsg: "tenant ID is required",
		},
		{
			name:       "missing policy name",
			args:       []string{"--tenant", "test-tenant", "--file", "policy.yaml"},
			wantErrMsg: "policy name is required",
		},
		{
			name:       "missing file",
			args:       []string{"--tenant", "test-tenant", "--name", "policy1"},
			wantErrMsg: "policy file is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newPolicyCreateCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if err == nil {
				t.Fatal("expected error")
			}
			if !containsError(err, tt.wantErrMsg) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErrMsg, err)
			}
		})
	}
}

// TestRunPolicyCreate_ContextError tests that runPolicyCreate propagates context errors
func TestRunPolicyCreate_ContextError(t *testing.T) {
	// Create a temporary policy file
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	err := os.WriteFile(policyFile, []byte("effect: allow\nactions: [read]"), 0644)
	if err != nil {
		t.Fatalf("failed to create temp policy file: %v", err)
	}

	expectedErr := ErrTestContext{Message: "policy create context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newPolicyCreateCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant", "--name", "policy1", "--file", policyFile})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "policy create context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunPolicyCreate_FileNotFound tests runPolicyCreate with non-existent file
func TestRunPolicyCreate_FileNotFound(t *testing.T) {
	expectedErr := ErrTestContext{Message: "context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newPolicyCreateCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant", "--name", "policy1", "--file", "/nonexistent/policy.yaml"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}

	// Should fail on file read before context error
	if !containsError(err, "no such file") && !containsError(err, "context error") {
		t.Errorf("expected file not found or context error, got: %v", err)
	}
}

// TestRunPolicyGet_ArgValidation tests that runPolicyGet requires 2 arguments
func TestRunPolicyGet_ArgValidation(t *testing.T) {
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
			args:    []string{"tenant-id", "policy-name", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newPolicyGetCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunPolicyGet_ContextError tests that runPolicyGet propagates context errors
func TestRunPolicyGet_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "policy get context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newPolicyGetCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant", "admin-policy"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "policy get context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunPolicyList_MissingTenantID tests that runPolicyList returns error when tenant is empty
func TestRunPolicyList_MissingTenantID(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newPolicyListCommand(getFlags)
	cmd.SetArgs([]string{}) // No --tenant flag

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing tenant ID")
	}

	var missingTenantErr ErrMissingTenantID
	if !errors.As(err, &missingTenantErr) {
		t.Errorf("expected ErrMissingTenantID, got %T: %v", err, err)
	}
}

// TestRunPolicyList_ContextError tests that runPolicyList propagates context errors
func TestRunPolicyList_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "policy list context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newPolicyListCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "policy list context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunPolicyUpdate_ValidationErrors tests runPolicyUpdate validation via command
func TestRunPolicyUpdate_ValidationErrors(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	tests := []struct {
		name       string
		args       []string
		wantErrMsg string
	}{
		{
			name:       "missing tenant ID",
			args:       []string{"--name", "policy1"},
			wantErrMsg: "tenant ID is required",
		},
		{
			name:       "missing policy name",
			args:       []string{"--tenant", "test-tenant"},
			wantErrMsg: "policy name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newPolicyUpdateCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if err == nil {
				t.Fatal("expected error")
			}
			if !containsError(err, tt.wantErrMsg) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErrMsg, err)
			}
		})
	}
}

// TestRunPolicyUpdate_ContextError tests that runPolicyUpdate propagates context errors
func TestRunPolicyUpdate_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "policy update context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newPolicyUpdateCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant", "--name", "policy1"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "policy update context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunPolicyDelete_ArgValidation tests that runPolicyDelete requires 2 arguments
func TestRunPolicyDelete_ArgValidation(t *testing.T) {
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
			args:    []string{"tenant-id", "policy-name", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newPolicyDeleteCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunPolicyDelete_ContextError tests that runPolicyDelete propagates context errors
func TestRunPolicyDelete_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "policy delete context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newPolicyDeleteCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant", "admin-policy"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "policy delete context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunPolicyValidate_ValidationErrors tests runPolicyValidate validation via command
func TestRunPolicyValidate_ValidationErrors(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	tests := []struct {
		name       string
		args       []string
		wantErrMsg string
	}{
		{
			name:       "missing tenant ID",
			args:       []string{"--file", "policy.yaml"},
			wantErrMsg: "tenant ID is required",
		},
		{
			name:       "missing file",
			args:       []string{"--tenant", "test-tenant"},
			wantErrMsg: "policy file is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newPolicyValidateCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if err == nil {
				t.Fatal("expected error")
			}
			if !containsError(err, tt.wantErrMsg) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErrMsg, err)
			}
		})
	}
}

// TestRunPolicyValidate_ContextError tests that runPolicyValidate propagates context errors
func TestRunPolicyValidate_ContextError(t *testing.T) {
	// Create a temporary policy file
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	err := os.WriteFile(policyFile, []byte("effect: allow\nactions: [read]"), 0644)
	if err != nil {
		t.Fatalf("failed to create temp policy file: %v", err)
	}

	expectedErr := ErrTestContext{Message: "policy validate context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newPolicyValidateCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant", "--file", policyFile})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "policy validate context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunPolicyTest_ValidationErrors tests runPolicyTest validation via command
func TestRunPolicyTest_ValidationErrors(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	tests := []struct {
		name       string
		args       []string
		wantErrMsg string
	}{
		{
			name:       "missing tenant ID",
			args:       []string{"--subject", "user-1", "--action", "read", "--resource", "/api/users"},
			wantErrMsg: "tenant ID is required",
		},
		{
			name:       "missing subject",
			args:       []string{"--tenant", "test-tenant", "--action", "read", "--resource", "/api/users"},
			wantErrMsg: "subject ID is required",
		},
		{
			name:       "missing action",
			args:       []string{"--tenant", "test-tenant", "--subject", "user-1", "--resource", "/api/users"},
			wantErrMsg: "action is required",
		},
		{
			name:       "missing resource",
			args:       []string{"--tenant", "test-tenant", "--subject", "user-1", "--action", "read"},
			wantErrMsg: "resource is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newPolicyTestCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if err == nil {
				t.Fatal("expected error")
			}
			if !containsError(err, tt.wantErrMsg) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErrMsg, err)
			}
		})
	}
}

// TestRunPolicyTest_ContextError tests that runPolicyTest propagates context errors
func TestRunPolicyTest_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "policy test context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newPolicyTestCommand(getFlags)
	cmd.SetArgs([]string{
		"--tenant", "test-tenant",
		"--subject", "user-123",
		"--action", "read",
		"--resource", "/api/users",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "policy test context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestPolicyCreateCommand_AllFlags tests that policy create command has all expected flags
func TestPolicyCreateCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newPolicyCreateCommand(getFlags)

	expectedFlags := []struct {
		name         string
		defaultValue string
	}{
		{"tenant", ""},
		{"name", ""},
		{"description", ""},
		{"priority", "0"},
		{"file", ""},
		{"labels", ""},
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

// TestPolicyListCommand_AllFlags tests that policy list command has all expected flags
func TestPolicyListCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newPolicyListCommand(getFlags)

	expectedFlags := []struct {
		name         string
		shorthand    string
		defaultValue string
	}{
		{"tenant", "", ""},
		{"page", "p", "1"},
		{"page-size", "s", "50"},
	}

	for _, ef := range expectedFlags {
		flag := cmd.Flags().Lookup(ef.name)
		if flag == nil {
			t.Errorf("flag --%s not found", ef.name)
			continue
		}
		if ef.shorthand != "" && flag.Shorthand != ef.shorthand {
			t.Errorf("flag --%s shorthand = %q, want %q", ef.name, flag.Shorthand, ef.shorthand)
		}
		if flag.DefValue != ef.defaultValue {
			t.Errorf("flag --%s default value = %q, want %q", ef.name, flag.DefValue, ef.defaultValue)
		}
	}
}

// TestPolicyTestCommand_AllFlags tests that policy test command has all expected flags
func TestPolicyTestCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newPolicyTestCommand(getFlags)

	expectedFlags := []struct {
		name         string
		defaultValue string
	}{
		{"tenant", ""},
		{"subject", ""},
		{"roles", ""},
		{"groups", ""},
		{"action", ""},
		{"resource", ""},
		{"context", ""},
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

// TestPolicyUpdateCommand_AllFlags tests that policy update command has all expected flags
func TestPolicyUpdateCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newPolicyUpdateCommand(getFlags)

	expectedFlags := []struct {
		name         string
		defaultValue string
	}{
		{"tenant", ""},
		{"name", ""},
		{"description", ""},
		{"priority", "0"},
		{"file", ""},
		{"labels", ""},
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

// TestPolicyValidateCommand_AllFlags tests that policy validate command has all expected flags
func TestPolicyValidateCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newPolicyValidateCommand(getFlags)

	expectedFlags := []struct {
		name         string
		defaultValue string
	}{
		{"tenant", ""},
		{"file", ""},
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
