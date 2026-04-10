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

// TestRunAppRegister_ValidationErrors tests runAppRegister validation via command
func TestRunAppRegister_ValidationErrors(t *testing.T) {
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
			args:       []string{"--name", "MyApp"},
			wantErrMsg: "tenant ID is required",
		},
		{
			name:       "missing app name",
			args:       []string{"--tenant", "test-tenant"},
			wantErrMsg: "application name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newAppRegisterCommand(getFlags)
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

// TestRunAppRegister_MissingTenantID tests that runAppRegister returns error when tenant is empty
func TestRunAppRegister_MissingTenantID(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newAppRegisterCommand(getFlags)
	cmd.SetArgs([]string{"--name", "MyApp"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing tenant ID")
	}

	var missingTenantErr ErrMissingTenantID
	if !errors.As(err, &missingTenantErr) {
		t.Errorf("expected ErrMissingTenantID, got %T: %v", err, err)
	}
}

// TestRunAppRegister_MissingAppName tests that runAppRegister returns error when name is empty
func TestRunAppRegister_MissingAppName(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newAppRegisterCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing app name")
	}

	var missingAppNameErr ErrMissingAppName
	if !errors.As(err, &missingAppNameErr) {
		t.Errorf("expected ErrMissingAppName, got %T: %v", err, err)
	}
}

// TestRunAppRegister_ContextError tests that runAppRegister propagates context errors
func TestRunAppRegister_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "app register context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newAppRegisterCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant", "--name", "MyApp"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "app register context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunAppGet_ArgValidation tests that runAppGet requires 2 arguments
func TestRunAppGet_ArgValidation(t *testing.T) {
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
			args:    []string{"tenant-id", "client-id", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newAppGetCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunAppGet_ContextError tests that runAppGet propagates context errors
func TestRunAppGet_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "app get context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newAppGetCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant", "client-123"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "app get context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunAppList_MissingTenantID tests that runAppList returns error when tenant is empty
func TestRunAppList_MissingTenantID(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newAppListCommand(getFlags)
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

// TestRunAppList_ContextError tests that runAppList propagates context errors
func TestRunAppList_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "app list context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newAppListCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "app list context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunAppUpdate_ValidationErrors tests runAppUpdate validation via command
func TestRunAppUpdate_ValidationErrors(t *testing.T) {
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
			args:       []string{"--client-id", "client-123"},
			wantErrMsg: "tenant ID is required",
		},
		{
			name:       "missing client ID",
			args:       []string{"--tenant", "test-tenant"},
			wantErrMsg: "client ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newAppUpdateCommand(getFlags)
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

// TestRunAppUpdate_ContextError tests that runAppUpdate propagates context errors
func TestRunAppUpdate_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "app update context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newAppUpdateCommand(getFlags)
	cmd.SetArgs([]string{"--tenant", "test-tenant", "--client-id", "client-123"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "app update context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunAppDelete_ArgValidation tests that runAppDelete requires 2 arguments
func TestRunAppDelete_ArgValidation(t *testing.T) {
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
			args:    []string{"tenant-id", "client-id", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newAppDeleteCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunAppDelete_ContextError tests that runAppDelete propagates context errors
func TestRunAppDelete_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "app delete context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newAppDeleteCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant", "client-123"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "app delete context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunAppRotateSecret_ArgValidation tests that runAppRotateSecret requires 2 arguments
func TestRunAppRotateSecret_ArgValidation(t *testing.T) {
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
			args:    []string{"tenant-id", "client-id", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newAppRotateSecretCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunAppRotateSecret_ContextError tests that runAppRotateSecret propagates context errors
func TestRunAppRotateSecret_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "rotate secret context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newAppRotateSecretCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant", "client-123"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "rotate secret context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestAppRegisterCommand_AllFlags tests that app register command has all expected flags
func TestAppRegisterCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newAppRegisterCommand(getFlags)

	expectedFlags := []struct {
		name         string
		defaultValue string
	}{
		{"tenant", ""},
		{"name", ""},
		{"redirect-uris", ""},
		{"grant-types", "authorization_code"},
		{"response-types", "code"},
		{"resource-prefix", ""},
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

// TestAppListCommand_AllFlags tests that app list command has all expected flags
func TestAppListCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newAppListCommand(getFlags)

	expectedFlags := []struct {
		name         string
		defaultValue string
	}{
		{"tenant", ""},
		{"page", "1"},
		{"page-size", "50"},
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

// TestAppUpdateCommand_AllFlags tests that app update command has all expected flags
func TestAppUpdateCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newAppUpdateCommand(getFlags)

	expectedFlags := []struct {
		name         string
		defaultValue string
	}{
		{"tenant", ""},
		{"client-id", ""},
		{"name", ""},
		{"redirect-uris", ""},
		{"grant-types", ""},
		{"response-types", ""},
		{"resource-prefix", ""},
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
