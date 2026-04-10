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

// TestRunTenantCreate_MissingTenantID tests that runTenantCreate returns error when id is empty
func TestRunTenantCreate_MissingTenantID(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantCreateCommand(getFlags)
	cmd.SetArgs([]string{"--name", "Test Tenant"}) // Missing --id flag

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing tenant ID")
	}

	var missingTenantErr ErrMissingTenantID
	if !errors.As(err, &missingTenantErr) {
		t.Errorf("expected ErrMissingTenantID, got %T: %v", err, err)
	}
}

// TestRunTenantCreate_ContextError tests that runTenantCreate propagates context errors
func TestRunTenantCreate_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "tenant create context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newTenantCreateCommand(getFlags)
	cmd.SetArgs([]string{"--id", "test-tenant", "--name", "Test Tenant"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "tenant create context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunTenantGet_ArgValidation tests that runTenantGet requires 1 argument
func TestRunTenantGet_ArgValidation(t *testing.T) {
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
			name:    "two arguments",
			args:    []string{"tenant-id", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newTenantGetCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunTenantGet_ContextError tests that runTenantGet propagates context errors
func TestRunTenantGet_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "tenant get context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newTenantGetCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "tenant get context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunTenantList_ContextError tests that runTenantList propagates context errors
func TestRunTenantList_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "tenant list context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newTenantListCommand(getFlags)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "tenant list context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunTenantUpdate_MissingTenantID tests that runTenantUpdate returns error when id is empty
func TestRunTenantUpdate_MissingTenantID(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantUpdateCommand(getFlags)
	cmd.SetArgs([]string{"--name", "Updated Tenant"}) // Missing --id flag

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing tenant ID")
	}

	var missingTenantErr ErrMissingTenantID
	if !errors.As(err, &missingTenantErr) {
		t.Errorf("expected ErrMissingTenantID, got %T: %v", err, err)
	}
}

// TestRunTenantUpdate_ContextError tests that runTenantUpdate propagates context errors
func TestRunTenantUpdate_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "tenant update context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newTenantUpdateCommand(getFlags)
	cmd.SetArgs([]string{"--id", "test-tenant", "--name", "Updated"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "tenant update context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestRunTenantDelete_ArgValidation tests that runTenantDelete requires 1 argument
func TestRunTenantDelete_ArgValidation(t *testing.T) {
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
			name:    "two arguments",
			args:    []string{"tenant-id", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newTenantDeleteCommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRunTenantDelete_ContextError tests that runTenantDelete propagates context errors
func TestRunTenantDelete_ContextError(t *testing.T) {
	expectedErr := ErrTestContext{Message: "tenant delete context error"}
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(expectedErr)
	}

	cmd := newTenantDeleteCommand(getFlags)
	cmd.SetArgs([]string{"test-tenant"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from context")
	}

	if !containsError(err, "tenant delete context error") {
		t.Errorf("expected error to contain context error, got: %v", err)
	}
}

// TestTenantCreateCommand_AllFlags tests that tenant create command has all expected flags
func TestTenantCreateCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantCreateCommand(getFlags)

	expectedFlags := []struct {
		name         string
		defaultValue string
	}{
		{"id", ""},
		{"name", ""},
		{"max-users", "0"},
		{"mfa-required", "false"},
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

// TestTenantListCommand_AllFlags tests that tenant list command has all expected flags
func TestTenantListCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantListCommand(getFlags)

	expectedFlags := []struct {
		name         string
		shorthand    string
		defaultValue string
	}{
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

// TestTenantUpdateCommand_AllFlags tests that tenant update command has all expected flags
func TestTenantUpdateCommand_AllFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantUpdateCommand(getFlags)

	expectedFlags := []struct {
		name         string
		defaultValue string
	}{
		{"id", ""},
		{"name", ""},
		{"max-users", "0"},
		{"mfa-required", "false"},
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

// TestTenantGetCommand_LongDescription tests that tenant get command has a long description
func TestTenantGetCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantGetCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

// TestTenantDeleteCommand_LongDescription tests that tenant delete command has a long description
func TestTenantDeleteCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantDeleteCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

// TestTenantListCommand_Defaults tests that tenant list has correct defaults
func TestTenantListCommand_Defaults(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantListCommand(getFlags)

	// Check page default
	pageFlag := cmd.Flags().Lookup("page")
	if pageFlag == nil {
		t.Fatal("page flag not found")
	}
	if pageFlag.DefValue != "1" {
		t.Errorf("page default value = %q, want %q", pageFlag.DefValue, "1")
	}

	// Check page-size default
	pageSizeFlag := cmd.Flags().Lookup("page-size")
	if pageSizeFlag == nil {
		t.Fatal("page-size flag not found")
	}
	if pageSizeFlag.DefValue != "50" {
		t.Errorf("page-size default value = %q, want %q", pageSizeFlag.DefValue, "50")
	}
}

// TestTenantCreateCommand_RunE tests that tenant create command has RunE set
func TestTenantCreateCommand_RunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantCreateCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set for tenant create command")
	}
}

// TestTenantGetCommand_RunE tests that tenant get command has RunE set
func TestTenantGetCommand_RunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantGetCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set for tenant get command")
	}
}

// TestTenantListCommand_RunE tests that tenant list command has RunE set
func TestTenantListCommand_RunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantListCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set for tenant list command")
	}
}

// TestTenantUpdateCommand_RunE tests that tenant update command has RunE set
func TestTenantUpdateCommand_RunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantUpdateCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set for tenant update command")
	}
}

// TestTenantDeleteCommand_RunE tests that tenant delete command has RunE set
func TestTenantDeleteCommand_RunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return makeTestFlags(nil)
	}

	cmd := newTenantDeleteCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set for tenant delete command")
	}
}
