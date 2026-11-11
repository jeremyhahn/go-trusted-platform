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

package registry

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewListCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewListCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewListCommand returned nil")
	}

	if cmd.Use != "list" {
		t.Errorf("expected Use to be 'list', got %q", cmd.Use)
	}

	if cmd.Short != "List images in the registry" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewListCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(cmd.Long) < 100 {
		t.Error("Long description should be descriptive (at least 100 chars)")
	}
}

func TestNewListCommand_AcceptsNoArgs(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	// List command should not require any arguments
	if cmd.Args != nil {
		err := cmd.Args(cmd, []string{})
		if err != nil {
			t.Errorf("list command should accept no args: %v", err)
		}
	}
}

func TestNewListCommand_HasFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	tests := []struct {
		name      string
		shorthand string
	}{
		{name: "repository", shorthand: "r"},
		{name: "prefix", shorthand: "p"},
		{name: "limit", shorthand: "l"},
		{name: "cursor", shorthand: ""},
		{name: "show-encrypted", shorthand: ""},
		{name: "sort-by", shorthand: ""},
		{name: "sort-desc", shorthand: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.name)
			if flag == nil {
				t.Errorf("expected flag %q to exist", tt.name)
				return
			}
			if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
				t.Errorf("expected shorthand %q for flag %q, got %q",
					tt.shorthand, tt.name, flag.Shorthand)
			}
		})
	}
}

func TestNewListCommand_DefaultFlagValues(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	repositoryFlag := cmd.Flags().Lookup("repository")
	if repositoryFlag == nil {
		t.Fatal("repository flag not found")
	}
	if repositoryFlag.DefValue != "" {
		t.Errorf("expected repository default to be empty, got %q", repositoryFlag.DefValue)
	}

	prefixFlag := cmd.Flags().Lookup("prefix")
	if prefixFlag == nil {
		t.Fatal("prefix flag not found")
	}
	if prefixFlag.DefValue != "" {
		t.Errorf("expected prefix default to be empty, got %q", prefixFlag.DefValue)
	}

	limitFlag := cmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Fatal("limit flag not found")
	}
	if limitFlag.DefValue != "50" {
		t.Errorf("expected limit default to be '50', got %q", limitFlag.DefValue)
	}

	showEncryptedFlag := cmd.Flags().Lookup("show-encrypted")
	if showEncryptedFlag == nil {
		t.Fatal("show-encrypted flag not found")
	}
	if showEncryptedFlag.DefValue != "true" {
		t.Errorf("expected show-encrypted default to be 'true', got %q", showEncryptedFlag.DefValue)
	}

	sortByFlag := cmd.Flags().Lookup("sort-by")
	if sortByFlag == nil {
		t.Fatal("sort-by flag not found")
	}
	if sortByFlag.DefValue != "name" {
		t.Errorf("expected sort-by default to be 'name', got %q", sortByFlag.DefValue)
	}

	sortDescFlag := cmd.Flags().Lookup("sort-desc")
	if sortDescFlag == nil {
		t.Fatal("sort-desc flag not found")
	}
	if sortDescFlag.DefValue != "false" {
		t.Errorf("expected sort-desc default to be 'false', got %q", sortDescFlag.DefValue)
	}
}

func TestListResult_EmptyImages(t *testing.T) {
	result := ListResult{
		Images:     []*ImageListItem{},
		TotalCount: 0,
		HasMore:    false,
		NextCursor: "",
	}

	if len(result.Images) != 0 {
		t.Errorf("expected 0 images, got %d", len(result.Images))
	}

	if result.TotalCount != 0 {
		t.Errorf("expected TotalCount 0, got %d", result.TotalCount)
	}

	if result.HasMore {
		t.Error("expected HasMore to be false")
	}

	if result.NextCursor != "" {
		t.Errorf("expected empty NextCursor, got %q", result.NextCursor)
	}
}

func TestNewListCommand_FlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	flags := []string{"repository", "prefix", "limit", "cursor", "show-encrypted", "sort-by", "sort-desc"}

	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("flag %q not found", name)
			}
			if flag.Usage == "" {
				t.Errorf("flag %q should have usage text", name)
			}
		})
	}
}

func TestNewListCommand_RunEExists(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewListCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewListCommand_FlagTypes(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	// Verify repository is a string flag
	repoFlag := cmd.Flags().Lookup("repository")
	if repoFlag == nil {
		t.Fatal("repository flag not found")
	}
	if repoFlag.Value.Type() != "string" {
		t.Errorf("expected repository flag to be string, got %s", repoFlag.Value.Type())
	}

	// Verify prefix is a string flag
	prefixFlag := cmd.Flags().Lookup("prefix")
	if prefixFlag == nil {
		t.Fatal("prefix flag not found")
	}
	if prefixFlag.Value.Type() != "string" {
		t.Errorf("expected prefix flag to be string, got %s", prefixFlag.Value.Type())
	}

	// Verify limit is an integer flag (int or int32)
	limitFlag := cmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Fatal("limit flag not found")
	}
	limitType := limitFlag.Value.Type()
	if !strings.HasPrefix(limitType, "int") {
		t.Errorf("expected limit flag to be int type, got %s", limitType)
	}

	// Verify cursor is a string flag
	cursorFlag := cmd.Flags().Lookup("cursor")
	if cursorFlag == nil {
		t.Fatal("cursor flag not found")
	}
	if cursorFlag.Value.Type() != "string" {
		t.Errorf("expected cursor flag to be string, got %s", cursorFlag.Value.Type())
	}

	// Verify show-encrypted is a bool flag
	showEncryptedFlag := cmd.Flags().Lookup("show-encrypted")
	if showEncryptedFlag == nil {
		t.Fatal("show-encrypted flag not found")
	}
	if showEncryptedFlag.Value.Type() != "bool" {
		t.Errorf("expected show-encrypted flag to be bool, got %s", showEncryptedFlag.Value.Type())
	}

	// Verify sort-by is a string flag
	sortByFlag := cmd.Flags().Lookup("sort-by")
	if sortByFlag == nil {
		t.Fatal("sort-by flag not found")
	}
	if sortByFlag.Value.Type() != "string" {
		t.Errorf("expected sort-by flag to be string, got %s", sortByFlag.Value.Type())
	}

	// Verify sort-desc is a bool flag
	sortDescFlag := cmd.Flags().Lookup("sort-desc")
	if sortDescFlag == nil {
		t.Fatal("sort-desc flag not found")
	}
	if sortDescFlag.Value.Type() != "bool" {
		t.Errorf("expected sort-desc flag to be bool, got %s", sortDescFlag.Value.Type())
	}
}

func TestNewListCommand_HasAliases(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	// Check if there are aliases (ls is common for list)
	if len(cmd.Aliases) > 0 {
		// Just verify they exist, don't enforce specific aliases
		t.Logf("list command has aliases: %v", cmd.Aliases)
	}
}

// Tests for buildReference function
func TestBuildReference_WithTag(t *testing.T) {
	ref := buildReference("myrepo/myimage", "v1.0")

	if ref != "myrepo/myimage:v1.0" {
		t.Errorf("expected 'myrepo/myimage:v1.0', got %q", ref)
	}
}

func TestBuildReference_WithoutTag(t *testing.T) {
	ref := buildReference("myrepo/myimage", "")

	if ref != "myrepo/myimage" {
		t.Errorf("expected 'myrepo/myimage', got %q", ref)
	}
}

func TestBuildReference_SimpleRepository(t *testing.T) {
	ref := buildReference("alpine", "latest")

	if ref != "alpine:latest" {
		t.Errorf("expected 'alpine:latest', got %q", ref)
	}
}

func TestBuildReference_EmptyRepository(t *testing.T) {
	ref := buildReference("", "v1.0")

	if ref != ":v1.0" {
		t.Errorf("expected ':v1.0', got %q", ref)
	}
}

func TestBuildReference_BothEmpty(t *testing.T) {
	ref := buildReference("", "")

	if ref != "" {
		t.Errorf("expected empty string, got %q", ref)
	}
}
