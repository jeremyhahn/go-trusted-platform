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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewDeleteCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewDeleteCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewDeleteCommand returned nil")
	}

	if cmd.Use != "delete <image-reference>" {
		t.Errorf("expected Use to be 'delete <image-reference>', got %q", cmd.Use)
	}

	if cmd.Short != "Delete an image from the registry" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewDeleteCommand_HasAliases(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDeleteCommand(getFlags)

	expectedAliases := []string{"rm", "remove"}
	if len(cmd.Aliases) != len(expectedAliases) {
		t.Errorf("expected %d aliases, got %d", len(expectedAliases), len(cmd.Aliases))
	}

	for i, alias := range expectedAliases {
		if cmd.Aliases[i] != alias {
			t.Errorf("expected alias %q at index %d, got %q", alias, i, cmd.Aliases[i])
		}
	}
}

func TestNewDeleteCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDeleteCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(cmd.Long) < 100 {
		t.Error("Long description should be descriptive (at least 100 chars)")
	}
}

func TestNewDeleteCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDeleteCommand(getFlags)

	if cmd.Args == nil {
		t.Error("Args should not be nil")
	}

	err := cmd.Args(cmd, []string{})
	if err == nil {
		t.Error("expected error when no args provided")
	}

	err = cmd.Args(cmd, []string{"myrepo/myimage:v1.0"})
	if err != nil {
		t.Errorf("unexpected error with one arg: %v", err)
	}

	err = cmd.Args(cmd, []string{"image1", "image2"})
	if err == nil {
		t.Error("expected error when two args provided")
	}
}

func TestNewDeleteCommand_HasFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDeleteCommand(getFlags)

	tests := []struct {
		name      string
		shorthand string
	}{
		{name: "force", shorthand: "f"},
		{name: "dry-run", shorthand: ""},
		{name: "keep-untagged", shorthand: ""},
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

func TestRunDelete_InvalidImageReference(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	tests := []struct {
		name string
		ref  string
	}{
		{name: "empty reference", ref: ""},
		{name: "too long reference", ref: string(make([]byte, 300))},
		{name: "invalid characters", ref: "INVALID/UPPERCASE:tag"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runDelete(flags, tt.ref, true, false, false)
			if err == nil {
				t.Error("expected error for invalid reference")
			}

			if _, ok := err.(ErrInvalidImageReference); !ok {
				t.Errorf("expected ErrInvalidImageReference, got %T: %v", err, err)
			}
		})
	}
}

func TestNewDeleteCommand_DefaultFlagValues(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDeleteCommand(getFlags)

	forceFlag := cmd.Flags().Lookup("force")
	if forceFlag == nil {
		t.Fatal("force flag not found")
	}
	if forceFlag.DefValue != "false" {
		t.Errorf("expected force default to be 'false', got %q", forceFlag.DefValue)
	}

	dryRunFlag := cmd.Flags().Lookup("dry-run")
	if dryRunFlag == nil {
		t.Fatal("dry-run flag not found")
	}
	if dryRunFlag.DefValue != "false" {
		t.Errorf("expected dry-run default to be 'false', got %q", dryRunFlag.DefValue)
	}

	keepUntaggedFlag := cmd.Flags().Lookup("keep-untagged")
	if keepUntaggedFlag == nil {
		t.Fatal("keep-untagged flag not found")
	}
	if keepUntaggedFlag.DefValue != "false" {
		t.Errorf("expected keep-untagged default to be 'false', got %q", keepUntaggedFlag.DefValue)
	}
}

func TestNewDeleteCommand_FlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDeleteCommand(getFlags)

	forceFlag := cmd.Flags().Lookup("force")
	if forceFlag.Usage == "" {
		t.Error("force flag should have usage text")
	}

	dryRunFlag := cmd.Flags().Lookup("dry-run")
	if dryRunFlag.Usage == "" {
		t.Error("dry-run flag should have usage text")
	}

	keepUntaggedFlag := cmd.Flags().Lookup("keep-untagged")
	if keepUntaggedFlag.Usage == "" {
		t.Error("keep-untagged flag should have usage text")
	}
}

func TestDeleteResult_FailedDelete(t *testing.T) {
	result := DeleteResultCLI{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		Deleted:   false,
		Message:   "Access denied",
		Timestamp: 0,
	}

	if result.Deleted {
		t.Error("expected Deleted to be false")
	}

	if result.Message != "Access denied" {
		t.Errorf("unexpected Message: %q", result.Message)
	}
}

func TestPrintDeleteResult_DryRun(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	result := &DeleteResultCLI{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		Deleted:   false,
		Message:   "dry run - no changes made",
		Timestamp: 0,
	}

	err := printDeleteResult(flags, printer, result, true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintDeleteResult_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	result := &DeleteResultCLI{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		Deleted:   true,
		Timestamp: 1234567890,
	}

	err := printDeleteResult(flags, printer, result, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintDeleteResult_SuccessWithBytesFreed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	result := &DeleteResultCLI{
		Reference:  "myrepo/myimage:v1.0",
		Digest:     "sha256:abc123",
		Deleted:    true,
		BytesFreed: 1073741824, // 1 GB
		Timestamp:  1234567890,
	}

	err := printDeleteResult(flags, printer, result, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintDeleteResult_SuccessWithMessage(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	result := &DeleteResultCLI{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		Deleted:   true,
		Message:   "Image deleted with manifest cleanup",
		Timestamp: 1234567890,
	}

	err := printDeleteResult(flags, printer, result, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintDeleteResult_Failure(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	result := &DeleteResultCLI{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		Deleted:   false,
		Message:   "Permission denied",
		Timestamp: 0,
	}

	err := printDeleteResult(flags, printer, result, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintDeleteResult_JSONFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	result := &DeleteResultCLI{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		Deleted:   true,
		Timestamp: 1234567890,
	}

	err := printDeleteResult(flags, printer, result, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintDeleteResult_YAMLFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatYAML,
		NoColor:      true,
	}

	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	result := &DeleteResultCLI{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		Deleted:   true,
		Timestamp: 1234567890,
	}

	err := printDeleteResult(flags, printer, result, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintDeleteResult_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormat("invalid"),
		NoColor:      true,
	}

	printer := cli.NewPrinter(cli.OutputFormatTable, flags.NoColor)

	result := &DeleteResultCLI{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		Deleted:   true,
		Timestamp: 1234567890,
	}

	err := printDeleteResult(flags, printer, result, false)
	if err == nil {
		t.Error("expected error for invalid format")
	}

	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T: %v", err, err)
	}
}

func TestPrintDeleteResult_FailureWithEmptyMessage(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	result := &DeleteResultCLI{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		Deleted:   false,
		Message:   "",
		Timestamp: 0,
	}

	err := printDeleteResult(flags, printer, result, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewDeleteCommand_RunEExists(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewDeleteCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewDeleteCommand_FlagTypes(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDeleteCommand(getFlags)

	// Verify force is a bool flag
	forceFlag := cmd.Flags().Lookup("force")
	if forceFlag == nil {
		t.Fatal("force flag not found")
	}
	if forceFlag.Value.Type() != "bool" {
		t.Errorf("expected force flag to be bool, got %s", forceFlag.Value.Type())
	}

	// Verify dry-run is a bool flag
	dryRunFlag := cmd.Flags().Lookup("dry-run")
	if dryRunFlag == nil {
		t.Fatal("dry-run flag not found")
	}
	if dryRunFlag.Value.Type() != "bool" {
		t.Errorf("expected dry-run flag to be bool, got %s", dryRunFlag.Value.Type())
	}

	// Verify keep-untagged is a bool flag
	keepUntaggedFlag := cmd.Flags().Lookup("keep-untagged")
	if keepUntaggedFlag == nil {
		t.Fatal("keep-untagged flag not found")
	}
	if keepUntaggedFlag.Value.Type() != "bool" {
		t.Errorf("expected keep-untagged flag to be bool, got %s", keepUntaggedFlag.Value.Type())
	}
}
