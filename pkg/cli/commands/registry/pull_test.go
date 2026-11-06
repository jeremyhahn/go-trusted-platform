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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewPullCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewPullCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewPullCommand returned nil")
	}

	if cmd.Use != "pull <image-reference>" {
		t.Errorf("expected Use to be 'pull <image-reference>', got %q", cmd.Use)
	}

	if cmd.Short != "Pull an image from the registry" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewPullCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPullCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(cmd.Long) < 100 {
		t.Error("Long description should be descriptive (at least 100 chars)")
	}
}

func TestNewPullCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPullCommand(getFlags)

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

func TestNewPullCommand_HasFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPullCommand(getFlags)

	tests := []struct {
		name      string
		shorthand string
	}{
		{name: "decrypt", shorthand: "d"},
		{name: "verify", shorthand: ""},
		{name: "platform", shorthand: "p"},
		{name: "output-file", shorthand: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.name)
			if flag == nil {
				t.Errorf("expected flag %q to exist", tt.name)
				return
			}
			if flag.Shorthand != tt.shorthand {
				t.Errorf("expected shorthand %q for flag %q, got %q",
					tt.shorthand, tt.name, flag.Shorthand)
			}
		})
	}
}

// pullUnderRoot mounts the pull command under a root that carries the global
// --output/-o format flag, as platformctl does, and parses args against it.
func pullUnderRoot(t *testing.T, args ...string) (format, outputFile string) {
	t.Helper()
	root := &cobra.Command{Use: "platformctl"}
	root.PersistentFlags().StringVarP(&format, "output", "o", "table", "output format")
	root.AddCommand(NewPullCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} }))

	pull, rest, err := root.Find(append([]string{"pull"}, args...))
	if err != nil {
		t.Fatalf("find pull: %v", err)
	}
	if err := pull.ParseFlags(rest); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	outputFile, err = pull.Flags().GetString("output-file")
	if err != nil {
		t.Fatalf("output-file flag: %v", err)
	}
	return format, outputFile
}

// The global --output selects the format on pull; a pull-local flag of the
// same name once shadowed it, so --output json named a file and the table
// renderer wrote "// Image pulled successfully" to stdout.
func TestNewPullCommand_GlobalOutputSelectsFormat(t *testing.T) {
	for _, args := range [][]string{
		{"--output", "json", "registry.example.com/app:v1"},
		{"-o", "json", "registry.example.com/app:v1"},
	} {
		format, outputFile := pullUnderRoot(t, args...)
		if format != "json" {
			t.Errorf("%v: format = %q, want json", args, format)
		}
		if outputFile != "" {
			t.Errorf("%v: output file = %q, want none", args, outputFile)
		}
	}
}

func TestNewPullCommand_OutputFileNamesTheFile(t *testing.T) {
	format, outputFile := pullUnderRoot(t, "--output-file", "image.json", "registry.example.com/app:v1")
	if outputFile != "image.json" {
		t.Errorf("output file = %q, want image.json", outputFile)
	}
	if format != "table" {
		t.Errorf("format = %q, want the table default", format)
	}
}

func TestRunPull_InvalidImageReference(t *testing.T) {
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
			err := runPull(flags, tt.ref, false, false, "", "")
			if err == nil {
				t.Error("expected error for invalid reference")
			}

			if _, ok := err.(ErrInvalidImageReference); !ok {
				t.Errorf("expected ErrInvalidImageReference, got %T: %v", err, err)
			}
		})
	}
}

func TestNewPullCommand_DefaultFlagValues(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPullCommand(getFlags)

	decryptFlag := cmd.Flags().Lookup("decrypt")
	if decryptFlag == nil {
		t.Fatal("decrypt flag not found")
	}
	if decryptFlag.DefValue != "false" {
		t.Errorf("expected decrypt default to be 'false', got %q", decryptFlag.DefValue)
	}

	verifyFlag := cmd.Flags().Lookup("verify")
	if verifyFlag == nil {
		t.Fatal("verify flag not found")
	}
	if verifyFlag.DefValue != "false" {
		t.Errorf("expected verify default to be 'false', got %q", verifyFlag.DefValue)
	}

	platformFlag := cmd.Flags().Lookup("platform")
	if platformFlag == nil {
		t.Fatal("platform flag not found")
	}
	if platformFlag.DefValue != "" {
		t.Errorf("expected platform default to be empty, got %q", platformFlag.DefValue)
	}

	outputFlag := cmd.Flags().Lookup("output-file")
	if outputFlag == nil {
		t.Fatal("output flag not found")
	}
	if outputFlag.DefValue != "" {
		t.Errorf("expected output default to be empty, got %q", outputFlag.DefValue)
	}
}

func TestNewPullCommand_FlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPullCommand(getFlags)

	decryptFlag := cmd.Flags().Lookup("decrypt")
	if decryptFlag.Usage == "" {
		t.Error("decrypt flag should have usage text")
	}

	verifyFlag := cmd.Flags().Lookup("verify")
	if verifyFlag.Usage == "" {
		t.Error("verify flag should have usage text")
	}

	platformFlag := cmd.Flags().Lookup("platform")
	if platformFlag.Usage == "" {
		t.Error("platform flag should have usage text")
	}

	outputFlag := cmd.Flags().Lookup("output-file")
	if outputFlag.Usage == "" {
		t.Error("output flag should have usage text")
	}
}

func TestPullResult_EmptyPlatform(t *testing.T) {
	result := PullResult{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		Size:      1024,
		Decrypted: false,
		Verified:  false,
		Platform:  "",
		Timestamp: 0,
	}

	if result.Platform != "" {
		t.Errorf("expected empty Platform, got %q", result.Platform)
	}
}

func TestNewPullCommand_RunEExists(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewPullCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewPullCommand_FlagTypes(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPullCommand(getFlags)

	// Verify decrypt is a bool flag
	decryptFlag := cmd.Flags().Lookup("decrypt")
	if decryptFlag == nil {
		t.Fatal("decrypt flag not found")
	}
	if decryptFlag.Value.Type() != "bool" {
		t.Errorf("expected decrypt flag to be bool, got %s", decryptFlag.Value.Type())
	}

	// Verify verify is a bool flag
	verifyFlag := cmd.Flags().Lookup("verify")
	if verifyFlag == nil {
		t.Fatal("verify flag not found")
	}
	if verifyFlag.Value.Type() != "bool" {
		t.Errorf("expected verify flag to be bool, got %s", verifyFlag.Value.Type())
	}

	// Verify platform is a string flag
	platformFlag := cmd.Flags().Lookup("platform")
	if platformFlag == nil {
		t.Fatal("platform flag not found")
	}
	if platformFlag.Value.Type() != "string" {
		t.Errorf("expected platform flag to be string, got %s", platformFlag.Value.Type())
	}

	// Verify output is a string flag
	outputFlag := cmd.Flags().Lookup("output-file")
	if outputFlag == nil {
		t.Fatal("output flag not found")
	}
	if outputFlag.Value.Type() != "string" {
		t.Errorf("expected output flag to be string, got %s", outputFlag.Value.Type())
	}
}
