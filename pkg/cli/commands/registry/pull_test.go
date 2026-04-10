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
		{name: "verify", shorthand: "v"},
		{name: "platform", shorthand: "p"},
		{name: "output", shorthand: "o"},
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

func TestPullResult_Fields(t *testing.T) {
	result := PullResult{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		Size:      2048,
		Decrypted: true,
		Verified:  true,
		Platform:  "linux/amd64",
		Timestamp: 1234567890,
	}

	if result.Reference != "myrepo/myimage:v1.0" {
		t.Errorf("unexpected Reference: %q", result.Reference)
	}

	if result.Digest != "sha256:abc123" {
		t.Errorf("unexpected Digest: %q", result.Digest)
	}

	if result.Size != 2048 {
		t.Errorf("unexpected Size: %d", result.Size)
	}

	if !result.Decrypted {
		t.Error("expected Decrypted to be true")
	}

	if !result.Verified {
		t.Error("expected Verified to be true")
	}

	if result.Platform != "linux/amd64" {
		t.Errorf("unexpected Platform: %q", result.Platform)
	}

	if result.Timestamp != 1234567890 {
		t.Errorf("unexpected Timestamp: %d", result.Timestamp)
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

	outputFlag := cmd.Flags().Lookup("output")
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

	outputFlag := cmd.Flags().Lookup("output")
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

func TestPullResult_ZeroValues(t *testing.T) {
	var result PullResult

	if result.Reference != "" {
		t.Errorf("expected empty Reference, got %q", result.Reference)
	}

	if result.Digest != "" {
		t.Errorf("expected empty Digest, got %q", result.Digest)
	}

	if result.Size != 0 {
		t.Errorf("expected zero Size, got %d", result.Size)
	}

	if result.Decrypted {
		t.Error("expected Decrypted to be false")
	}

	if result.Verified {
		t.Error("expected Verified to be false")
	}

	if result.Timestamp != 0 {
		t.Errorf("expected zero Timestamp, got %d", result.Timestamp)
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
	outputFlag := cmd.Flags().Lookup("output")
	if outputFlag == nil {
		t.Fatal("output flag not found")
	}
	if outputFlag.Value.Type() != "string" {
		t.Errorf("expected output flag to be string, got %s", outputFlag.Value.Type())
	}
}
