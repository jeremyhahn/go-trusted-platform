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

func TestNewPushCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewPushCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewPushCommand returned nil")
	}

	if cmd.Use != "push <image-reference>" {
		t.Errorf("expected Use to be 'push <image-reference>', got %q", cmd.Use)
	}

	if cmd.Short != "Push an image to the registry" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewPushCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPushCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(cmd.Long) < 100 {
		t.Error("Long description should be descriptive (at least 100 chars)")
	}
}

func TestNewPushCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPushCommand(getFlags)

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

func TestNewPushCommand_HasFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPushCommand(getFlags)

	tests := []struct {
		name      string
		shorthand string
	}{
		{name: "encrypt", shorthand: "e"},
		{name: "key-id", shorthand: "k"},
		{name: "sign", shorthand: "s"},
		{name: "signing-key-id", shorthand: ""},
		{name: "overwrite", shorthand: ""},
		{name: "input", shorthand: "i"},
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

func TestPushResult_JSONTags(t *testing.T) {
	result := PushResult{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		Size:      1024,
		Encrypted: true,
		KeyID:     "my-key",
		Signed:    true,
		Timestamp: 1234567890,
	}

	if result.Reference != "myrepo/myimage:v1.0" {
		t.Errorf("unexpected Reference: %q", result.Reference)
	}

	if result.Digest != "sha256:abc123" {
		t.Errorf("unexpected Digest: %q", result.Digest)
	}

	if result.Size != 1024 {
		t.Errorf("unexpected Size: %d", result.Size)
	}

	if !result.Encrypted {
		t.Error("expected Encrypted to be true")
	}

	if result.KeyID != "my-key" {
		t.Errorf("unexpected KeyID: %q", result.KeyID)
	}

	if !result.Signed {
		t.Error("expected Signed to be true")
	}

	if result.Timestamp != 1234567890 {
		t.Errorf("unexpected Timestamp: %d", result.Timestamp)
	}
}

func TestNewPushCommand_DefaultFlagValues(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPushCommand(getFlags)

	encryptFlag := cmd.Flags().Lookup("encrypt")
	if encryptFlag == nil {
		t.Fatal("encrypt flag not found")
	}
	if encryptFlag.DefValue != "false" {
		t.Errorf("expected encrypt default to be 'false', got %q", encryptFlag.DefValue)
	}

	keyIDFlag := cmd.Flags().Lookup("key-id")
	if keyIDFlag == nil {
		t.Fatal("key-id flag not found")
	}
	if keyIDFlag.DefValue != "" {
		t.Errorf("expected key-id default to be empty, got %q", keyIDFlag.DefValue)
	}

	signFlag := cmd.Flags().Lookup("sign")
	if signFlag == nil {
		t.Fatal("sign flag not found")
	}
	if signFlag.DefValue != "false" {
		t.Errorf("expected sign default to be 'false', got %q", signFlag.DefValue)
	}

	overwriteFlag := cmd.Flags().Lookup("overwrite")
	if overwriteFlag == nil {
		t.Fatal("overwrite flag not found")
	}
	if overwriteFlag.DefValue != "false" {
		t.Errorf("expected overwrite default to be 'false', got %q", overwriteFlag.DefValue)
	}

	inputFlag := cmd.Flags().Lookup("input")
	if inputFlag == nil {
		t.Fatal("input flag not found")
	}
	if inputFlag.DefValue != "" {
		t.Errorf("expected input default to be empty, got %q", inputFlag.DefValue)
	}
}

func TestNewPushCommand_FlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPushCommand(getFlags)

	encryptFlag := cmd.Flags().Lookup("encrypt")
	if encryptFlag.Usage == "" {
		t.Error("encrypt flag should have usage text")
	}

	keyIDFlag := cmd.Flags().Lookup("key-id")
	if keyIDFlag.Usage == "" {
		t.Error("key-id flag should have usage text")
	}

	signFlag := cmd.Flags().Lookup("sign")
	if signFlag.Usage == "" {
		t.Error("sign flag should have usage text")
	}

	inputFlag := cmd.Flags().Lookup("input")
	if inputFlag.Usage == "" {
		t.Error("input flag should have usage text")
	}
}

func TestNewPushCommand_RunEExists(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewPushCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewPushCommand_FlagTypes(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPushCommand(getFlags)

	// Verify encrypt is a bool flag
	encryptFlag := cmd.Flags().Lookup("encrypt")
	if encryptFlag == nil {
		t.Fatal("encrypt flag not found")
	}
	if encryptFlag.Value.Type() != "bool" {
		t.Errorf("expected encrypt flag to be bool, got %s", encryptFlag.Value.Type())
	}

	// Verify key-id is a string flag
	keyIDFlag := cmd.Flags().Lookup("key-id")
	if keyIDFlag == nil {
		t.Fatal("key-id flag not found")
	}
	if keyIDFlag.Value.Type() != "string" {
		t.Errorf("expected key-id flag to be string, got %s", keyIDFlag.Value.Type())
	}

	// Verify sign is a bool flag
	signFlag := cmd.Flags().Lookup("sign")
	if signFlag == nil {
		t.Fatal("sign flag not found")
	}
	if signFlag.Value.Type() != "bool" {
		t.Errorf("expected sign flag to be bool, got %s", signFlag.Value.Type())
	}

	// Verify signing-key-id is a string flag
	signingKeyIDFlag := cmd.Flags().Lookup("signing-key-id")
	if signingKeyIDFlag == nil {
		t.Fatal("signing-key-id flag not found")
	}
	if signingKeyIDFlag.Value.Type() != "string" {
		t.Errorf("expected signing-key-id flag to be string, got %s", signingKeyIDFlag.Value.Type())
	}

	// Verify overwrite is a bool flag
	overwriteFlag := cmd.Flags().Lookup("overwrite")
	if overwriteFlag == nil {
		t.Fatal("overwrite flag not found")
	}
	if overwriteFlag.Value.Type() != "bool" {
		t.Errorf("expected overwrite flag to be bool, got %s", overwriteFlag.Value.Type())
	}

	// Verify input is a string flag
	inputFlag := cmd.Flags().Lookup("input")
	if inputFlag == nil {
		t.Fatal("input flag not found")
	}
	if inputFlag.Value.Type() != "string" {
		t.Errorf("expected input flag to be string, got %s", inputFlag.Value.Type())
	}
}

func TestPushResult_ZeroValues(t *testing.T) {
	var result PushResult

	if result.Reference != "" {
		t.Errorf("expected empty Reference, got %q", result.Reference)
	}

	if result.Digest != "" {
		t.Errorf("expected empty Digest, got %q", result.Digest)
	}

	if result.Size != 0 {
		t.Errorf("expected zero Size, got %d", result.Size)
	}

	if result.Encrypted {
		t.Error("expected Encrypted to be false")
	}

	if result.KeyID != "" {
		t.Errorf("expected empty KeyID, got %q", result.KeyID)
	}

	if result.Signed {
		t.Error("expected Signed to be false")
	}

	if result.Timestamp != 0 {
		t.Errorf("expected zero Timestamp, got %d", result.Timestamp)
	}
}
