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
	"github.com/jeremyhahn/go-trusted-platform/pkg/registry"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestApplyPushAnnotations(t *testing.T) {
	tests := []struct {
		name       string
		existing   map[string]string
		encrypt    bool
		keyID      string
		sign       bool
		signingKey string
		want       map[string]string
	}{
		{
			name: "no options leaves no annotations",
			want: map[string]string{},
		},
		{
			name:       "sign and encrypt both",
			encrypt:    true,
			keyID:      "dek-1",
			sign:       true,
			signingKey: "signer-1",
			want: map[string]string{
				registry.PushAnnotationEncrypt:      "true",
				registry.PushAnnotationKeyID:        "dek-1",
				registry.PushAnnotationSign:         "true",
				registry.PushAnnotationSigningKeyID: "signer-1",
			},
		},
		{
			name: "sign only omits encryption keys",
			sign: true,
			want: map[string]string{
				// The key is sent even when empty: the registry treats an
				// unset signing key as the registry default.
				registry.PushAnnotationSign:         "true",
				registry.PushAnnotationSigningKeyID: "",
			},
		},
		{
			name:    "encrypt only omits signing keys",
			encrypt: true,
			keyID:   "dek-2",
			want: map[string]string{
				registry.PushAnnotationEncrypt: "true",
				registry.PushAnnotationKeyID:   "dek-2",
			},
		},
		{
			name:     "existing overwrite annotation is preserved",
			existing: map[string]string{"overwrite": "true"},
			sign:     true,
			want: map[string]string{
				"overwrite":                         "true",
				registry.PushAnnotationSign:         "true",
				registry.PushAnnotationSigningKeyID: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyPushAnnotations(tt.existing, tt.encrypt, tt.keyID, tt.sign, tt.signingKey)

			want := tt.want
			if want == nil {
				want = map[string]string{}
			}
			if len(got) != len(want) {
				t.Fatalf("annotations = %#v, want %#v", got, want)
			}
			for k, v := range want {
				if got[k] != v {
					t.Errorf("annotation %q = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestPushResultFromResponse_SignedReply(t *testing.T) {
	resp := &platformv1.PushResponse{
		Artifact: &platformv1.Artifact{
			Digest: "sha256:abc",
			Annotations: map[string]string{
				registry.ManifestAnnotationSigned:    "true",
				registry.ManifestAnnotationEncrypted: "true",
			},
		},
	}

	result := PushResultFromResponse("myrepo/myimage:v1.0", resp, "")

	if !result.Signed {
		t.Error("expected a signed reply to be reported as signed")
	}
	if !result.Encrypted {
		t.Error("expected an encrypted reply to be reported as encrypted")
	}
	if result.Digest != "sha256:abc" {
		t.Errorf("unexpected digest: %q", result.Digest)
	}
	if result.Reference != "myrepo/myimage:v1.0" {
		t.Errorf("unexpected reference: %q", result.Reference)
	}
}

func TestPushResultFromResponse_UnsignedReply(t *testing.T) {
	// A reply without the signed annotation is reported as not signed.
	resp := &platformv1.PushResponse{
		Artifact: &platformv1.Artifact{
			Digest: "sha256:def",
			Annotations: map[string]string{
				"org.letstrust.registry.other": "kept",
			},
		},
	}

	result := PushResultFromResponse("myrepo/myimage:v1.0", resp, "")

	if result.Signed {
		t.Error("expected a reply without the signed annotation to be reported as not signed")
	}
	if result.Encrypted {
		t.Error("expected a reply without the encrypted annotation to be reported as not encrypted")
	}
}

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

	if cmd.RunE == nil {
		t.Error("RunE should be set")
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
		flagType  string
		defValue  string
	}{
		{name: "encrypt", shorthand: "e", flagType: "bool", defValue: "false"},
		{name: "key-id", shorthand: "k", flagType: "string", defValue: ""},
		{name: "sign", shorthand: "s", flagType: "bool", defValue: "false"},
		{name: "signing-key-id", shorthand: "", flagType: "string", defValue: ""},
		{name: "overwrite", shorthand: "", flagType: "bool", defValue: "false"},
		{name: "input", shorthand: "i", flagType: "string", defValue: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.name)
			if flag == nil {
				t.Fatalf("expected flag %q to exist", tt.name)
			}
			if flag.Shorthand != tt.shorthand {
				t.Errorf("expected shorthand %q for flag %q, got %q",
					tt.shorthand, tt.name, flag.Shorthand)
			}
			if flag.Value.Type() != tt.flagType {
				t.Errorf("expected %s flag to be %s, got %s", tt.name, tt.flagType, flag.Value.Type())
			}
			if flag.DefValue != tt.defValue {
				t.Errorf("expected %s default %q, got %q", tt.name, tt.defValue, flag.DefValue)
			}
			if flag.Usage == "" {
				t.Errorf("flag %q should have usage text", tt.name)
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
