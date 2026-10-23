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
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// TestConvertInspectDomainResponse_OSAndArchitecture checks that inspect's
// JSON document carries the artifact's os and architecture
// (docs/registry/cli.md §5).
func TestConvertInspectDomainResponse_OSAndArchitecture(t *testing.T) {
	detail := &regsvc.ArtifactDetail{
		Artifact: &regsvc.Artifact{Repository: "apps/api", Tag: "1.0", OS: "linux", Architecture: "amd64"},
	}

	out, err := json.Marshal(convertInspectDomainResponse(detail, "apps/api:1.0"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc struct {
		Manifest map[string]any `json:"manifest"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Manifest["os"] != "linux" {
		t.Errorf("os = %v, want linux", doc.Manifest["os"])
	}
	if doc.Manifest["architecture"] != "amd64" {
		t.Errorf("architecture = %v, want amd64", doc.Manifest["architecture"])
	}
}

// TestConvertInspectDomainResponse_NoArtifact checks that a detail without
// an artifact omits os and architecture rather than printing empty values.
func TestConvertInspectDomainResponse_NoArtifact(t *testing.T) {
	out, err := json.Marshal(convertInspectDomainResponse(&regsvc.ArtifactDetail{}, "apps/api:1.0"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc struct {
		Manifest map[string]any `json:"manifest"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"os", "architecture"} {
		if _, ok := doc.Manifest[key]; ok {
			t.Errorf("%s present without an artifact", key)
		}
	}
}

func TestNewInspectCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewInspectCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewInspectCommand returned nil")
	}

	if cmd.Use != "inspect <image-reference>" {
		t.Errorf("expected Use to be 'inspect <image-reference>', got %q", cmd.Use)
	}

	if cmd.Short != "Inspect an image manifest" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewInspectCommand_HasAliases(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewInspectCommand(getFlags)

	expectedAliases := []string{"describe", "show"}
	if len(cmd.Aliases) != len(expectedAliases) {
		t.Errorf("expected %d aliases, got %d", len(expectedAliases), len(cmd.Aliases))
	}

	for i, alias := range expectedAliases {
		if cmd.Aliases[i] != alias {
			t.Errorf("expected alias %q at index %d, got %q", alias, i, cmd.Aliases[i])
		}
	}
}

func TestNewInspectCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewInspectCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(cmd.Long) < 100 {
		t.Error("Long description should be descriptive (at least 100 chars)")
	}
}

func TestNewInspectCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewInspectCommand(getFlags)

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

func TestNewInspectCommand_HasFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewInspectCommand(getFlags)

	tests := []struct {
		name      string
		shorthand string
	}{
		{name: "layers", shorthand: ""},
		{name: "signature", shorthand: ""},
		{name: "encryption", shorthand: ""},
		{name: "raw", shorthand: ""},
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

func TestImageManifest_Fields(t *testing.T) {
	manifest := ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Config: &ManifestConfig{
			Digest:    "sha256:config123",
			Size:      1024,
			MediaType: "application/vnd.oci.image.config.v1+json",
		},
		Layers: []*LayerInfo{
			{
				Digest:    "sha256:layer1",
				Size:      10240,
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Encrypted: false,
			},
		},
		Annotations: map[string]string{"key": "value"},
		CreatedAt:   1234567890,
		PushedAt:    1234567900,
		PushedBy:    "user@example.com",
	}

	if manifest.Reference != "myrepo/myimage:v1.0" {
		t.Errorf("unexpected Reference: %q", manifest.Reference)
	}

	if manifest.Digest != "sha256:abc123" {
		t.Errorf("unexpected Digest: %q", manifest.Digest)
	}

	if manifest.MediaType != "application/vnd.oci.image.manifest.v1+json" {
		t.Errorf("unexpected MediaType: %q", manifest.MediaType)
	}

	if manifest.SchemaVer != 2 {
		t.Errorf("unexpected SchemaVer: %d", manifest.SchemaVer)
	}

	if manifest.Config == nil {
		t.Fatal("Config should not be nil")
	}

	if len(manifest.Layers) != 1 {
		t.Errorf("expected 1 layer, got %d", len(manifest.Layers))
	}

	if manifest.PushedBy != "user@example.com" {
		t.Errorf("unexpected PushedBy: %q", manifest.PushedBy)
	}
}

func TestManifestConfig_Fields(t *testing.T) {
	config := ManifestConfig{
		Digest:    "sha256:config123",
		Size:      2048,
		MediaType: "application/vnd.oci.image.config.v1+json",
	}

	if config.Digest != "sha256:config123" {
		t.Errorf("unexpected Digest: %q", config.Digest)
	}

	if config.Size != 2048 {
		t.Errorf("unexpected Size: %d", config.Size)
	}

	if config.MediaType != "application/vnd.oci.image.config.v1+json" {
		t.Errorf("unexpected MediaType: %q", config.MediaType)
	}
}

func TestLayerInfo_Fields(t *testing.T) {
	layer := LayerInfo{
		Digest:    "sha256:layer123",
		Size:      10240,
		MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
		Encrypted: true,
	}

	if layer.Digest != "sha256:layer123" {
		t.Errorf("unexpected Digest: %q", layer.Digest)
	}

	if layer.Size != 10240 {
		t.Errorf("unexpected Size: %d", layer.Size)
	}

	if layer.MediaType != "application/vnd.oci.image.layer.v1.tar+gzip" {
		t.Errorf("unexpected MediaType: %q", layer.MediaType)
	}

	if !layer.Encrypted {
		t.Error("expected Encrypted to be true")
	}
}

func TestSignatureInfo_Fields(t *testing.T) {
	sig := SignatureInfo{
		Signed:      true,
		SignedBy:    "user@example.com",
		KeyID:       "key-123",
		Algorithm:   "ECDSA-P256",
		ValidatedAt: 1234567890,
		Valid:       true,
	}

	if !sig.Signed {
		t.Error("expected Signed to be true")
	}

	if sig.SignedBy != "user@example.com" {
		t.Errorf("unexpected SignedBy: %q", sig.SignedBy)
	}

	if sig.KeyID != "key-123" {
		t.Errorf("unexpected KeyID: %q", sig.KeyID)
	}

	if sig.Algorithm != "ECDSA-P256" {
		t.Errorf("unexpected Algorithm: %q", sig.Algorithm)
	}

	if sig.ValidatedAt != 1234567890 {
		t.Errorf("unexpected ValidatedAt: %d", sig.ValidatedAt)
	}

	if !sig.Valid {
		t.Error("expected Valid to be true")
	}
}

func TestEncryptionInfo_Fields(t *testing.T) {
	enc := EncryptionInfo{
		Encrypted:  true,
		KeyIDs:     []string{"key-1", "key-2"},
		Algorithm:  "AES-256-GCM",
		LayerCount: 3,
	}

	if !enc.Encrypted {
		t.Error("expected Encrypted to be true")
	}

	if len(enc.KeyIDs) != 2 {
		t.Errorf("expected 2 key IDs, got %d", len(enc.KeyIDs))
	}

	if enc.Algorithm != "AES-256-GCM" {
		t.Errorf("unexpected Algorithm: %q", enc.Algorithm)
	}

	if enc.LayerCount != 3 {
		t.Errorf("unexpected LayerCount: %d", enc.LayerCount)
	}
}

func TestNewInspectCommand_DefaultFlagValues(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewInspectCommand(getFlags)

	flags := []string{"layers", "signature", "encryption", "raw"}

	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("flag %q not found", name)
			}
			if flag.DefValue != "false" {
				t.Errorf("expected default value 'false' for %q, got %q", name, flag.DefValue)
			}
		})
	}
}

func TestNewInspectCommand_FlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewInspectCommand(getFlags)

	flags := []string{"layers", "signature", "encryption", "raw"}

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

func TestInspectResult_Fields(t *testing.T) {
	result := InspectResult{
		Manifest: &ImageManifest{
			Reference: "myrepo/myimage:v1.0",
			Digest:    "sha256:abc123",
		},
	}

	if result.Manifest == nil {
		t.Fatal("Manifest should not be nil")
	}

	if result.Manifest.Reference != "myrepo/myimage:v1.0" {
		t.Errorf("unexpected Reference: %q", result.Manifest.Reference)
	}
}

func TestPrintInspectTable_NilManifest(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	err := printInspectTable(printer, nil, false, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintInspectTable_MinimalManifest(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
	}

	err := printInspectTable(printer, manifest, false, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintInspectTable_WithLayers(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Layers: []*LayerInfo{
			{
				Digest:    "sha256:layer1",
				Size:      10240,
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Encrypted: false,
			},
			{
				Digest:    "sha256:layer2",
				Size:      20480,
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Encrypted: true,
			},
		},
	}

	err := printInspectTable(printer, manifest, true, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintInspectTable_WithSignature(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Signature: &SignatureInfo{
			Signed:      true,
			SignedBy:    "user@example.com",
			KeyID:       "key-123",
			Algorithm:   "ECDSA-P256",
			ValidatedAt: 1234567890,
			Valid:       true,
		},
	}

	err := printInspectTable(printer, manifest, false, true, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintInspectTable_WithEncryption(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Encryption: &EncryptionInfo{
			Encrypted:  true,
			KeyIDs:     []string{"key-1", "key-2"},
			Algorithm:  "AES-256-GCM",
			LayerCount: 3,
		},
	}

	err := printInspectTable(printer, manifest, false, false, true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintInspectTable_WithAnnotations(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Annotations: map[string]string{
			"org.opencontainers.image.title":   "My Image",
			"org.opencontainers.image.version": "1.0.0",
		},
	}

	err := printInspectTable(printer, manifest, false, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewInspectCommand_RunEExists(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewInspectCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewInspectCommand_FlagTypes(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewInspectCommand(getFlags)

	flags := []string{"layers", "signature", "encryption", "raw"}

	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("flag %q not found", name)
			}
			if flag.Value.Type() != "bool" {
				t.Errorf("expected %s flag to be bool, got %s", name, flag.Value.Type())
			}
		})
	}
}

func TestInspectResult_ZeroValues(t *testing.T) {
	var result InspectResult

	if result.Manifest != nil {
		t.Error("expected nil Manifest")
	}
}

func TestImageManifest_ZeroValues(t *testing.T) {
	var manifest ImageManifest

	if manifest.Reference != "" {
		t.Errorf("expected empty Reference, got %q", manifest.Reference)
	}

	if manifest.Digest != "" {
		t.Errorf("expected empty Digest, got %q", manifest.Digest)
	}

	if manifest.SchemaVer != 0 {
		t.Errorf("expected SchemaVer 0, got %d", manifest.SchemaVer)
	}

	if manifest.Config != nil {
		t.Error("expected nil Config")
	}

	if manifest.Layers != nil {
		t.Error("expected nil Layers")
	}
}

func TestPrintInspectTable_LayersNoShowLayers(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Layers: []*LayerInfo{
			{Digest: "sha256:layer1", Size: 1024},
			{Digest: "sha256:layer2", Size: 2048},
		},
	}

	// showLayers is false, so it should print summary instead of table
	err := printInspectTable(printer, manifest, false, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintInspectTable_UnsignedSignature(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Signature: &SignatureInfo{
			Signed: false,
		},
	}

	err := printInspectTable(printer, manifest, false, true, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintInspectTable_UnencryptedEncryption(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Encryption: &EncryptionInfo{
			Encrypted: false,
		},
	}

	err := printInspectTable(printer, manifest, false, false, true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintInspectTable_WithPushedBy(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		PushedBy:  "admin@example.com",
	}

	err := printInspectTable(printer, manifest, false, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintInspectTable_WithConfig(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Config: &ManifestConfig{
			Digest:    "sha256:config123",
			Size:      1024,
			MediaType: "application/vnd.oci.image.config.v1+json",
		},
	}

	err := printInspectTable(printer, manifest, false, false, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintInspectTable_SignatureWithPartialInfo(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	// Test signature without optional fields
	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Signature: &SignatureInfo{
			Signed:      true,
			Valid:       true,
			SignedBy:    "",
			KeyID:       "",
			Algorithm:   "",
			ValidatedAt: 0,
		},
	}

	err := printInspectTable(printer, manifest, false, true, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintInspectTable_EncryptionWithPartialInfo(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)

	// Test encryption without optional fields
	manifest := &ImageManifest{
		Reference: "myrepo/myimage:v1.0",
		Digest:    "sha256:abc123",
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		SchemaVer: 2,
		Encryption: &EncryptionInfo{
			Encrypted:  true,
			Algorithm:  "",
			KeyIDs:     nil,
			LayerCount: 1,
		},
	}

	err := printInspectTable(printer, manifest, false, false, true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
