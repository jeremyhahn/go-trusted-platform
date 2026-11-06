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

	if cmd.RunE == nil {
		t.Error("RunE should be set")
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

	for _, name := range []string{"layers", "signature", "encryption", "raw"} {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("flag %q not found", name)
			}
			if flag.Value.Type() != "bool" {
				t.Errorf("expected %s flag to be bool, got %s", name, flag.Value.Type())
			}
			if flag.DefValue != "false" {
				t.Errorf("expected default value 'false' for %q, got %q", name, flag.DefValue)
			}
			if flag.Usage == "" {
				t.Errorf("flag %q should have usage text", name)
			}
		})
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
