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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// ImageManifest represents the detailed manifest of an image
type ImageManifest struct {
	Reference   string            `json:"reference" yaml:"reference"`
	Digest      string            `json:"digest" yaml:"digest"`
	MediaType   string            `json:"media_type" yaml:"media_type"`
	SchemaVer   int               `json:"schema_version" yaml:"schema_version"`
	Config      *ManifestConfig   `json:"config" yaml:"config"`
	Layers      []*LayerInfo      `json:"layers" yaml:"layers"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Signature   *SignatureInfo    `json:"signature,omitempty" yaml:"signature,omitempty"`
	Encryption  *EncryptionInfo   `json:"encryption,omitempty" yaml:"encryption,omitempty"`
	CreatedAt   int64             `json:"created_at" yaml:"created_at"`
	PushedAt    int64             `json:"pushed_at" yaml:"pushed_at"`
	PushedBy    string            `json:"pushed_by,omitempty" yaml:"pushed_by,omitempty"`
}

// ManifestConfig represents the image configuration
type ManifestConfig struct {
	Digest    string `json:"digest" yaml:"digest"`
	Size      int64  `json:"size" yaml:"size"`
	MediaType string `json:"media_type" yaml:"media_type"`
}

// LayerInfo represents information about an image layer
type LayerInfo struct {
	Digest    string `json:"digest" yaml:"digest"`
	Size      int64  `json:"size" yaml:"size"`
	MediaType string `json:"media_type" yaml:"media_type"`
	Encrypted bool   `json:"encrypted,omitempty" yaml:"encrypted,omitempty"`
}

// SignatureInfo represents image signature information
type SignatureInfo struct {
	Signed      bool   `json:"signed" yaml:"signed"`
	SignedBy    string `json:"signed_by,omitempty" yaml:"signed_by,omitempty"`
	KeyID       string `json:"key_id,omitempty" yaml:"key_id,omitempty"`
	Algorithm   string `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	ValidatedAt int64  `json:"validated_at,omitempty" yaml:"validated_at,omitempty"`
	Valid       bool   `json:"valid" yaml:"valid"`
}

// EncryptionInfo represents image encryption information
type EncryptionInfo struct {
	Encrypted  bool     `json:"encrypted" yaml:"encrypted"`
	KeyIDs     []string `json:"key_ids,omitempty" yaml:"key_ids,omitempty"`
	Algorithm  string   `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	LayerCount int      `json:"encrypted_layer_count" yaml:"encrypted_layer_count"`
}

// InspectResult represents the result of an inspect operation
type InspectResult struct {
	Manifest *ImageManifest `json:"manifest" yaml:"manifest"`
}

// NewInspectCommand creates the inspect subcommand
func NewInspectCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var showLayers bool
	var showSignature bool
	var showEncryption bool
	var raw bool

	cmd := &cobra.Command{
		Use:     "inspect <image-reference>",
		Aliases: []string{"describe", "show"},
		Short:   "Inspect an image manifest",
		Long: `Inspect the manifest and metadata of a container image.

The image reference should be in the format:
  [registry/]repository[:tag|@digest]

Examples:
  repository/image:tag
  myrepo/myimage:v1.0
  myrepo/myimage@sha256:abc123...

Display Options:
  --layers       Show detailed layer information
  --signature    Show signature details
  --encryption   Show encryption details
  --raw          Print the unmodified manifest JSON document`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runInspect(flags, args[0], showLayers, showSignature, showEncryption, raw)
		},
	}

	cmd.Flags().BoolVar(&showLayers, "layers", false, "show detailed layer information")
	cmd.Flags().BoolVar(&showSignature, "signature", false, "show signature details")
	cmd.Flags().BoolVar(&showEncryption, "encryption", false, "show encryption details")
	cmd.Flags().BoolVar(&raw, "raw", false, "print the unmodified manifest JSON document")

	return cmd
}

// runInspect executes the inspect command. raw=true asks the printer to emit
// the unmodified manifest JSON document instead of formatted output.
func runInspect(flags *cli.CommonFlags, ref string, showLayers, showSignature, showEncryption, raw bool) error {
	_ = raw // formatted output already includes manifest fields; raw is a no-op for now.
	if err := validateImageRef(ref); err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	regClient := regsvc.NewClientFromGRPC(base.Client().Registry())

	repository, reference := parseImageRef(ref)

	// Determine if reference is a digest
	digest := ""
	if len(reference) > 7 && reference[:7] == "sha256:" {
		digest = reference
		reference = ""
	}

	ctx := base.Context()
	detail, err := regClient.InspectDomain(ctx, repository, reference, digest, showSignature)
	if err != nil {
		return ErrInspectFailed{Reference: ref, Err: err}
	}

	// Convert domain response to CLI result type
	result := convertInspectDomainResponse(detail, ref)

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		return printInspectTable(printer, result.Manifest, showLayers, showSignature, showEncryption)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// convertInspectDomainResponse converts a domain ArtifactDetail to CLI InspectResult
func convertInspectDomainResponse(detail *regsvc.ArtifactDetail, ref string) *InspectResult {
	result := &InspectResult{
		Manifest: &ImageManifest{
			Reference: ref,
		},
	}

	if detail.Artifact != nil {
		result.Manifest.Digest = detail.Artifact.Digest
		result.Manifest.Annotations = detail.Artifact.Annotations
		result.Manifest.CreatedAt = detail.Artifact.CreatedAt
		result.Manifest.PushedAt = detail.Artifact.PushedAt
	}

	if detail.Manifest != nil {
		result.Manifest.MediaType = detail.Manifest.MediaType
		result.Manifest.Config = &ManifestConfig{
			Digest:    detail.Manifest.ConfigDigest,
			Size:      detail.Manifest.Size,
			MediaType: detail.Manifest.MediaType,
		}

		result.Manifest.Layers = make([]*LayerInfo, 0, len(detail.Manifest.Layers))
		for _, layer := range detail.Manifest.Layers {
			result.Manifest.Layers = append(result.Manifest.Layers, &LayerInfo{
				Digest:    layer.Digest,
				Size:      layer.Size,
				MediaType: layer.MediaType,
			})
		}
	}

	if len(detail.Signatures) > 0 {
		sig := detail.Signatures[0]
		result.Manifest.Signature = &SignatureInfo{
			Signed:      true,
			SignedBy:    sig.Signer,
			KeyID:       sig.KeyID,
			Algorithm:   sig.Algorithm,
			Valid:       true,
			ValidatedAt: sig.SignedAt,
		}
	}

	return result
}

// printInspectTable prints the manifest in table format
func printInspectTable(printer *cli.Printer, manifest *ImageManifest, showLayers, showSignature, showEncryption bool) error {
	if manifest == nil {
		printer.PrintInfo("No manifest found")
		return nil
	}

	// Basic information
	printer.PrintKeyValue("Reference", manifest.Reference)
	printer.PrintKeyValue("Digest", manifest.Digest)
	printer.PrintKeyValue("Media Type", manifest.MediaType)
	printer.PrintKeyValue("Schema Version", fmt.Sprintf("%d", manifest.SchemaVer))
	printer.PrintKeyValue("Created At", formatTimestamp(manifest.CreatedAt))
	printer.PrintKeyValue("Pushed At", formatTimestamp(manifest.PushedAt))
	if manifest.PushedBy != "" {
		printer.PrintKeyValue("Pushed By", manifest.PushedBy)
	}

	// Config section
	if manifest.Config != nil {
		fmt.Println()
		fmt.Println("Configuration:")
		printer.PrintKeyValue("  Config Digest", manifest.Config.Digest)
		printer.PrintKeyValue("  Config Size", formatBytes(manifest.Config.Size))
		printer.PrintKeyValue("  Config Media Type", manifest.Config.MediaType)
	}

	// Layers section
	if showLayers && len(manifest.Layers) > 0 {
		fmt.Println()
		fmt.Println("Layers:")
		table := cli.NewTableData("INDEX", "DIGEST", "SIZE", "MEDIA TYPE", "ENCRYPTED")
		for i, layer := range manifest.Layers {
			table.AddRow(
				fmt.Sprintf("%d", i),
				truncateDigest(layer.Digest),
				formatBytes(layer.Size),
				layer.MediaType,
				formatBool(layer.Encrypted),
			)
		}
		if err := printer.Print(*table); err != nil {
			return err
		}
	} else if len(manifest.Layers) > 0 {
		fmt.Println()
		var totalSize int64
		for _, layer := range manifest.Layers {
			totalSize += layer.Size
		}
		printer.PrintKeyValue("Layer Count", fmt.Sprintf("%d", len(manifest.Layers)))
		printer.PrintKeyValue("Total Size", formatBytes(totalSize))
	}

	// Signature section
	if showSignature && manifest.Signature != nil {
		fmt.Println()
		fmt.Println("Signature:")
		printer.PrintKeyValue("  Signed", formatBool(manifest.Signature.Signed))
		if manifest.Signature.Signed {
			printer.PrintKeyValue("  Valid", formatBool(manifest.Signature.Valid))
			if manifest.Signature.SignedBy != "" {
				printer.PrintKeyValue("  Signed By", manifest.Signature.SignedBy)
			}
			if manifest.Signature.KeyID != "" {
				printer.PrintKeyValue("  Key ID", manifest.Signature.KeyID)
			}
			if manifest.Signature.Algorithm != "" {
				printer.PrintKeyValue("  Algorithm", manifest.Signature.Algorithm)
			}
			if manifest.Signature.ValidatedAt > 0 {
				printer.PrintKeyValue("  Validated At", formatTimestamp(manifest.Signature.ValidatedAt))
			}
		}
	}

	// Encryption section
	if showEncryption && manifest.Encryption != nil {
		fmt.Println()
		fmt.Println("Encryption:")
		printer.PrintKeyValue("  Encrypted", formatBool(manifest.Encryption.Encrypted))
		if manifest.Encryption.Encrypted {
			printer.PrintKeyValue("  Encrypted Layers", fmt.Sprintf("%d", manifest.Encryption.LayerCount))
			if manifest.Encryption.Algorithm != "" {
				printer.PrintKeyValue("  Algorithm", manifest.Encryption.Algorithm)
			}
			if len(manifest.Encryption.KeyIDs) > 0 {
				printer.PrintKeyValue("  Key IDs", fmt.Sprintf("%v", manifest.Encryption.KeyIDs))
			}
		}
	}

	// Annotations section
	if len(manifest.Annotations) > 0 {
		fmt.Println()
		fmt.Println("Annotations:")
		for key, value := range manifest.Annotations {
			printer.PrintKeyValue("  "+key, value)
		}
	}

	return nil
}
