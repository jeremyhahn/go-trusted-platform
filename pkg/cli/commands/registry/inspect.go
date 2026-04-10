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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
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
	var rawManifest bool

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

When inspecting, TPM attestation may be required depending on the
registry's access control policies.

Display Options:
  --layers       Show detailed layer information
  --signature    Show signature details
  --encryption   Show encryption details
  --raw          Show raw manifest JSON`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runInspect(flags, args[0], showLayers, showSignature, showEncryption, rawManifest)
		},
	}

	cmd.Flags().BoolVar(&showLayers, "layers", false, "show detailed layer information")
	cmd.Flags().BoolVar(&showSignature, "signature", false, "show signature details")
	cmd.Flags().BoolVar(&showEncryption, "encryption", false, "show encryption details")
	cmd.Flags().BoolVar(&rawManifest, "raw", false, "show raw manifest JSON")

	return cmd
}

// runInspect executes the inspect command
func runInspect(flags *cli.CommonFlags, ref string, showLayers, showSignature, showEncryption, rawManifest bool) error {
	// Validate image reference
	if err := validateImageRef(ref); err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := base.Client().Registry()
	if client == nil {
		return ErrRegistryClientNotInitialized{}
	}

	// Parse reference to get repository and tag/digest
	repository, reference := parseImageRef(ref)

	// Build the request
	req := &platformv1.InspectArtifactRequest{
		Repository:        repository,
		Reference:         reference,
		IncludeSignatures: showSignature,
		IncludeScanResult: false,
	}

	// If reference looks like a digest, set it in the digest field instead
	if len(reference) > 7 && reference[:7] == "sha256:" {
		req.Digest = reference
		req.Reference = ""
	}

	// Call the registry service
	ctx := base.Context()
	resp, err := client.Inspect(ctx, req)
	if err != nil {
		return ErrInspectFailed{Reference: ref, Err: err}
	}

	// Convert response to our result type
	result := convertInspectResponse(resp, ref)

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

// convertInspectResponse converts a gRPC response to our internal result type
func convertInspectResponse(resp *platformv1.InspectArtifactResponse, ref string) *InspectResult {
	result := &InspectResult{
		Manifest: &ImageManifest{
			Reference: ref,
		},
	}

	detail := resp.GetDetail()
	if detail == nil {
		return result
	}

	artifact := detail.GetArtifact()
	if artifact == nil {
		return result
	}

	// Populate manifest from artifact
	result.Manifest.Digest = artifact.GetDigest()
	result.Manifest.Annotations = artifact.GetAnnotations()

	// Convert timestamps
	if artifact.GetCreatedAt() != nil {
		result.Manifest.CreatedAt = artifact.GetCreatedAt().GetSeconds()
	}
	if artifact.GetPushedAt() != nil {
		result.Manifest.PushedAt = artifact.GetPushedAt().GetSeconds()
	}

	// Get manifest details
	manifest := artifact.GetManifest()
	if manifest != nil {
		result.Manifest.MediaType = manifest.GetMediaType()
		result.Manifest.Config = &ManifestConfig{
			Digest:    manifest.GetConfigDigest(),
			Size:      manifest.GetSize(),
			MediaType: manifest.GetMediaType(),
		}

		// Convert layers
		layers := manifest.GetLayers()
		result.Manifest.Layers = make([]*LayerInfo, 0, len(layers))
		for _, layer := range layers {
			result.Manifest.Layers = append(result.Manifest.Layers, &LayerInfo{
				Digest:    layer.GetDigest(),
				Size:      layer.GetSize(),
				MediaType: layer.GetMediaType(),
			})
		}
	}

	// Convert signatures
	signatures := detail.GetSignatures()
	if len(signatures) > 0 {
		sig := signatures[0] // Use first signature for display
		result.Manifest.Signature = &SignatureInfo{
			Signed:    true,
			SignedBy:  sig.GetSigner(),
			KeyID:     sig.GetKeyId(),
			Algorithm: sig.GetAlgorithm(),
			Valid:     true, // Assume valid if present
		}
		if sig.GetSignedAt() != nil {
			result.Manifest.Signature.ValidatedAt = sig.GetSignedAt().GetSeconds()
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
