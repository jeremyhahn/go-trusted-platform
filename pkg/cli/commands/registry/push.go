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
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// PushResult represents the result of a push operation
type PushResult struct {
	Reference string `json:"reference" yaml:"reference"`
	Digest    string `json:"digest" yaml:"digest"`
	Size      int64  `json:"size" yaml:"size"`
	Encrypted bool   `json:"encrypted" yaml:"encrypted"`
	KeyID     string `json:"key_id,omitempty" yaml:"key_id,omitempty"`
	Signed    bool   `json:"signed" yaml:"signed"`
	Timestamp int64  `json:"timestamp" yaml:"timestamp"`
}

// defaultChunkSize is the default size for streaming chunks (64KB)
const defaultChunkSize = 64 * 1024

// NewPushCommand creates the push subcommand
func NewPushCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var encrypt bool
	var keyID string
	var sign bool
	var signingKeyID string
	var overwrite bool
	var inputFile string

	cmd := &cobra.Command{
		Use:   "push <image-reference>",
		Short: "Push an image to the registry",
		Long: `Push a container image to the Trusted Registry.

The image reference should be in the format:
  [registry/]repository[:tag|@digest]

Input:
  Use --input to specify a file to push. If not specified, reads from stdin.

Encryption:
  Use --encrypt to encrypt the image layers before storage. You must
  provide a --key-id that references a key managed by the KMS.

Signing:
  Use --sign to sign the image manifest. Combine with --signing-key-id
  to select an explicit signing key (defaults to the tenant signer).

Overwrite:
  Use --overwrite to replace an existing tag of the same name.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runPush(flags, args[0], encrypt, keyID, sign, signingKeyID, overwrite, inputFile)
		},
	}

	cmd.Flags().BoolVarP(&encrypt, "encrypt", "e", false, "encrypt image layers before storage")
	cmd.Flags().StringVarP(&keyID, "key-id", "k", "", "encryption key ID (required with --encrypt)")
	cmd.Flags().BoolVarP(&sign, "sign", "s", false, "sign the image manifest")
	cmd.Flags().StringVar(&signingKeyID, "signing-key-id", "", "key ID to use for manifest signing (defaults to tenant signer)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "replace an existing tag with the same name")
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file path (reads from stdin if not provided)")

	return cmd
}

// runPush executes the push command. signingKeyID overrides the default
// tenant signer when sign=true; overwrite=true replaces an existing tag.
func runPush(flags *cli.CommonFlags, ref string, encrypt bool, keyID string, sign bool, signingKeyID string, overwrite bool, inputFile string) error {
	if err := validateImageRef(ref); err != nil {
		return err
	}

	if encrypt && keyID == "" {
		return ErrEncryptionKeyRequired{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	regClient := regsvc.NewClientFromGRPC(base.Client().Registry())

	repository, tag := parseImageRef(ref)

	// Open input source
	var reader io.Reader
	var fileSize int64
	if inputFile != "" {
		file, fileErr := os.Open(inputFile)
		if fileErr != nil {
			return ErrPushFailed{Reference: ref, Err: fileErr}
		}
		defer file.Close()

		stat, statErr := file.Stat()
		if statErr != nil {
			return ErrPushFailed{Reference: ref, Err: statErr}
		}
		fileSize = stat.Size()
		reader = file
	} else {
		reader = os.Stdin
	}

	// Create the streaming push client using SDK helpers
	ctx := base.Context()
	stream, err := regClient.Push(ctx)
	if err != nil {
		return ErrPushFailed{Reference: ref, Err: err}
	}

	// Send metadata first using SDK helpers
	metadata := pushMetadataOf(repository, tag, fileSize, encrypt, keyID, sign, signingKeyID, overwrite)
	metadataReq := regsvc.NewPushMetadataRequest(metadata)
	if err := stream.Send(metadataReq); err != nil {
		return ErrPushFailed{Reference: ref, Err: err}
	}

	// Stream the data in chunks
	buffer := make([]byte, defaultChunkSize)
	var totalSent int64
	for {
		n, readErr := reader.Read(buffer)
		if readErr != nil && readErr != io.EOF {
			return ErrPushFailed{Reference: ref, Err: readErr}
		}

		if n > 0 {
			chunkReq := regsvc.NewPushChunkRequest(buffer[:n])
			if sendErr := stream.Send(chunkReq); sendErr != nil {
				return ErrPushFailed{Reference: ref, Err: sendErr}
			}
			totalSent += int64(n)
		}

		if readErr == io.EOF {
			break
		}
	}

	// Close and receive the response
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return ErrPushFailed{Reference: ref, Err: err}
	}

	// Check for error status
	if resp.GetStatus() != nil && !resp.GetStatus().GetSuccess() {
		return ErrPushFailed{Reference: ref, Err: &MessageError{Msg: resp.GetStatus().GetMessage()}}
	}

	// Build result from response
	// Encrypted and Key ID come from the manifest the registry stored, so
	// the result reports what the registry did, not what was asked.
	stored := resp.GetArtifact().GetAnnotations()
	result := &PushResult{
		Reference: ref,
		Digest:    resp.GetArtifact().GetDigest(),
		Size:      resp.GetBytesReceived(),
		Encrypted: stored[regsvc.ManifestAnnotationEncrypted] == "true",
		KeyID:     stored[regsvc.ManifestAnnotationKeyID],
		// The registry refuses a --sign push it cannot sign
		// (ErrSigningNotConfigured), so a push that got here was signed
		// exactly when it asked to be.
		Signed: sign,
	}

	if resp.GetTimestamp() != nil {
		result.Timestamp = resp.GetTimestamp().GetSeconds()
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Image pushed successfully: %s", ref))
		fmt.Println()
		printer.PrintKeyValue("Reference", result.Reference)
		printer.PrintKeyValue("Digest", result.Digest)
		printer.PrintKeyValue("Size", formatBytes(result.Size))
		printer.PrintKeyValue("Encrypted", formatBool(result.Encrypted))
		if result.KeyID != "" {
			printer.PrintKeyValue("Key ID", result.KeyID)
		}
		printer.PrintKeyValue("Signed", formatBool(result.Signed))
		printer.PrintKeyValue("Pushed At", formatTimestamp(result.Timestamp))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// pushMetadataOf builds the push metadata, carrying each push flag to the
// registry as the annotation docs/registry/cli.md §3 names for it.
func pushMetadataOf(repository, tag string, size int64, encrypt bool, keyID string, sign bool, signingKeyID string, overwrite bool) *platformv1.PushMetadata {
	metadata := regsvc.NewPushMetadata(repository, tag, size)
	if encrypt {
		metadata = regsvc.WithEncryption(metadata, keyID)
	}
	if sign {
		metadata = regsvc.WithSigning(metadata, signingKeyID)
	}
	if overwrite {
		metadata = regsvc.WithOverwrite(metadata)
	}
	return metadata
}
