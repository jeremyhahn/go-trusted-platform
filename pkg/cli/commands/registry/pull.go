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
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// PullResult represents the result of a pull operation
type PullResult struct {
	Reference string `json:"reference" yaml:"reference"`
	Digest    string `json:"digest" yaml:"digest"`
	Size      int64  `json:"size" yaml:"size"`
	Decrypted bool   `json:"decrypted" yaml:"decrypted"`
	Verified  bool   `json:"verified" yaml:"verified"`
	Platform  string `json:"platform,omitempty" yaml:"platform,omitempty"`
	Timestamp int64  `json:"timestamp" yaml:"timestamp"`
}

// NewPullCommand creates the pull subcommand
func NewPullCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var decrypt bool
	var verify bool
	var platform string
	var outputFile string

	cmd := &cobra.Command{
		Use:   "pull <image-reference>",
		Short: "Pull an image from the registry",
		Long: `Pull a container image from the Trusted Registry.

The image reference should be in the format:
  [registry/]repository[:tag|@digest]

Output:
  Use --output-file to specify a file to write to. If not specified, the
  image document is written to stdout and nothing else is.

Decryption:
  If the image is encrypted, use --decrypt to automatically decrypt
  the image layers during pull.

Verification:
  Use --verify to verify the image signature.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runPull(flags, args[0], decrypt, verify, platform, outputFile)
		},
	}

	cmd.Flags().BoolVarP(&decrypt, "decrypt", "d", false, "decrypt encrypted image layers")
	cmd.Flags().BoolVar(&verify, "verify", false, "verify image signature")
	cmd.Flags().StringVarP(&platform, "platform", "p", "", "target platform (e.g., linux/amd64)")
	// Not --output: that is the global output-format flag, and a local flag of
	// the same name would shadow it, so --output json would name a file.
	cmd.Flags().StringVar(&outputFile, "output-file", "", "output file path (writes to stdout if not provided)")

	return cmd
}

// runPull executes the pull command
func runPull(flags *cli.CommonFlags, ref string, decrypt, verify bool, platform, outputFile string) error {
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

	// Build the pull request using SDK helper
	pullReq := regsvc.NewPullRequest(repository, reference, "")
	if len(reference) > 7 && reference[:7] == "sha256:" {
		pullReq = regsvc.NewPullRequest(repository, "", reference)
	}

	// Create the streaming pull client
	ctx := base.Context()
	stream, err := regClient.Pull(ctx, pullReq)
	if err != nil {
		return ErrPullFailed{Reference: ref, Err: err}
	}

	// Open output destination
	var writer io.Writer
	var file *os.File
	if outputFile != "" {
		var fileErr error
		file, fileErr = os.Create(outputFile)
		if fileErr != nil {
			return ErrPullFailed{Reference: ref, Err: fileErr}
		}
		defer file.Close()
		writer = file
	} else {
		writer = os.Stdout
	}

	// Track metadata and size
	result := &PullResult{
		Reference: ref,
		Decrypted: decrypt,
		Verified:  verify,
		Platform:  platform,
	}
	var totalReceived int64

	// Receive the stream
	for {
		resp, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			return ErrPullFailed{Reference: ref, Err: recvErr}
		}

		// Handle metadata
		if metadata := resp.GetMetadata(); metadata != nil {
			if metadata.GetArtifact() != nil {
				result.Digest = metadata.GetArtifact().GetDigest()
				if metadata.GetArtifact().GetOs() != "" || metadata.GetArtifact().GetArchitecture() != "" {
					result.Platform = fmt.Sprintf("%s/%s",
						metadata.GetArtifact().GetOs(),
						metadata.GetArtifact().GetArchitecture())
				}
			}
			continue
		}

		// Handle data chunk
		if chunk := resp.GetChunk(); len(chunk) > 0 {
			n, writeErr := writer.Write(chunk)
			if writeErr != nil {
				return ErrPullFailed{Reference: ref, Err: writeErr}
			}
			totalReceived += int64(n)
		}
	}

	result.Size = totalReceived

	printer := base.Printer()

	// For table output, only print status info if writing to a file
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		if outputFile != "" {
			return printer.Print(result)
		}
		return nil

	case cli.OutputFormatTable:
		if outputFile != "" {
			printer.PrintSuccess(fmt.Sprintf("Image pulled successfully: %s", ref))
			fmt.Println()
			printer.PrintKeyValue("Reference", result.Reference)
			printer.PrintKeyValue("Digest", result.Digest)
			printer.PrintKeyValue("Size", formatBytes(result.Size))
			printer.PrintKeyValue("Decrypted", formatBool(result.Decrypted))
			printer.PrintKeyValue("Verified", formatBool(result.Verified))
			if result.Platform != "" {
				printer.PrintKeyValue("Platform", result.Platform)
			}
			printer.PrintKeyValue("Pulled At", formatTimestamp(result.Timestamp))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
