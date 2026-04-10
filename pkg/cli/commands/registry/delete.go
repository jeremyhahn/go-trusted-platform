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
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// DeleteResult represents the result of a delete operation
type DeleteResult struct {
	Reference  string `json:"reference" yaml:"reference"`
	Digest     string `json:"digest" yaml:"digest"`
	Deleted    bool   `json:"deleted" yaml:"deleted"`
	Message    string `json:"message,omitempty" yaml:"message,omitempty"`
	BytesFreed int64  `json:"bytes_freed,omitempty" yaml:"bytes_freed,omitempty"`
	Timestamp  int64  `json:"timestamp" yaml:"timestamp"`
}

// NewDeleteCommand creates the delete subcommand
func NewDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var force bool
	var dryRun bool
	var keepUntagged bool

	cmd := &cobra.Command{
		Use:     "delete <image-reference>",
		Aliases: []string{"rm", "remove"},
		Short:   "Delete an image from the registry",
		Long: `Delete a container image from the Trusted Registry.

The image reference should be in the format:
  [registry/]repository[:tag|@digest]

Examples:
  repository/image:tag
  myrepo/myimage:v1.0
  myrepo/myimage@sha256:abc123...

When deleting, TPM attestation is automatically generated to prove the
integrity of the host. If the registry requires attestation, the delete
will fail if the host cannot be verified.

Confirmation:
  By default, the command will prompt for confirmation before deleting.
  Use --force to skip the confirmation prompt.

Dry Run:
  Use --dry-run to see what would be deleted without actually deleting.

Keep Untagged:
  Use --keep-untagged to preserve untagged manifests when deleting a tag.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runDelete(flags, args[0], force, dryRun, keepUntagged)
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "skip confirmation prompt")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be deleted without deleting")
	cmd.Flags().BoolVar(&keepUntagged, "keep-untagged", false, "preserve untagged manifests when deleting a tag")

	return cmd
}

// runDelete executes the delete command
func runDelete(flags *cli.CommonFlags, ref string, force, dryRun, keepUntagged bool) error {
	// Validate image reference
	if err := validateImageRef(ref); err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	printer := base.Printer()

	// Prompt for confirmation if not forced
	if !force && !dryRun {
		confirmed, confirmErr := promptConfirmation(ref)
		if confirmErr != nil {
			return ErrDeleteFailed{Reference: ref, Err: confirmErr}
		}
		if !confirmed {
			printer.PrintInfo("Delete operation cancelled")
			return nil
		}
	}

	// Handle dry run
	if dryRun {
		result := &DeleteResult{
			Reference: ref,
			Digest:    "sha256:pending",
			Deleted:   false,
			Message:   "dry run - no changes made",
			Timestamp: 0,
		}
		return printDeleteResult(flags, printer, result, true)
	}

	client := base.Client().Registry()
	if client == nil {
		return ErrRegistryClientNotInitialized{}
	}

	// Parse reference to get repository and tag/digest
	repository, reference := parseImageRef(ref)

	// Build the request
	req := &platformv1.DeleteArtifactRequest{
		Repository: repository,
		Reference:  reference,
		Force:      force,
	}

	// If reference looks like a digest, set it in the digest field instead
	if len(reference) > 7 && reference[:7] == "sha256:" {
		req.Digest = reference
		req.Reference = ""
	}

	// Call the registry service
	ctx := base.Context()
	resp, err := client.Delete(ctx, req)
	if err != nil {
		return ErrDeleteFailed{Reference: ref, Err: err}
	}

	// Convert response to our result type
	result := &DeleteResult{
		Reference:  ref,
		Digest:     resp.GetDigest(),
		Deleted:    resp.GetStatus() == nil || resp.GetStatus().GetSuccess(),
		BytesFreed: resp.GetBytesFreed(),
	}

	if resp.GetStatus() != nil && !resp.GetStatus().GetSuccess() {
		result.Message = resp.GetStatus().GetMessage()
	}

	if resp.GetTimestamp() != nil {
		result.Timestamp = resp.GetTimestamp().GetSeconds()
	}

	return printDeleteResult(flags, printer, result, false)
}

// printDeleteResult outputs the delete result in the appropriate format
func printDeleteResult(flags *cli.CommonFlags, printer *cli.Printer, result *DeleteResult, dryRun bool) error {
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if dryRun {
			printer.PrintWarning(fmt.Sprintf("Would delete: %s", result.Reference))
		} else if result.Deleted {
			printer.PrintSuccess(fmt.Sprintf("Image deleted successfully: %s", result.Reference))
		} else {
			printer.PrintError(fmt.Sprintf("Failed to delete image: %s", result.Reference))
			if result.Message != "" {
				printer.PrintInfo(result.Message)
			}
		}
		fmt.Println()
		printer.PrintKeyValue("Reference", result.Reference)
		printer.PrintKeyValue("Digest", result.Digest)
		printer.PrintKeyValue("Deleted", formatBool(result.Deleted))
		if result.BytesFreed > 0 {
			printer.PrintKeyValue("Space Freed", formatBytes(result.BytesFreed))
		}
		if result.Message != "" {
			printer.PrintKeyValue("Message", result.Message)
		}
		if !dryRun && result.Deleted {
			printer.PrintKeyValue("Deleted At", formatTimestamp(result.Timestamp))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// promptConfirmation asks the user to confirm the delete operation
func promptConfirmation(ref string) (bool, error) {
	fmt.Printf("Are you sure you want to delete image %q? [y/N]: ", ref)

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes", nil
}
