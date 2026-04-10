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

package vtpm

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newDeleteCommand creates the delete subcommand for deleting bundles
func newDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "delete [bundle-id]",
		Short: "Delete a vTPM bundle",
		Long: `Delete a vTPM bundle and all associated files.

This operation is irreversible. Use --force to skip the confirmation prompt.

WARNING: Once deleted, the bundle cannot be recovered. Any VMs using this
bundle will lose their TPM identity.

Examples:
  # Delete a bundle (with confirmation)
  platformctl vtpm delete bundle-123

  # Delete a bundle without confirmation
  platformctl vtpm delete bundle-123 --force`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runDelete(flags, args[0], force)
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "skip confirmation prompt")

	return cmd
}

// runDelete executes the delete command
func runDelete(flags *cli.CommonFlags, bundleID string, force bool) error {
	// Validate bundle ID is provided
	if bundleID == "" {
		return ErrMissingRequiredFlag{Flag: "bundle-id"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	client := base.Client().VTPM()
	if client == nil {
		return ErrVTPMNotAvailable{}
	}

	printer := base.Printer()

	// Confirm deletion if not forced
	if !force {
		printer.PrintWarning(fmt.Sprintf("This will permanently delete bundle '%s' and all associated files.", bundleID))
		fmt.Print("Are you sure you want to proceed? [y/N]: ")

		reader := bufio.NewReader(os.Stdin)
		response, readErr := reader.ReadString('\n')
		if readErr != nil {
			return readErr
		}

		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			printer.PrintInfo("Operation cancelled")
			return nil
		}
	}

	req := &platformv1.DeleteBundleRequest{
		Id: bundleID,
	}

	ctx := base.Context()
	resp, err := client.DeleteBundle(ctx, req)
	if err != nil {
		return ErrDeleteBundleFailed{Reason: err.Error()}
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess(fmt.Sprintf("Bundle '%s' deleted successfully", bundleID))
		} else {
			msg := "unknown error"
			if resp.Status != nil && resp.Status.Message != "" {
				msg = resp.Status.Message
			}
			printer.PrintError(fmt.Sprintf("Failed to delete bundle: %s", msg))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
