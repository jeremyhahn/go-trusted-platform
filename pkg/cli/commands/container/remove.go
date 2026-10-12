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

package container

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// removeOptions holds the options for the remove command
type removeOptions struct {
	force         bool
	deleteVolumes bool
}

// newRemoveCommand creates the container remove subcommand
func newRemoveCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &removeOptions{}

	cmd := &cobra.Command{
		Use:     "remove <container-id>",
		Aliases: []string{"rm", "delete"},
		Short:   "Remove a container",
		Long: `Remove a container from the system.

By default, only stopped containers can be removed. Use --force to
remove a running container (it will be stopped first).

Examples:
  # Remove a stopped container
  platformctl container remove myapp

  # Force remove a running container
  platformctl container remove myapp --force

  # Remove container and its volumes
  platformctl container remove myapp --volumes

  # Remove container with JSON output
  platformctl container remove myapp --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRemove(flags, args[0], opts)
		},
	}

	cmd.Flags().BoolVarP(&opts.force, "force", "f", false, "force remove running container")
	cmd.Flags().BoolVar(&opts.deleteVolumes, "volumes", false, "remove associated volumes")

	return cmd
}

// runRemove executes the container remove command
func runRemove(flags *cli.CommonFlags, containerID string, opts *removeOptions) error {
	if containerID == "" {
		return ErrInvalidContainerConfig{Field: "id", Reason: "container ID is required"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	grpcClient := base.Client().Compute()
	if grpcClient == nil {
		return ErrContainerClientNotInitialized{}
	}

	sdkClient := computesvc.NewClientFromGRPC(grpcClient)

	ctx := base.Context()
	status, err := sdkClient.DeleteContainerDomain(ctx, &computesvc.DeleteContainerParams{
		ID:            containerID,
		Force:         opts.force,
		DeleteVolumes: opts.deleteVolumes,
	})
	if err != nil {
		return ErrContainerOperationFailed{Operation: "remove", ID: containerID, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		if status != nil && status.Success {
			printer.PrintSuccess(fmt.Sprintf("Container removed successfully: %s", containerID))
		} else if status != nil {
			printer.PrintError(fmt.Sprintf("Failed to remove container: %s", status.Message))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
