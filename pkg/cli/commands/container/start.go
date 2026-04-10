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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newStartCommand creates the container start subcommand
func newStartCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start <container-id>",
		Short: "Start a container",
		Long: `Start a stopped or created container.

The container must exist and be in a stopped or created state.

Examples:
  # Start a container by name
  platformctl container start myapp

  # Start a container by ID
  platformctl container start abc123def456

  # Start container with JSON output
  platformctl container start myapp --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runStart(flags, args[0])
		},
	}

	return cmd
}

// runStart executes the container start command
func runStart(flags *cli.CommonFlags, containerID string) error {
	if containerID == "" {
		return ErrInvalidContainerConfig{Field: "id", Reason: "container ID is required"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := base.Client().Compute()
	if client == nil {
		return ErrContainerClientNotInitialized{}
	}

	req := &platformv1.StartContainerRequest{
		Id: containerID,
	}

	ctx := base.Context()
	resp, err := client.StartContainer(ctx, req)
	if err != nil {
		return ErrContainerOperationFailed{Operation: "start", ID: containerID, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess(fmt.Sprintf("Container started successfully: %s", containerID))
		} else if resp.Status != nil {
			printer.PrintError(fmt.Sprintf("Failed to start container: %s", resp.Status.Message))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
