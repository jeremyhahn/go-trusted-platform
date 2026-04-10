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

// stopOptions holds the options for the stop command
type stopOptions struct {
	timeout uint32
}

// newStopCommand creates the container stop subcommand
func newStopCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &stopOptions{}

	cmd := &cobra.Command{
		Use:   "stop <container-id>",
		Short: "Stop a running container",
		Long: `Stop a running container gracefully.

The container receives a SIGTERM signal and is given time to shut down
gracefully. If the container does not stop within the timeout period,
it will be forcefully terminated.

Examples:
  # Stop a container with default timeout
  platformctl container stop myapp

  # Stop a container with custom timeout (30 seconds)
  platformctl container stop myapp --timeout 30

  # Stop container with JSON output
  platformctl container stop myapp --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runStop(flags, args[0], opts)
		},
	}

	cmd.Flags().Uint32VarP(&opts.timeout, "timeout", "t", 10, "seconds to wait before forcing stop")

	return cmd
}

// runStop executes the container stop command
func runStop(flags *cli.CommonFlags, containerID string, opts *stopOptions) error {
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

	req := &platformv1.StopContainerRequest{
		Id:             containerID,
		TimeoutSeconds: opts.timeout,
	}

	ctx := base.Context()
	resp, err := client.StopContainer(ctx, req)
	if err != nil {
		return ErrContainerOperationFailed{Operation: "stop", ID: containerID, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess(fmt.Sprintf("Container stopped successfully: %s", containerID))
		} else if resp.Status != nil {
			printer.PrintError(fmt.Sprintf("Failed to stop container: %s", resp.Status.Message))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
