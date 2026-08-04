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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
)

// newStopCommand creates the stop subcommand for stopping a vTPM daemon
func newStopCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var bundleID string

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the swtpm daemon for a bundle",
		Long: `Stop the swtpm (software TPM) daemon for a vTPM bundle.

Stopping the daemon terminates all active TPM sessions. Any in-progress
operations will be interrupted.

Examples:
  # Stop the vTPM for a bundle
  platformctl vtpm stop --bundle-id bundle-123

  # Stop and output as JSON
  platformctl vtpm stop --bundle-id bundle-123 -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runStop(flags, bundleID)
		},
	}

	cmd.Flags().StringVar(&bundleID, "bundle-id", "", "bundle ID (required)")
	_ = cmd.MarkFlagRequired("bundle-id")

	return cmd
}

// runStop executes the stop command
func runStop(flags *cli.CommonFlags, bundleID string) error {
	if bundleID == "" {
		return ErrMissingRequiredFlag{Flag: "bundle-id"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	ctx := base.Context()
	resp, err := sdkClient.StopDomain(ctx, bundleID)
	if err != nil {
		return ErrStopVTPMFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Stopped {
			printer.PrintSuccess(fmt.Sprintf("vTPM stopped for bundle: %s", resp.BundleID))
		} else {
			printer.PrintError(fmt.Sprintf("Failed to stop vTPM for bundle: %s", bundleID))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
