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
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
)

// newIsRunningCommand creates the is-running subcommand for checking vTPM status
func newIsRunningCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var bundleID string

	cmd := &cobra.Command{
		Use:   "is-running",
		Short: "Check if the vTPM daemon is running for a bundle",
		Long: `Check if the swtpm (software TPM) daemon is currently running
for a vTPM bundle.

Returns the running status of the vTPM daemon.

Examples:
  # Check if vTPM is running
  platformctl vtpm is-running --bundle-id bundle-123

  # Check status and output as JSON
  platformctl vtpm is-running --bundle-id bundle-123 -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runIsRunning(flags, bundleID)
		},
	}

	cmd.Flags().StringVar(&bundleID, "bundle-id", "", "bundle ID (required)")
	cli.MarkFlagsRequired(cmd, "bundle-id")

	return cmd
}

// runIsRunning executes the is-running command
func runIsRunning(flags *cli.CommonFlags, bundleID string) error {
	if bundleID == "" {
		return ErrMissingRequiredFlag{Flag: "bundle-id"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{Err: err}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	ctx := base.Context()
	resp, err := sdkClient.IsRunningDomain(ctx, bundleID)
	if err != nil {
		return ErrIsRunningFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("Bundle ID", resp.BundleID)
		printer.PrintKeyValue("Running", formatBool(resp.Running))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// formatRunningStatus returns a human-readable running status string
func formatRunningStatus(running bool) string {
	if running {
		return "running"
	}
	return "stopped"
}
