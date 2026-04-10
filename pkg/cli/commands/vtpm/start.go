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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newStartCommand creates the start subcommand for starting a vTPM daemon
func newStartCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var bundleID string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the swtpm daemon for a bundle",
		Long: `Start the swtpm (software TPM) daemon for a vTPM bundle.

The swtpm daemon must be running for runtime TPM operations such as
quoting, sealing, unsealing, and PCR operations.

Examples:
  # Start the vTPM for a bundle
  platformctl vtpm start --bundle-id bundle-123

  # Start and output as JSON
  platformctl vtpm start --bundle-id bundle-123 -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runStart(flags, bundleID)
		},
	}

	cmd.Flags().StringVar(&bundleID, "bundle-id", "", "bundle ID (required)")
	_ = cmd.MarkFlagRequired("bundle-id")

	return cmd
}

// runStart executes the start command
func runStart(flags *cli.CommonFlags, bundleID string) error {
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

	req := &platformv1.StartVTPMRequest{
		BundleId: bundleID,
	}

	ctx := base.Context()
	resp, err := client.StartVTPM(ctx, req)
	if err != nil {
		return ErrStartVTPMFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Running {
			printer.PrintSuccess(fmt.Sprintf("vTPM started for bundle: %s", resp.BundleId))
			if resp.SocketPath != "" {
				printer.PrintKeyValue("Socket Path", resp.SocketPath)
			}
		} else {
			printer.PrintError(fmt.Sprintf("Failed to start vTPM for bundle: %s", bundleID))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
