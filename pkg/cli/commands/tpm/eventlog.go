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

package tpm

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newEventlogCommand creates the eventlog subcommand for event log operations
func newEventlogCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "eventlog",
		Short: "Get TPM event log",
		Long: `Retrieve and display the TPM event log (binary_bios_measurements).

The event log contains a record of all measurements that have been
extended into the PCRs. This is essential for remote attestation
to understand the platform's boot history.

Available formats:
  - json: JSON formatted output
  - text: Human-readable text format
  - binary: Raw binary data

Examples:
  # Get event log in text format
  platformctl tpm eventlog

  # Get event log as JSON
  platformctl tpm eventlog --format json

  # Get event log as JSON output
  platformctl tpm eventlog -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runEventlog(flags, format)
		},
	}

	cmd.Flags().StringVar(&format, "format", "text", "output format: json, text, binary")

	return cmd
}

// runEventlog executes the eventlog command
func runEventlog(flags *cli.CommonFlags, format string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runEventlogWithClient(&tpmBaseCommandAdapter{base: base}, format)
}

// runEventlogWithClient runs eventlog with a testable interface
func runEventlogWithClient(base TPMBaseCommandInterface, format string) error {
	defer base.Close()

	sdkClient := tpmsvc.NewClientFromGRPC(base.TPMClient())

	ctx := base.Context()
	resp, err := sdkClient.GetEventLogDomain(ctx, format)
	if err != nil {
		return ErrEventLogFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"format":      resp.Format,
		"event_count": resp.EventCount,
	}

	if format == "binary" {
		output["event_log"] = hex.EncodeToString(resp.EventLog)
	} else {
		output["event_log"] = string(resp.EventLog)
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("Format", resp.Format)
		printer.PrintKeyValue("Event Count", fmt.Sprintf("%d", resp.EventCount))
		fmt.Println()
		if format == "binary" {
			fmt.Println(hex.EncodeToString(resp.EventLog))
		} else {
			fmt.Print(string(resp.EventLog))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
