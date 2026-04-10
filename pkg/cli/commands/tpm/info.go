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
	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newInfoCommand creates the info subcommand for TPM information
func newInfoCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Get TPM device information",
		Long: `Display TPM 2.0 device information and capabilities.

Returns information about the TPM including:
  - TPM version
  - Manufacturer information
  - Firmware version
  - Supported algorithms
  - Available PCR banks
  - Maximum NVRAM size
  - FIPS mode status

Examples:
  # Get TPM info in table format
  platformctl tpm info

  # Get TPM info as JSON
  platformctl tpm info -o json

  # Get TPM info as YAML
  platformctl tpm info -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runInfo(flags)
		},
	}

	return cmd
}

// runInfo executes the info command
func runInfo(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runInfoWithClient(&tpmBaseCommandAdapter{base: base})
}

// runInfoWithClient runs info with a testable interface
func runInfoWithClient(base TPMBaseCommandInterface) error {
	defer base.Close()

	ctx := base.Context()
	resp, err := base.TPMClient().Info(ctx, &platformv1.TPMInfoRequest{})
	if err != nil {
		return ErrTPMInfoFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := buildTPMInfoOutput(resp)

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printTPMInfoDetails(printer, resp)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// buildTPMInfoOutput creates the structured output for JSON/YAML rendering.
//
// The authoritative TPM information is the comprehensive multi-line
// report composed by go-xkms TPM2.Info(), delivered in
// resp.Properties["info"]. We expose it as "info" alongside the two
// structured flags clients may want to branch on programmatically.
func buildTPMInfoOutput(resp *platformv1.TPMInfoResponse) map[string]interface{} {
	return map[string]interface{}{
		"info":         resp.GetProperties()["info"],
		"is_simulator": resp.IsSimulator,
	}
}

// printTPMInfoDetails prints the comprehensive xkms TPM info report in
// table (text) format by writing the verbatim multi-line string produced
// by go-xkms TPM2.Info(). We do not reformat or reinvent fields — the
// xkms library owns the presentation layer for TPM capabilities.
func printTPMInfoDetails(printer *cli.Printer, resp *platformv1.TPMInfoResponse) {
	if info := resp.GetProperties()["info"]; info != "" {
		printer.Println(info)
		return
	}
	// Fallback: server returned no info string (should not happen with
	// a wired TPM); surface the simulator flag so the user sees something.
	printer.PrintKeyValue("Simulator", formatBool(resp.IsSimulator))
}
