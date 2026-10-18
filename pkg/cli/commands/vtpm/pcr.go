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
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
)

// newPCRCommand creates the pcr subcommand group for PCR operations
func newPCRCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pcr",
		Short: "PCR (Platform Configuration Register) operations",
		Long: `Manage PCR (Platform Configuration Register) values for a vTPM bundle.

PCRs are fixed-size registers in the TPM that record measurements.
They can only be extended (not directly written) and are used for
platform integrity attestation.

Examples:
  # Extend a PCR with data
  platformctl vtpm pcr extend --bundle-id bundle-123 --pcr-index 7 --data deadbeef

  # Read a PCR value
  platformctl vtpm pcr read --bundle-id bundle-123 --pcr-index 7`,
	}

	cmd.AddCommand(newPCRExtendCommand(getFlags))
	cmd.AddCommand(newPCRReadCommand(getFlags))

	return cmd
}

// newPCRExtendCommand creates the pcr extend subcommand
func newPCRExtendCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		bundleID string
		pcrIndex int32
		data     string
	)

	cmd := &cobra.Command{
		Use:   "extend",
		Short: "Extend a PCR with data",
		Long: `Extend a PCR (Platform Configuration Register) with the provided data.

PCR extension is a one-way operation: the new PCR value is computed as
hash(old_value || new_data). This ensures a tamper-evident log of all
measurements extended into the PCR.

The data should be provided as a hex-encoded string.

Examples:
  # Extend PCR 7 with data
  platformctl vtpm pcr extend --bundle-id bundle-123 --pcr-index 7 --data deadbeef

  # Extend and output as JSON
  platformctl vtpm pcr extend --bundle-id bundle-123 --pcr-index 0 --data abc123 -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runPCRExtend(flags, bundleID, pcrIndex, data)
		},
	}

	cmd.Flags().StringVar(&bundleID, "bundle-id", "", "bundle ID (required)")
	cmd.Flags().Int32Var(&pcrIndex, "pcr-index", -1, "PCR index to extend (0-23, required)")
	cmd.Flags().StringVar(&data, "data", "", "hex-encoded data to extend into the PCR (required)")

	cli.MarkFlagsRequired(cmd, "bundle-id")
	cli.MarkFlagsRequired(cmd, "pcr-index")
	cli.MarkFlagsRequired(cmd, "data")

	return cmd
}

// runPCRExtend executes the pcr extend command
func runPCRExtend(flags *cli.CommonFlags, bundleID string, pcrIndex int32, data string) error {
	if bundleID == "" {
		return ErrMissingRequiredFlag{Flag: "bundle-id"}
	}
	if pcrIndex < 0 || pcrIndex > 23 {
		return ErrInvalidPCRIndex{Index: fmt.Sprintf("%d", pcrIndex), Reason: "PCR index must be between 0 and 23"}
	}
	if data == "" {
		return ErrMissingRequiredFlag{Flag: "data"}
	}

	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		return ErrInvalidHexData{Reason: err.Error()}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	ctx := base.Context()
	resp, err := sdkClient.ExtendPCRDomain(ctx, bundleID, int32(pcrIndex), dataBytes)
	if err != nil {
		return ErrExtendPCRFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Extended {
			printer.PrintSuccess(fmt.Sprintf("PCR[%d] extended for bundle: %s", resp.PCRIndex, resp.BundleID))
		} else {
			printer.PrintError(fmt.Sprintf("Failed to extend PCR[%d] for bundle: %s", pcrIndex, bundleID))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// newPCRReadCommand creates the pcr read subcommand
func newPCRReadCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		bundleID string
		pcrIndex int32
	)

	cmd := &cobra.Command{
		Use:   "read",
		Short: "Read a PCR value",
		Long: `Read the current value of a PCR (Platform Configuration Register).

Returns the current hash value stored in the specified PCR.

Examples:
  # Read PCR 7
  platformctl vtpm pcr read --bundle-id bundle-123 --pcr-index 7

  # Read PCR 0 and output as JSON
  platformctl vtpm pcr read --bundle-id bundle-123 --pcr-index 0 -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runPCRRead(flags, bundleID, pcrIndex)
		},
	}

	cmd.Flags().StringVar(&bundleID, "bundle-id", "", "bundle ID (required)")
	cmd.Flags().Int32Var(&pcrIndex, "pcr-index", -1, "PCR index to read (0-23, required)")

	cli.MarkFlagsRequired(cmd, "bundle-id")
	cli.MarkFlagsRequired(cmd, "pcr-index")

	return cmd
}

// runPCRRead executes the pcr read command
func runPCRRead(flags *cli.CommonFlags, bundleID string, pcrIndex int32) error {
	if bundleID == "" {
		return ErrMissingRequiredFlag{Flag: "bundle-id"}
	}
	if pcrIndex < 0 || pcrIndex > 23 {
		return ErrInvalidPCRIndex{Index: fmt.Sprintf("%d", pcrIndex), Reason: "PCR index must be between 0 and 23"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	ctx := base.Context()
	resp, err := sdkClient.ReadPCRDomain(ctx, bundleID, int32(pcrIndex))
	if err != nil {
		return ErrReadPCRFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("Bundle ID", resp.BundleID)
		printer.PrintKeyValue(fmt.Sprintf("PCR[%d]", resp.PCRIndex), hex.EncodeToString(resp.Value))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
