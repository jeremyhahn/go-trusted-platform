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
	"encoding/base64"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
)

// newUnsealCommand creates the unseal subcommand for unsealing data from the TPM
func newUnsealCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		bundleID   string
		sealedData string
		authValue  string
	)

	cmd := &cobra.Command{
		Use:   "unseal",
		Short: "Unseal data from the TPM",
		Long: `Unseal (decrypt) data that was previously sealed to the TPM.

If the data was sealed with PCR binding, the current PCR values must match
the values at the time of sealing for the unseal operation to succeed.

The sealed data should be provided as a base64-encoded string.

Examples:
  # Unseal data from the TPM
  platformctl vtpm unseal --bundle-id bundle-123 --sealed-data <base64>

  # Unseal data with an auth value
  platformctl vtpm unseal --bundle-id bundle-123 --sealed-data <base64> --auth-value mysecret

  # Unseal and output as JSON
  platformctl vtpm unseal --bundle-id bundle-123 --sealed-data <base64> -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runUnseal(flags, bundleID, sealedData, authValue)
		},
	}

	cmd.Flags().StringVar(&bundleID, "bundle-id", "", "bundle ID (required)")
	cmd.Flags().StringVar(&sealedData, "sealed-data", "", "base64-encoded sealed data (required)")
	cmd.Flags().StringVar(&authValue, "auth-value", "", "auth value used during sealing")

	cli.MarkFlagsRequired(cmd, "bundle-id")
	cli.MarkFlagsRequired(cmd, "sealed-data")

	return cmd
}

// runUnseal executes the unseal command
func runUnseal(flags *cli.CommonFlags, bundleID, sealedData, authValue string) error {
	if bundleID == "" {
		return ErrMissingRequiredFlag{Flag: "bundle-id"}
	}
	if sealedData == "" {
		return ErrMissingRequiredFlag{Flag: "sealed-data"}
	}

	sealedBytes, err := base64.StdEncoding.DecodeString(sealedData)
	if err != nil {
		return ErrInvalidBase64Data{Reason: err.Error()}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	ctx := base.Context()
	resp, err := sdkClient.UnsealDomain(ctx, bundleID, sealedBytes, authValue)
	if err != nil {
		return ErrUnsealVTPMFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("Bundle ID", resp.BundleID)
		printer.PrintKeyValue("Data", base64.StdEncoding.EncodeToString(resp.Data))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
