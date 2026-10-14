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

// newSealCommand creates the seal subcommand for sealing data to the TPM
func newSealCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		bundleID  string
		data      string
		pcrs      string
		authValue string
	)

	cmd := &cobra.Command{
		Use:   "seal",
		Short: "Seal data to the TPM",
		Long: `Seal (encrypt) data to the TPM, protected by its auth value.

PCR-bound sealing is unavailable: the daemon refuses a request with --pcrs
until go-quicbaas re-exports the TPM policy primitives (go-quicbaas #1171).
It never seals such a request as an object that ignores the PCRs.

The data should be provided as a base64-encoded string.

Examples:
  # Seal data with an auth value
  platformctl vtpm seal --bundle-id bundle-123 --data aGVsbG8= --auth-value mysecret

  # Seal and output as JSON
  platformctl vtpm seal --bundle-id bundle-123 --data aGVsbG8= --auth-value mysecret -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runSeal(flags, bundleID, data, pcrs, authValue)
		},
	}

	cmd.Flags().StringVar(&bundleID, "bundle-id", "", "bundle ID (required)")
	cmd.Flags().StringVar(&data, "data", "", "base64-encoded data to seal (required)")
	cmd.Flags().StringVar(&pcrs, "pcrs", "", "comma-separated list of PCR indices to bind to; refused until go-quicbaas #1171")
	cmd.Flags().StringVar(&authValue, "auth-value", "", "optional auth value for the sealed data")

	_ = cmd.MarkFlagRequired("bundle-id")
	_ = cmd.MarkFlagRequired("data")

	return cmd
}

// runSeal executes the seal command
func runSeal(flags *cli.CommonFlags, bundleID, data, pcrs, authValue string) error {
	if bundleID == "" {
		return ErrMissingRequiredFlag{Flag: "bundle-id"}
	}
	if data == "" {
		return ErrMissingRequiredFlag{Flag: "data"}
	}

	dataBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ErrInvalidBase64Data{Reason: err.Error()}
	}

	var pcrIndices []int32
	if pcrs != "" {
		pcrIndices, err = parsePCRIndices(pcrs)
		if err != nil {
			return err
		}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	ctx := base.Context()
	resp, err := sdkClient.SealDomain(ctx, bundleID, dataBytes, pcrIndices, authValue)
	if err != nil {
		return ErrSealVTPMFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("Bundle ID", resp.BundleID)
		printer.PrintKeyValue("Sealed Data", base64.StdEncoding.EncodeToString(resp.SealedData))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
