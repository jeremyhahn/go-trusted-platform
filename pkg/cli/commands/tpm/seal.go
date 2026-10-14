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

	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newSealCommand creates the seal subcommand for sealing data to the TPM
func newSealCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var cn, data, password, parentPassword string
	var parentHandle uint32
	var pcrIndices []int
	var pcrBank string
	var overwrite bool

	cmd := &cobra.Command{
		Use:   "seal",
		Short: "Seal data to the TPM",
		Long: `Seal data to the TPM as a keyed hash object, protected by its password.

PCR-bound sealing is unavailable: the daemon refuses a request with --pcrs
until go-quicbaas re-exports the TPM policy primitives (go-quicbaas #1171).
It never seals such a request as an object that ignores the PCRs.

Examples:
  # Seal with password protection
  platformctl tpm seal --cn my-secret --data "secret" --password mypassword

  # Overwrite existing sealed data
  platformctl tpm seal --cn my-secret --data "new secret" --password mypassword --overwrite`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			opts := &sealOptions{
				CN:             cn,
				Data:           data,
				Password:       password,
				ParentHandle:   parentHandle,
				ParentPassword: parentPassword,
				PCRIndices:     intSliceToUint32(pcrIndices),
				PCRBank:        pcrBank,
				Overwrite:      overwrite,
			}
			return runSeal(flags, opts)
		},
	}

	cmd.Flags().StringVar(&cn, "cn", "", "common name for the sealed object (required)")
	cmd.Flags().StringVar(&data, "data", "", "data to seal")
	cmd.Flags().StringVar(&password, "password", "", "password for the sealed object")
	cmd.Flags().Uint32Var(&parentHandle, "parent", 0x81000001, "parent SRK handle")
	cmd.Flags().StringVar(&parentPassword, "parent-password", "", "parent key password")
	cmd.Flags().IntSliceVar(&pcrIndices, "pcrs", nil, "PCR indices to bind to (comma-separated); refused until go-quicbaas #1171")
	cmd.Flags().StringVar(&pcrBank, "pcr-bank", "sha256", "PCR bank algorithm (sha1, sha256, sha384, sha512)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite existing sealed data")

	_ = cmd.MarkFlagRequired("cn")

	return cmd
}

// sealOptions holds options for the seal command
type sealOptions struct {
	CN             string
	Data           string
	Password       string
	ParentHandle   uint32
	ParentPassword string
	PCRIndices     []uint32
	PCRBank        string
	Overwrite      bool
}

// intSliceToUint32 converts []int to []uint32
func intSliceToUint32(in []int) []uint32 {
	if in == nil {
		return nil
	}
	out := make([]uint32, len(in))
	for i, v := range in {
		out[i] = uint32(v)
	}
	return out
}

// runSeal executes the seal command
func runSeal(flags *cli.CommonFlags, opts *sealOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runSealWithClient(&tpmBaseCommandAdapter{base: base}, opts)
}

// runSealWithClient runs seal with a testable interface
func runSealWithClient(base TPMBaseCommandInterface, opts *sealOptions) error {
	defer base.Close()

	sdkClient := tpmsvc.NewClientFromGRPC(base.TPMClient())
	bank := tpmsvc.ParsePCRBank(opts.PCRBank)

	req := &tpmsvc.SealRequest{
		CN:             opts.CN,
		Data:           []byte(opts.Data),
		Password:       opts.Password,
		ParentHandle:   opts.ParentHandle,
		ParentPassword: opts.ParentPassword,
		PCRIndices:     opts.PCRIndices,
		PCRBank:        bank,
		Overwrite:      opts.Overwrite,
	}

	ctx := base.Context()
	resp, err := sdkClient.SealDomain(ctx, req)
	if err != nil {
		return ErrSealFailed{Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrSealFailed{Reason: msg}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"success": resp.Status.Success,
		"cn":      opts.CN,
		"message": resp.Status.Message,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("Data sealed successfully")
		printer.PrintKeyValue("Common Name", opts.CN)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
