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

// newSealCommand creates the seal subcommand for sealing data to the TPM
func newSealCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var cn, data, password, parentPassword string
	var parentHandle uint32
	var pcrIndices []int
	var pcrBank string
	var overwrite, usePolicy bool

	cmd := &cobra.Command{
		Use:   "seal",
		Short: "Seal data to the TPM",
		Long: `Seal data to the TPM as a keyed hash object.

The sealed data can only be unsealed when the TPM is in the same state
(PCR values match) as when the data was sealed.

Examples:
  # Seal a secret with a common name
  platformctl tpm seal --cn my-secret --data "secret data"

  # Seal with password protection
  platformctl tpm seal --cn my-secret --data "secret" --password mypassword

  # Seal with PCR policy (PCRs 0 and 7)
  platformctl tpm seal --cn my-secret --data "secret" --pcrs 0,7

  # Overwrite existing sealed data
  platformctl tpm seal --cn my-secret --data "new secret" --overwrite`,
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
				UsePolicy:      usePolicy,
			}
			return runSeal(flags, opts)
		},
	}

	cmd.Flags().StringVar(&cn, "cn", "", "common name for the sealed object (required)")
	cmd.Flags().StringVar(&data, "data", "", "data to seal")
	cmd.Flags().StringVar(&password, "password", "", "password for the sealed object")
	cmd.Flags().Uint32Var(&parentHandle, "parent", 0x81000001, "parent SRK handle")
	cmd.Flags().StringVar(&parentPassword, "parent-password", "", "parent key password")
	cmd.Flags().IntSliceVar(&pcrIndices, "pcrs", nil, "PCR indices to bind to (comma-separated)")
	cmd.Flags().StringVar(&pcrBank, "pcr-bank", "sha256", "PCR bank algorithm (sha1, sha256, sha384, sha512)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite existing sealed data")
	cmd.Flags().BoolVar(&usePolicy, "policy", true, "attach platform policy to the sealed object")

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
	UsePolicy      bool
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

	pcrBank := parsePCRBank(opts.PCRBank)

	req := &platformv1.SealRequest{
		Cn:             opts.CN,
		Data:           []byte(opts.Data),
		Password:       opts.Password,
		ParentHandle:   opts.ParentHandle,
		ParentPassword: opts.ParentPassword,
		PcrIndices:     opts.PCRIndices,
		PcrBank:        pcrBank,
		Overwrite:      opts.Overwrite,
	}

	ctx := base.Context()
	resp, err := base.TPMClient().Seal(ctx, req)
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

// parsePCRBank converts a string PCR bank name to the proto enum value
func parsePCRBank(bank string) platformv1.PCRBank {
	switch bank {
	case "sha1", "SHA1":
		return platformv1.PCRBank_PCR_BANK_SHA1
	case "sha256", "SHA256":
		return platformv1.PCRBank_PCR_BANK_SHA256
	case "sha384", "SHA384":
		return platformv1.PCRBank_PCR_BANK_SHA384
	case "sha512", "SHA512":
		return platformv1.PCRBank_PCR_BANK_SHA512
	case "sm3_256", "SM3_256":
		return platformv1.PCRBank_PCR_BANK_SM3_256
	default:
		return platformv1.PCRBank_PCR_BANK_SHA256
	}
}
