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
	"fmt"

	"github.com/spf13/cobra"

	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newUnsealCommand creates the unseal subcommand for unsealing data from the TPM
func newUnsealCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var cn, password, parentPassword string
	var parentHandle uint32
	var pcrIndices []int
	var pcrBank string

	cmd := &cobra.Command{
		Use:   "unseal",
		Short: "Unseal data from the TPM",
		Long: `Unseal data that was previously sealed to the TPM.

The unsealing operation will only succeed if the current PCR values
match those that were used during the sealing operation.

Examples:
  # Unseal a secret by common name
  platformctl tpm unseal --cn my-secret

  # Unseal with password
  platformctl tpm unseal --cn my-secret --password mypassword

  # Unseal and output raw data
  platformctl tpm unseal --cn my-secret -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			opts := &unsealOptions{
				CN:             cn,
				Password:       password,
				ParentHandle:   parentHandle,
				ParentPassword: parentPassword,
				PCRIndices:     intSliceToUint32(pcrIndices),
				PCRBank:        pcrBank,
			}
			return runUnseal(flags, opts)
		},
	}

	cmd.Flags().StringVar(&cn, "cn", "", "common name of the sealed object (required)")
	cmd.Flags().StringVar(&password, "password", "", "password for the sealed object")
	cmd.Flags().Uint32Var(&parentHandle, "parent", 0x81000001, "parent SRK handle")
	cmd.Flags().StringVar(&parentPassword, "parent-password", "", "parent key password")
	cmd.Flags().IntSliceVar(&pcrIndices, "pcrs", nil, "PCR indices (comma-separated)")
	cmd.Flags().StringVar(&pcrBank, "pcr-bank", "sha256", "PCR bank algorithm (sha1, sha256, sha384, sha512)")

	cli.MarkFlagsRequired(cmd, "cn")

	return cmd
}

// unsealOptions holds options for the unseal command
type unsealOptions struct {
	CN             string
	Password       string
	ParentHandle   uint32
	ParentPassword string
	PCRIndices     []uint32
	PCRBank        string
}

// runUnseal executes the unseal command
func runUnseal(flags *cli.CommonFlags, opts *unsealOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runUnsealWithClient(&tpmBaseCommandAdapter{base: base}, opts)
}

// runUnsealWithClient runs unseal with a testable interface
func runUnsealWithClient(base TPMBaseCommandInterface, opts *unsealOptions) error {
	defer base.Close()

	sdkClient := tpmsvc.NewClientFromGRPC(base.TPMClient())
	bank := tpmsvc.ParsePCRBank(opts.PCRBank)

	req := &tpmsvc.UnsealRequest{
		CN:             opts.CN,
		Password:       opts.Password,
		ParentHandle:   opts.ParentHandle,
		ParentPassword: opts.ParentPassword,
		PCRIndices:     opts.PCRIndices,
		PCRBank:        bank,
	}

	ctx := base.Context()
	resp, err := sdkClient.UnsealDomain(ctx, req)
	if err != nil {
		return ErrUnsealFailed{Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrUnsealFailed{Reason: msg}
	}

	printer := base.Printer()
	flags := base.Flags()

	// The same shape as seal's JSON: callers key on "success".
	output := map[string]interface{}{
		"success": resp.Status.Success,
		"cn":      opts.CN,
		"data":    string(resp.Data),
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		// For table format, just print the data directly
		fmt.Print(string(resp.Data))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
