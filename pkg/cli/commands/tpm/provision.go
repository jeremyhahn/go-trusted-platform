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

// newProvisionCommand creates the provision subcommand for TPM provisioning
func newProvisionCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var createEK, createSRK, createAK bool
	var ownerPassword, endorsementPassword string

	cmd := &cobra.Command{
		Use:   "provision",
		Short: "Provision the TPM with required keys",
		Long: `Initializes the platform by establishing an initial Security Officer
whose credentials are used to take ownership of the TPM and key stores.

The TPM is provisioned per TCG recommended guidance, with an EK and SRK persisted
to their recommended storage hierarchy handle indexes. Key stores, services and
components referenced in the platform configuration file are initialized.

This command:
  - Creates the Endorsement Key (EK) if requested
  - Creates the Storage Root Key (SRK) if requested
  - Creates the Attestation Key (AK) if requested
  - Sets up hierarchy authorizations

Examples:
  # Provision with default settings (creates EK, SRK, and AK)
  platformctl tpm provision --create-ek --create-srk --create-ak

  # Provision with owner password
  platformctl tpm provision --owner-password mypassword

  # Provision and output as JSON
  platformctl tpm provision --create-ek -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			opts := &provisionOptions{
				CreateEK:            createEK,
				CreateSRK:           createSRK,
				CreateAK:            createAK,
				OwnerPassword:       ownerPassword,
				EndorsementPassword: endorsementPassword,
			}
			return runProvision(flags, opts)
		},
	}

	cmd.Flags().BoolVar(&createEK, "create-ek", true, "create Endorsement Key")
	cmd.Flags().BoolVar(&createSRK, "create-srk", true, "create Storage Root Key")
	cmd.Flags().BoolVar(&createAK, "create-ak", true, "create Attestation Key")
	cmd.Flags().StringVar(&ownerPassword, "owner-password", "", "TPM owner hierarchy password")
	cmd.Flags().StringVar(&endorsementPassword, "endorsement-password", "", "TPM endorsement hierarchy password")

	return cmd
}

// provisionOptions holds options for the provision command
type provisionOptions struct {
	CreateEK            bool
	CreateSRK           bool
	CreateAK            bool
	OwnerPassword       string
	EndorsementPassword string
}

// runProvision executes the provision command
func runProvision(flags *cli.CommonFlags, opts *provisionOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runProvisionWithClient(&tpmBaseCommandAdapter{base: base}, opts)
}

// runProvisionWithClient runs provision with a testable interface
func runProvisionWithClient(base TPMBaseCommandInterface, opts *provisionOptions) error {
	defer base.Close()

	sdkClient := tpmsvc.NewClientFromGRPC(base.TPMClient())

	req := &tpmsvc.ProvisionRequest{
		CreateEK:            opts.CreateEK,
		CreateSRK:           opts.CreateSRK,
		CreateAK:            opts.CreateAK,
		OwnerPassword:       opts.OwnerPassword,
		EndorsementPassword: opts.EndorsementPassword,
	}

	ctx := base.Context()
	resp, err := sdkClient.ProvisionDomain(ctx, req)
	if err != nil {
		return ErrTPMProvisionFailed{Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrTPMProvisionFailed{Reason: msg}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"success": resp.Status.Success,
		"message": resp.Status.Message,
	}

	if len(resp.EKPublic) > 0 {
		output["ek_created"] = true
	}
	if len(resp.SRKPublic) > 0 {
		output["srk_created"] = true
	}
	if len(resp.AKPublic) > 0 {
		output["ak_created"] = true
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("TPM provisioned successfully")
		fmt.Println()
		if len(resp.EKPublic) > 0 {
			printer.PrintKeyValue("EK Created", "Yes")
		}
		if len(resp.SRKPublic) > 0 {
			printer.PrintKeyValue("SRK Created", "Yes")
		}
		if len(resp.AKPublic) > 0 {
			printer.PrintKeyValue("AK Created", "Yes")
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
