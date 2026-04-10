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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newSRKCommand creates the srk command group for SRK operations
func newSRKCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "srk",
		Short: "Storage Root Key operations",
		Long: `Perform operations on the TPM 2.0 Storage Root Key (SRK).

The Storage Root Key is the primary key in the storage hierarchy.
It is used as the parent for all storage keys and sealing operations.

Available subcommands:
  - create: Create a new Storage Root Key
  - info: Get SRK information
  - delete: Delete the SRK

Examples:
  # Get SRK information
  platformctl tpm srk info

  # Create SRK with RSA algorithm
  platformctl tpm srk create --algorithm RSA-2048

  # Delete SRK
  platformctl tpm srk delete`,
	}

	cmd.AddCommand(newSRKCreateCommand(getFlags))
	cmd.AddCommand(newSRKInfoCommand(getFlags))
	cmd.AddCommand(newSRKDeleteCommand(getFlags))

	return cmd
}

// newSRKCreateCommand creates the create subcommand for SRK
func newSRKCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var algorithm string
	var persistent bool
	var parentHandle uint32
	var parentPassword string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new Storage Root Key",
		Long: `Create a new Storage Root Key (SRK) in the TPM.

The SRK is created in the storage hierarchy and optionally
persisted at the TCG-recommended handle.

Supported algorithms:
  - RSA-2048 (default)
  - RSA-3072
  - ECDSA-P256
  - ECDSA-P384

Examples:
  # Create SRK with default algorithm (RSA-2048)
  platformctl tpm srk create

  # Create persistent SRK with ECDSA
  platformctl tpm srk create --algorithm ECDSA-P256 --persistent`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			opts := &srkCreateOptions{
				Algorithm:      algorithm,
				Persistent:     persistent,
				ParentHandle:   parentHandle,
				ParentPassword: parentPassword,
			}
			return runSRKCreate(flags, opts)
		},
	}

	cmd.Flags().StringVar(&algorithm, "algorithm", "RSA-2048", "key algorithm: RSA-2048, RSA-3072, ECDSA-P256, ECDSA-P384")
	cmd.Flags().BoolVar(&persistent, "persistent", true, "persist the SRK to the TPM")
	cmd.Flags().Uint32Var(&parentHandle, "parent", 0x81010001, "parent EK handle")
	cmd.Flags().StringVar(&parentPassword, "parent-password", "", "parent key password")

	return cmd
}

// srkCreateOptions holds options for the SRK create command
type srkCreateOptions struct {
	Algorithm      string
	Persistent     bool
	ParentHandle   uint32
	ParentPassword string
}

// newSRKInfoCommand creates the info subcommand for SRK
func newSRKInfoCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var handle uint32

	cmd := &cobra.Command{
		Use:   "info",
		Short: "Get Storage Root Key information",
		Long: `Retrieve information about the Storage Root Key in the TPM.

Returns details including:
  - TPM handle
  - Key algorithm
  - Public key

Examples:
  # Get SRK info in table format
  platformctl tpm srk info

  # Get SRK info as JSON
  platformctl tpm srk info -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runSRKInfo(flags, handle)
		},
	}

	cmd.Flags().Uint32Var(&handle, "handle", 0x81000001, "SRK handle (default: TCG recommended)")

	return cmd
}

// newSRKDeleteCommand creates the delete subcommand for SRK
func newSRKDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var handle uint32
	var password string

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete the Storage Root Key",
		Long: `Delete the Storage Root Key from the TPM.

WARNING: This operation is irreversible and will invalidate
all keys derived from this SRK.

Examples:
  # Delete SRK
  platformctl tpm srk delete

  # Delete SRK with password
  platformctl tpm srk delete --password mypassword`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runSRKDelete(flags, handle, password)
		},
	}

	cmd.Flags().Uint32Var(&handle, "handle", 0x81000001, "SRK handle")
	cmd.Flags().StringVar(&password, "password", "", "authorization password")

	return cmd
}

// runSRKCreate executes the SRK create command
func runSRKCreate(flags *cli.CommonFlags, opts *srkCreateOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runSRKCreateWithClient(&tpmBaseCommandAdapter{base: base}, opts)
}

// runSRKCreateWithClient runs SRK create with a testable interface
func runSRKCreateWithClient(base TPMBaseCommandInterface, opts *srkCreateOptions) error {
	defer base.Close()

	keyAlg, err := parseKeyAlgorithm(opts.Algorithm)
	if err != nil {
		return err
	}

	req := &platformv1.CreateSRKRequest{
		Attributes: &platformv1.KeyAttributes{
			Algorithm: keyAlg,
		},
		Persistent:     opts.Persistent,
		ParentHandle:   opts.ParentHandle,
		ParentPassword: opts.ParentPassword,
	}

	ctx := base.Context()
	resp, err := base.TPMClient().CreateSRK(ctx, req)
	if err != nil {
		return ErrSRKCreateFailed{Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrSRKCreateFailed{Reason: msg}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"success":   resp.Status.Success,
		"handle":    fmt.Sprintf("0x%08X", resp.Handle),
		"algorithm": opts.Algorithm,
	}

	if len(resp.PublicKey) > 0 {
		output["public_key"] = hex.EncodeToString(resp.PublicKey)
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("Storage Root Key created successfully")
		fmt.Println()
		printer.PrintKeyValue("Handle", fmt.Sprintf("0x%08X", resp.Handle))
		printer.PrintKeyValue("Algorithm", opts.Algorithm)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runSRKInfo executes the SRK info command
func runSRKInfo(flags *cli.CommonFlags, handle uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runSRKInfoWithClient(&tpmBaseCommandAdapter{base: base}, handle)
}

// runSRKInfoWithClient runs SRK info with a testable interface
func runSRKInfoWithClient(base TPMBaseCommandInterface, handle uint32) error {
	defer base.Close()

	req := &platformv1.GetSRKRequest{
		Handle: handle,
	}

	ctx := base.Context()
	resp, err := base.TPMClient().GetSRK(ctx, req)
	if err != nil {
		return ErrSRKNotFound{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"handle":    fmt.Sprintf("0x%08X", resp.Handle),
		"algorithm": formatKeyAlgorithm(resp.Algorithm),
	}

	if len(resp.PublicKey) > 0 {
		output["public_key"] = hex.EncodeToString(resp.PublicKey)
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("Handle", fmt.Sprintf("0x%08X", resp.Handle))
		printer.PrintKeyValue("Algorithm", formatKeyAlgorithm(resp.Algorithm))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runSRKDelete executes the SRK delete command
func runSRKDelete(flags *cli.CommonFlags, handle uint32, password string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runSRKDeleteWithClient(&tpmBaseCommandAdapter{base: base}, handle, password)
}

// runSRKDeleteWithClient runs SRK delete with a testable interface
func runSRKDeleteWithClient(base TPMBaseCommandInterface, handle uint32, password string) error {
	defer base.Close()

	req := &platformv1.DeleteSRKRequest{
		Handle:   handle,
		Password: password,
	}

	ctx := base.Context()
	resp, err := base.TPMClient().DeleteSRK(ctx, req)
	if err != nil {
		return ErrSRKDeleteFailed{Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrSRKDeleteFailed{Reason: msg}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"deleted": resp.Status.Success,
		"message": resp.Status.Message,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("Storage Root Key deleted successfully")
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
