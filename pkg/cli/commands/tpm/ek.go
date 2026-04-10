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

// newEKCommand creates the ek command group for EK operations
func newEKCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ek",
		Short: "Endorsement Key operations",
		Long: `Perform operations on the TPM 2.0 Endorsement Key (EK).

The Endorsement Key is a restricted encryption key that uniquely identifies the TPM.
It is used for privacy-sensitive operations and as the root of trust for the TPM.

Available subcommands:
  - create: Create a new Endorsement Key
  - info: Get EK information
  - certificate: Get EK certificate
  - delete: Delete the EK

Examples:
  # Get EK information
  platformctl tpm ek info

  # Create EK with RSA algorithm
  platformctl tpm ek create --algorithm RSA-2048

  # Get EK certificate
  platformctl tpm ek certificate

  # Delete EK
  platformctl tpm ek delete`,
	}

	cmd.AddCommand(newEKCreateCommand(getFlags))
	cmd.AddCommand(newEKInfoCommand(getFlags))
	cmd.AddCommand(newEKCertificateCommand(getFlags))
	cmd.AddCommand(newEKDeleteCommand(getFlags))

	return cmd
}

// newEKCreateCommand creates the create subcommand for EK
func newEKCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var algorithm string
	var persistent bool

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new Endorsement Key",
		Long: `Create a new Endorsement Key (EK) in the TPM.

The EK is created in the endorsement hierarchy and optionally
persisted at the TCG-recommended handle.

Supported algorithms:
  - RSA-2048 (default)
  - RSA-3072
  - ECDSA-P256
  - ECDSA-P384

Examples:
  # Create EK with default algorithm (RSA-2048)
  platformctl tpm ek create

  # Create persistent EK with ECDSA
  platformctl tpm ek create --algorithm ECDSA-P256 --persistent`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runEKCreate(flags, algorithm, persistent)
		},
	}

	cmd.Flags().StringVar(&algorithm, "algorithm", "RSA-2048", "key algorithm: RSA-2048, RSA-3072, ECDSA-P256, ECDSA-P384")
	cmd.Flags().BoolVar(&persistent, "persistent", true, "persist the EK to the TPM")

	return cmd
}

// newEKInfoCommand creates the info subcommand for EK
func newEKInfoCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var handle uint32

	cmd := &cobra.Command{
		Use:   "info",
		Short: "Get Endorsement Key information",
		Long: `Retrieve information about the Endorsement Key in the TPM.

Returns details including:
  - TPM handle
  - Key algorithm
  - Public key

Examples:
  # Get EK info in table format
  platformctl tpm ek info

  # Get EK info as JSON
  platformctl tpm ek info -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runEKInfo(flags, handle)
		},
	}

	cmd.Flags().Uint32Var(&handle, "handle", 0x81010001, "EK handle (default: TCG recommended)")

	return cmd
}

// newEKCertificateCommand creates the certificate subcommand for EK
func newEKCertificateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certificate",
		Short: "Get Endorsement Key certificate",
		Long: `Retrieve the Endorsement Key certificate from the TPM.

The EK certificate is typically provisioned by the TPM manufacturer
and stored in NVRAM.

Examples:
  # Get EK certificate in table format
  platformctl tpm ek certificate

  # Get EK certificate as JSON
  platformctl tpm ek certificate -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runEKCertificate(flags)
		},
	}

	return cmd
}

// newEKDeleteCommand creates the delete subcommand for EK
func newEKDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var handle uint32
	var password string

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete the Endorsement Key",
		Long: `Delete the Endorsement Key from the TPM.

WARNING: This operation is irreversible.

Examples:
  # Delete EK
  platformctl tpm ek delete

  # Delete EK with password
  platformctl tpm ek delete --password mypassword`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runEKDelete(flags, handle, password)
		},
	}

	cmd.Flags().Uint32Var(&handle, "handle", 0x81010001, "EK handle")
	cmd.Flags().StringVar(&password, "password", "", "authorization password")

	return cmd
}

// runEKCreate executes the EK create command
func runEKCreate(flags *cli.CommonFlags, algorithm string, persistent bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runEKCreateWithClient(&tpmBaseCommandAdapter{base: base}, algorithm, persistent)
}

// runEKCreateWithClient runs EK create with a testable interface
func runEKCreateWithClient(base TPMBaseCommandInterface, algorithm string, persistent bool) error {
	defer base.Close()

	keyAlg, err := parseKeyAlgorithm(algorithm)
	if err != nil {
		return err
	}

	req := &platformv1.CreateEKRequest{
		Attributes: &platformv1.KeyAttributes{
			Algorithm: keyAlg,
		},
		Persistent: persistent,
	}

	ctx := base.Context()
	resp, err := base.TPMClient().CreateEK(ctx, req)
	if err != nil {
		return ErrEKCreateFailed{Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrEKCreateFailed{Reason: msg}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"success":   resp.Status.Success,
		"handle":    fmt.Sprintf("0x%08X", resp.Handle),
		"algorithm": algorithm,
	}

	if len(resp.PublicKey) > 0 {
		output["public_key"] = hex.EncodeToString(resp.PublicKey)
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("Endorsement Key created successfully")
		fmt.Println()
		printer.PrintKeyValue("Handle", fmt.Sprintf("0x%08X", resp.Handle))
		printer.PrintKeyValue("Algorithm", algorithm)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runEKInfo executes the EK info command
func runEKInfo(flags *cli.CommonFlags, handle uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runEKInfoWithClient(&tpmBaseCommandAdapter{base: base}, handle)
}

// runEKInfoWithClient runs EK info with a testable interface
func runEKInfoWithClient(base TPMBaseCommandInterface, handle uint32) error {
	defer base.Close()

	req := &platformv1.GetEKRequest{
		Handle: handle,
	}

	ctx := base.Context()
	resp, err := base.TPMClient().GetEK(ctx, req)
	if err != nil {
		return ErrEKNotFound{Reason: err.Error()}
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

// runEKCertificate executes the EK certificate command
func runEKCertificate(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runEKCertificateWithClient(&tpmBaseCommandAdapter{base: base})
}

// runEKCertificateWithClient runs EK certificate with a testable interface
func runEKCertificateWithClient(base TPMBaseCommandInterface) error {
	defer base.Close()

	req := &platformv1.GetEKCertificateRequest{}

	ctx := base.Context()
	resp, err := base.TPMClient().GetEKCertificate(ctx, req)
	if err != nil {
		return ErrEKCertificateNotFound{Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"format": resp.Format,
	}

	if len(resp.Certificate) > 0 {
		output["certificate"] = string(resp.Certificate)
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("Format", resp.Format)
		if len(resp.Certificate) > 0 {
			fmt.Println()
			fmt.Print(string(resp.Certificate))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runEKDelete executes the EK delete command
func runEKDelete(flags *cli.CommonFlags, handle uint32, password string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runEKDeleteWithClient(&tpmBaseCommandAdapter{base: base}, handle, password)
}

// runEKDeleteWithClient runs EK delete with a testable interface
func runEKDeleteWithClient(base TPMBaseCommandInterface, handle uint32, password string) error {
	defer base.Close()

	req := &platformv1.DeleteEKRequest{
		Handle:   handle,
		Password: password,
	}

	ctx := base.Context()
	resp, err := base.TPMClient().DeleteEK(ctx, req)
	if err != nil {
		return ErrEKDeleteFailed{Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrEKDeleteFailed{Reason: msg}
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
		printer.PrintSuccess("Endorsement Key deleted successfully")
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// parseKeyAlgorithm converts a string algorithm name to the proto enum value
func parseKeyAlgorithm(algorithm string) (platformv1.KeyAlgorithm, error) {
	switch algorithm {
	case "RSA-2048", "RSA2048":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048, nil
	case "RSA-3072", "RSA3072":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072, nil
	case "RSA-4096", "RSA4096":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096, nil
	case "ECDSA-P256", "ECDSAP256", "P256":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, nil
	case "ECDSA-P384", "ECDSAP384", "P384":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384, nil
	case "ECDSA-P521", "ECDSAP521", "P521":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521, nil
	default:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED,
			ErrInvalidKeyAlgorithm{Algorithm: algorithm}
	}
}

// formatKeyAlgorithm converts a proto enum value to a human-readable string
func formatKeyAlgorithm(alg platformv1.KeyAlgorithm) string {
	switch alg {
	case platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048:
		return "RSA-2048"
	case platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072:
		return "RSA-3072"
	case platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096:
		return "RSA-4096"
	case platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256:
		return "ECDSA-P256"
	case platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384:
		return "ECDSA-P384"
	case platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521:
		return "ECDSA-P521"
	default:
		return "Unknown"
	}
}
