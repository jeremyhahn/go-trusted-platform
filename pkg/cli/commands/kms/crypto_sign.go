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

package kms

import (
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"

	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// signFlags contains flags for the sign command
type signFlags struct {
	keyID         string
	inputPath     string
	outputPath    string
	hashAlgorithm string
	base64Out     bool
}

// newCryptoSignCommand creates the sign subcommand
func newCryptoSignCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &signFlags{}

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Create a digital signature",
		Long: `Create a digital signature of data using a named signing key.

The signing operation is performed server-side using an asymmetric key
(RSA, ECDSA, or EdDSA). The message is hashed using the specified algorithm
before signing.

Supported hash algorithms:
  - sha256, sha384, sha512 (SHA-2 family)
  - sha3-256, sha3-384, sha3-512 (SHA-3 family)
  - blake2b-256, blake2b-512 (BLAKE2b)

Input can be provided via:
  - --input flag (reads from file)
  - stdin (pipe data to the command)

Examples:
  # Sign a file
  platformctl kms crypto sign --key-id signing-key --input document.pdf --output signature.sig

  # Sign with specific hash algorithm
  platformctl kms crypto sign --key-id ecdsa-key --input data.txt --hash sha384

  # Sign from stdin
  echo "message to sign" | platformctl kms crypto sign --key-id rsa-key`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCryptoSign(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", "", "signing key ID (required)")
	cmd.Flags().StringVarP(&cmdFlags.inputPath, "input", "i", "", "input file path")
	cmd.Flags().StringVarP(&cmdFlags.outputPath, "output", "o", "", "output file for signature")
	cmd.Flags().StringVar(&cmdFlags.hashAlgorithm, "hash", "sha256", "hash algorithm")
	cmd.Flags().BoolVar(&cmdFlags.base64Out, "base64", true, "base64 encode output")

	if err := cmd.MarkFlagRequired("key-id"); err != nil {
		panic(fmt.Sprintf("failed to mark key-id flag required: %v", err))
	}

	return cmd
}

// runCryptoSign executes the sign operation
func runCryptoSign(flags *cli.CommonFlags, cmdFlags *signFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	// Read input data
	message, err := readInputData(cmdFlags.inputPath)
	if err != nil {
		return err
	}

	// Parse hash algorithm
	hashAlg, err := parseHashAlgorithm(cmdFlags.hashAlgorithm)
	if err != nil {
		return err
	}

	ctx := base.Context()
	resp, err := sdkClient.SignDomain(ctx, cmdFlags.keyID, message, hashAlg)
	if err != nil {
		return ErrCryptoOperationFailed{Operation: "sign", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			KeyID         string `json:"key_id" yaml:"key_id"`
			KeyVersion    uint64 `json:"key_version" yaml:"key_version"`
			Signature     string `json:"signature" yaml:"signature"`
			HashAlgorithm string `json:"hash_algorithm" yaml:"hash_algorithm"`
			Timestamp     string `json:"timestamp" yaml:"timestamp"`
		}{
			KeyID:         resp.KeyID,
			KeyVersion:    resp.KeyVersion,
			Signature:     base64.StdEncoding.EncodeToString(resp.Signature),
			HashAlgorithm: formatHashAlgorithm(resp.HashAlgorithm),
			Timestamp:     formatTimestamp(resp.Timestamp),
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		// Write signature to output
		if err := writeOutputData(cmdFlags.outputPath, resp.Signature, cmdFlags.base64Out); err != nil {
			return err
		}

		// Show metadata if writing to file
		if cmdFlags.outputPath != "" {
			printer.PrintSuccess("Message signed successfully")
			printer.PrintKeyValue("Key ID", resp.KeyID)
			printer.PrintKeyValue("Key Version", fmt.Sprintf("%d", resp.KeyVersion))
			printer.PrintKeyValue("Hash Algorithm", formatHashAlgorithm(resp.HashAlgorithm))
			printer.PrintKeyValue("Output", cmdFlags.outputPath)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
