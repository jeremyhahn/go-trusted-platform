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

// dataKeyFlags contains flags for data key generation commands
type dataKeyFlags struct {
	keyID      string
	algorithm  string
	keySize    int32
	context    string
	outputPath string
}

// newCryptoDataKeyCommand creates the data key operations command group
func newCryptoDataKeyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "datakey",
		Short: "Data encryption key operations",
		Long: `Generate data encryption keys (DEKs) for envelope encryption.

Envelope encryption is a pattern where:
1. A data encryption key (DEK) is generated
2. Data is encrypted locally using the DEK
3. The DEK itself is encrypted (wrapped) by a KMS-managed key (KEK)
4. Both the encrypted data and wrapped DEK are stored together

This provides the benefits of KMS-managed keys while allowing high-performance
local encryption for large datasets.

Commands:
  generate: Generate a DEK with both plaintext and wrapped versions
  wrapped:  Generate only the wrapped DEK (for secure key distribution)

Examples:
  # Generate a data key
  platformctl kms crypto datakey generate --key-id master-key

  # Generate with specific algorithm
  platformctl kms crypto datakey generate --key-id master-key --algorithm aes-256

  # Generate wrapped-only data key
  platformctl kms crypto datakey wrapped --key-id master-key`,
	}

	cmd.AddCommand(newGenerateDataKeyCommand(getFlags))
	cmd.AddCommand(newGenerateWrappedDataKeyCommand(getFlags))

	return cmd
}

// newGenerateDataKeyCommand creates the generate data key subcommand
func newGenerateDataKeyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &dataKeyFlags{}

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a data encryption key",
		Long: `Generate a data encryption key (DEK) for envelope encryption.

Returns both the plaintext DEK (for immediate use) and the encrypted
version (for secure storage). The plaintext should be used for local encryption
and then discarded; only the encrypted version should be persisted.

The encrypted DEK can be decrypted later using the decrypt command to recover
the plaintext DEK when the data needs to be decrypted.

Examples:
  # Generate a data key
  platformctl kms crypto datakey generate --key-id master-key

  # Generate with specific algorithm and key size
  platformctl kms crypto datakey generate --key-id master-key --algorithm aes-256 --key-size 256

  # Generate with context
  platformctl kms crypto datakey generate --key-id master-key --context "purpose=backup"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGenerateDataKey(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", "", "key encryption key ID (required)")
	cmd.Flags().StringVar(&cmdFlags.algorithm, "algorithm", "aes-256", "DEK algorithm")
	cmd.Flags().Int32Var(&cmdFlags.keySize, "key-size", 256, "DEK key size in bits")
	cmd.Flags().StringVar(&cmdFlags.context, "context", "", "encryption context (AAD)")
	cmd.Flags().StringVarP(&cmdFlags.outputPath, "output", "o", "", "output file for encrypted key")

	if err := cmd.MarkFlagRequired("key-id"); err != nil {
		panic(fmt.Sprintf("failed to mark key-id flag required: %v", err))
	}

	return cmd
}

// newGenerateWrappedDataKeyCommand creates the generate wrapped data key subcommand
func newGenerateWrappedDataKeyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &dataKeyFlags{}

	cmd := &cobra.Command{
		Use:   "wrapped",
		Short: "Generate a wrapped data encryption key",
		Long: `Generate only a wrapped (encrypted) data encryption key.

This command generates a DEK and returns only the wrapped version - the plaintext
DEK is never exposed. This is useful for:
  - Pre-generating keys for later use
  - Distributing encrypted keys to systems that will decrypt them later
  - Key escrow scenarios

To use the key, decrypt the wrapped DEK blob using the decrypt command with
the same key encryption key (KEK).

Examples:
  # Generate a wrapped-only data key
  platformctl kms crypto datakey wrapped --key-id master-key

  # Save wrapped key to file
  platformctl kms crypto datakey wrapped --key-id master-key --output wrapped-key.bin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGenerateWrappedDataKey(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", "", "key encryption key ID (required)")
	cmd.Flags().StringVar(&cmdFlags.algorithm, "algorithm", "aes-256", "DEK algorithm")
	cmd.Flags().Int32Var(&cmdFlags.keySize, "key-size", 256, "DEK key size in bits")
	cmd.Flags().StringVar(&cmdFlags.context, "context", "", "encryption context (AAD)")
	cmd.Flags().StringVarP(&cmdFlags.outputPath, "output", "o", "", "output file for wrapped key")

	if err := cmd.MarkFlagRequired("key-id"); err != nil {
		panic(fmt.Sprintf("failed to mark key-id flag required: %v", err))
	}

	return cmd
}

// runGenerateDataKey executes the generate data key operation
func runGenerateDataKey(flags *cli.CommonFlags, cmdFlags *dataKeyFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	// Parse algorithm using SDK parser
	keyAlg, err := kmssvc.ParseKeyAlgorithm(cmdFlags.algorithm)
	if err != nil {
		return ErrInvalidAlgorithm{Algorithm: cmdFlags.algorithm}
	}

	// Parse context if provided
	var contextBytes []byte
	if cmdFlags.context != "" {
		contextBytes = []byte(cmdFlags.context)
	}

	ctx := base.Context()
	resp, err := sdkClient.GenerateDataKeyDomain(ctx, cmdFlags.keyID, keyAlg, cmdFlags.keySize, contextBytes)
	if err != nil {
		return ErrCryptoOperationFailed{Operation: "generate data key", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			KeyID        string `json:"key_id" yaml:"key_id"`
			PlaintextKey string `json:"plaintext_key" yaml:"plaintext_key"`
			EncryptedKey string `json:"encrypted_key" yaml:"encrypted_key"`
			Timestamp    string `json:"timestamp" yaml:"timestamp"`
		}{
			KeyID:        resp.KeyID,
			PlaintextKey: base64.StdEncoding.EncodeToString(resp.PlaintextKey),
			EncryptedKey: base64.StdEncoding.EncodeToString(resp.EncryptedKey),
			Timestamp:    formatTimestamp(resp.Timestamp),
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("Data encryption key generated")
		printer.PrintKeyValue("Key ID", resp.KeyID)
		printer.PrintKeyValue("Algorithm", cmdFlags.algorithm)
		printer.PrintKeyValue("Plaintext Key (base64)", base64.StdEncoding.EncodeToString(resp.PlaintextKey))
		printer.PrintKeyValue("Encrypted Key (base64)", base64.StdEncoding.EncodeToString(resp.EncryptedKey))

		// Optionally write encrypted key to file
		if cmdFlags.outputPath != "" {
			if err := writeOutputData(cmdFlags.outputPath, resp.EncryptedKey, true); err != nil {
				return err
			}
			printer.PrintKeyValue("Encrypted Key File", cmdFlags.outputPath)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runGenerateWrappedDataKey executes the generate wrapped data key operation
func runGenerateWrappedDataKey(flags *cli.CommonFlags, cmdFlags *dataKeyFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	// Parse algorithm using SDK parser
	keyAlg, err := kmssvc.ParseKeyAlgorithm(cmdFlags.algorithm)
	if err != nil {
		return ErrInvalidAlgorithm{Algorithm: cmdFlags.algorithm}
	}

	// Parse context if provided
	var contextBytes []byte
	if cmdFlags.context != "" {
		contextBytes = []byte(cmdFlags.context)
	}

	ctx := base.Context()
	resp, err := sdkClient.GenerateWrappedDataKeyDomain(ctx, cmdFlags.keyID, keyAlg, cmdFlags.keySize, contextBytes)
	if err != nil {
		return ErrCryptoOperationFailed{Operation: "generate wrapped data key", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			WrappingKeyID string `json:"wrapping_key_id" yaml:"wrapping_key_id"`
			WrappedKey    string `json:"wrapped_key" yaml:"wrapped_key"`
			Timestamp     string `json:"timestamp" yaml:"timestamp"`
		}{
			WrappingKeyID: resp.WrappingKeyID,
			WrappedKey:    base64.StdEncoding.EncodeToString(resp.WrappedKey),
			Timestamp:     formatTimestamp(resp.Timestamp),
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		// Write wrapped key to output
		if err := writeOutputData(cmdFlags.outputPath, resp.WrappedKey, true); err != nil {
			return err
		}

		if cmdFlags.outputPath != "" {
			printer.PrintSuccess("Wrapped data encryption key generated")
			printer.PrintKeyValue("Wrapping Key ID", resp.WrappingKeyID)
			printer.PrintKeyValue("Algorithm", cmdFlags.algorithm)
			printer.PrintKeyValue("Output", cmdFlags.outputPath)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
