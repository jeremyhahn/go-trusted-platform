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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// decryptFlags contains flags for the decrypt command
type decryptFlags struct {
	keyID      string
	inputPath  string
	outputPath string
	context    string
	nonce      string
	keyVersion uint64
	base64In   bool
}

// newCryptoDecryptCommand creates the decrypt subcommand
func newCryptoDecryptCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &decryptFlags{}

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt data",
		Long: `Decrypt ciphertext that was encrypted with a named key.

The decryption is performed server-side using the specified key. If the data
was encrypted with a context (AAD), the same context must be provided for
successful decryption.

Input can be provided via:
  - --input flag (reads from file)
  - stdin (pipe data to the command)

By default, input is expected to be base64 encoded (as produced by encrypt).
Use --base64-input=false for raw binary input.

Examples:
  # Decrypt a file
  platformctl kms crypto decrypt --key-id mykey --input secret.enc --output secret.txt

  # Decrypt from stdin
  cat secret.enc | platformctl kms crypto decrypt --key-id mykey

  # Decrypt with context
  platformctl kms crypto decrypt --key-id mykey --input data.enc --context "user=alice"

  # Decrypt with specific key version
  platformctl kms crypto decrypt --key-id mykey --input data.enc --key-version 2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCryptoDecrypt(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", "", "decryption key ID (required)")
	cmd.Flags().StringVarP(&cmdFlags.inputPath, "input", "i", "", "input file path (reads from stdin if not provided)")
	cmd.Flags().StringVarP(&cmdFlags.outputPath, "output", "o", "", "output file path (writes to stdout if not provided)")
	cmd.Flags().StringVar(&cmdFlags.context, "context", "", "additional authenticated data (AAD) used during encryption")
	cmd.Flags().StringVar(&cmdFlags.nonce, "nonce", "", "nonce used during encryption (base64 encoded)")
	cmd.Flags().Uint64Var(&cmdFlags.keyVersion, "key-version", 0, "specific key version (0 for auto-detect)")
	cmd.Flags().BoolVar(&cmdFlags.base64In, "base64-input", true, "input is base64 encoded")

	if err := cmd.MarkFlagRequired("key-id"); err != nil {
		panic(fmt.Sprintf("failed to mark key-id flag required: %v", err))
	}

	return cmd
}

// runCryptoDecrypt executes the decrypt operation
func runCryptoDecrypt(flags *cli.CommonFlags, cmdFlags *decryptFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := base.Client().KMS()
	if client == nil {
		return ErrCryptoClientNotInitialized{}
	}

	// Read input data
	inputData, err := readInputData(cmdFlags.inputPath)
	if err != nil {
		return err
	}

	// Decode base64 if needed
	var ciphertext []byte
	if cmdFlags.base64In {
		ciphertext, err = decodeBase64Input(inputData)
		if err != nil {
			return err
		}
	} else {
		ciphertext = inputData
	}

	// Parse context if provided
	var contextBytes []byte
	if cmdFlags.context != "" {
		contextBytes = []byte(cmdFlags.context)
	}

	// Parse nonce if provided
	var nonceBytes []byte
	if cmdFlags.nonce != "" {
		nonceBytes, err = base64.StdEncoding.DecodeString(cmdFlags.nonce)
		if err != nil {
			return ErrInvalidBase64{Field: "nonce", Err: err}
		}
	}

	req := &platformv1.DecryptRequest{
		KeyId:      cmdFlags.keyID,
		Ciphertext: ciphertext,
		Context:    contextBytes,
		Nonce:      nonceBytes,
		KeyVersion: cmdFlags.keyVersion,
	}

	ctx := base.Context()
	resp, err := client.Decrypt(ctx, req)
	if err != nil {
		return ErrCryptoOperationFailed{Operation: "decrypt", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			KeyID      string `json:"key_id" yaml:"key_id"`
			KeyVersion uint64 `json:"key_version" yaml:"key_version"`
			Plaintext  string `json:"plaintext" yaml:"plaintext"`
			Timestamp  string `json:"timestamp" yaml:"timestamp"`
		}{
			KeyID:      resp.KeyId,
			KeyVersion: resp.KeyVersion,
			Plaintext:  string(resp.Plaintext),
			Timestamp:  formatTimestamp(resp.Timestamp),
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		// For table format, write plaintext to output
		if err := writeOutputData(cmdFlags.outputPath, resp.Plaintext, false); err != nil {
			return err
		}

		// Only show metadata if writing to file
		if cmdFlags.outputPath != "" {
			printer.PrintSuccess("Data decrypted successfully")
			printer.PrintKeyValue("Key ID", resp.KeyId)
			printer.PrintKeyValue("Key Version", fmt.Sprintf("%d", resp.KeyVersion))
			printer.PrintKeyValue("Output", cmdFlags.outputPath)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
