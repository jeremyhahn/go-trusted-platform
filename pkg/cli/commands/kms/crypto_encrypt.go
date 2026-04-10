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

// encryptFlags contains flags for the encrypt command
type encryptFlags struct {
	keyID      string
	inputPath  string
	outputPath string
	context    string
	nonce      string
	base64Out  bool
}

// newCryptoEncryptCommand creates the encrypt subcommand
func newCryptoEncryptCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &encryptFlags{}

	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt data with a key",
		Long: `Encrypt plaintext data using a named encryption key.

The encryption is performed server-side using the specified key. The ciphertext
includes authentication data to ensure integrity. An optional context can be
provided for additional authenticated data (AAD).

Input can be provided via:
  - --input flag (reads from file)
  - stdin (pipe data to the command)

Output can be directed to:
  - --output flag (writes to file)
  - stdout (default, base64 encoded for terminal safety)

Examples:
  # Encrypt a file
  platformctl kms crypto encrypt --key-id mykey --input secret.txt --output secret.enc

  # Encrypt from stdin
  echo "secret data" | platformctl kms crypto encrypt --key-id mykey

  # Encrypt with additional context
  platformctl kms crypto encrypt --key-id mykey --input data.txt --context "user=alice"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCryptoEncrypt(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", "", "encryption key ID (required)")
	cmd.Flags().StringVarP(&cmdFlags.inputPath, "input", "i", "", "input file path (reads from stdin if not provided)")
	cmd.Flags().StringVarP(&cmdFlags.outputPath, "output", "o", "", "output file path (writes to stdout if not provided)")
	cmd.Flags().StringVar(&cmdFlags.context, "context", "", "additional authenticated data (AAD)")
	cmd.Flags().StringVar(&cmdFlags.nonce, "nonce", "", "custom nonce (base64 encoded, auto-generated if not provided)")
	cmd.Flags().BoolVar(&cmdFlags.base64Out, "base64", true, "base64 encode output (default true for stdout)")

	if err := cmd.MarkFlagRequired("key-id"); err != nil {
		panic(fmt.Sprintf("failed to mark key-id flag required: %v", err))
	}

	return cmd
}

// runCryptoEncrypt executes the encrypt operation
func runCryptoEncrypt(flags *cli.CommonFlags, cmdFlags *encryptFlags) error {
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
	plaintext, err := readInputData(cmdFlags.inputPath)
	if err != nil {
		return err
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

	req := &platformv1.EncryptRequest{
		KeyId:     cmdFlags.keyID,
		Plaintext: plaintext,
		Context:   contextBytes,
		Nonce:     nonceBytes,
	}

	ctx := base.Context()
	resp, err := client.Encrypt(ctx, req)
	if err != nil {
		return ErrCryptoOperationFailed{Operation: "encrypt", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			KeyID      string `json:"key_id" yaml:"key_id"`
			KeyVersion uint64 `json:"key_version" yaml:"key_version"`
			Ciphertext string `json:"ciphertext" yaml:"ciphertext"`
			Nonce      string `json:"nonce" yaml:"nonce"`
			Timestamp  string `json:"timestamp" yaml:"timestamp"`
		}{
			KeyID:      resp.KeyId,
			KeyVersion: resp.KeyVersion,
			Ciphertext: base64.StdEncoding.EncodeToString(resp.Ciphertext),
			Nonce:      base64.StdEncoding.EncodeToString(resp.Nonce),
			Timestamp:  formatTimestamp(resp.Timestamp),
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		// For table format, write ciphertext to output and show metadata
		if err := writeOutputData(cmdFlags.outputPath, resp.Ciphertext, cmdFlags.base64Out); err != nil {
			return err
		}

		// Only show metadata if writing to file (not cluttering stdout)
		if cmdFlags.outputPath != "" {
			printer.PrintSuccess("Data encrypted successfully")
			printer.PrintKeyValue("Key ID", resp.KeyId)
			printer.PrintKeyValue("Key Version", fmt.Sprintf("%d", resp.KeyVersion))
			printer.PrintKeyValue("Nonce", base64.StdEncoding.EncodeToString(resp.Nonce))
			printer.PrintKeyValue("Output", cmdFlags.outputPath)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
