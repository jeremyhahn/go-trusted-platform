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

// rewrapFlags contains flags for the rewrap command
type rewrapFlags struct {
	keyID         string
	inputPath     string
	outputPath    string
	context       string
	nonce         string
	sourceVersion uint64
	base64In      bool
	base64Out     bool
}

// newCryptoRewrapCommand creates the rewrap subcommand
func newCryptoRewrapCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &rewrapFlags{}

	cmd := &cobra.Command{
		Use:   "rewrap",
		Short: "Re-encrypt data with latest key version",
		Long: `Re-encrypt ciphertext with the latest version of the encryption key.

This operation decrypts the ciphertext using its original key version and
re-encrypts it with the current (latest) version of the key. This is useful
after key rotation to update encrypted data to use the new key version
without exposing the plaintext.

The plaintext is never exposed outside the KMS - the operation is performed
entirely server-side.

Input can be provided via:
  - --input flag (reads from file)
  - stdin (pipe data to the command)

By default, input is expected to be base64 encoded (as produced by encrypt).
Use --base64-input=false for raw binary input.

Examples:
  # Rewrap data from file
  platformctl kms crypto rewrap --key-id mykey --input old.enc --output new.enc

  # Rewrap with context
  platformctl kms crypto rewrap --key-id mykey --input data.enc --context "user=alice"

  # Rewrap from stdin
  cat old.enc | platformctl kms crypto rewrap --key-id mykey --output new.enc

  # Rewrap with specific source version
  platformctl kms crypto rewrap --key-id mykey --input data.enc --source-version 2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCryptoRewrap(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", "", "key ID (required)")
	cmd.Flags().StringVarP(&cmdFlags.inputPath, "input", "i", "", "input file path (reads from stdin if not provided)")
	cmd.Flags().StringVarP(&cmdFlags.outputPath, "output", "o", "", "output file path (writes to stdout if not provided)")
	cmd.Flags().StringVar(&cmdFlags.context, "context", "", "encryption context (AAD)")
	cmd.Flags().StringVar(&cmdFlags.nonce, "nonce", "", "nonce from original encryption (base64)")
	cmd.Flags().Uint64Var(&cmdFlags.sourceVersion, "source-version", 0, "original key version (0 for auto-detect)")
	cmd.Flags().BoolVar(&cmdFlags.base64In, "base64-input", true, "input is base64 encoded")
	cmd.Flags().BoolVar(&cmdFlags.base64Out, "base64", true, "base64 encode output")

	if err := cmd.MarkFlagRequired("key-id"); err != nil {
		panic(fmt.Sprintf("failed to mark key-id flag required: %v", err))
	}

	return cmd
}

// runCryptoRewrap executes the rewrap operation
func runCryptoRewrap(flags *cli.CommonFlags, cmdFlags *rewrapFlags) error {
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

	req := &platformv1.RewrapRequest{
		KeyId:         cmdFlags.keyID,
		Ciphertext:    ciphertext,
		Context:       contextBytes,
		Nonce:         nonceBytes,
		SourceVersion: cmdFlags.sourceVersion,
	}

	ctx := base.Context()
	resp, err := client.Rewrap(ctx, req)
	if err != nil {
		return ErrCryptoOperationFailed{Operation: "rewrap", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			KeyID         string `json:"key_id" yaml:"key_id"`
			SourceVersion uint64 `json:"source_version" yaml:"source_version"`
			TargetVersion uint64 `json:"target_version" yaml:"target_version"`
			Ciphertext    string `json:"ciphertext" yaml:"ciphertext"`
			Nonce         string `json:"nonce" yaml:"nonce"`
			Timestamp     string `json:"timestamp" yaml:"timestamp"`
		}{
			KeyID:         resp.KeyId,
			SourceVersion: resp.SourceVersion,
			TargetVersion: resp.TargetVersion,
			Ciphertext:    base64.StdEncoding.EncodeToString(resp.Ciphertext),
			Nonce:         base64.StdEncoding.EncodeToString(resp.Nonce),
			Timestamp:     formatTimestamp(resp.Timestamp),
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		// For table format, write ciphertext to output and show metadata
		if err := writeOutputData(cmdFlags.outputPath, resp.Ciphertext, cmdFlags.base64Out); err != nil {
			return err
		}

		// Only show metadata if writing to file (not cluttering stdout)
		if cmdFlags.outputPath != "" {
			printer.PrintSuccess("Data rewrapped successfully")
			printer.PrintKeyValue("Key ID", resp.KeyId)
			printer.PrintKeyValue("Source Version", fmt.Sprintf("%d", resp.SourceVersion))
			printer.PrintKeyValue("Target Version", fmt.Sprintf("%d", resp.TargetVersion))
			printer.PrintKeyValue("Nonce", base64.StdEncoding.EncodeToString(resp.Nonce))
			printer.PrintKeyValue("Output", cmdFlags.outputPath)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
