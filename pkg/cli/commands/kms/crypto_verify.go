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

// ErrSignatureRequired is returned when a signature is not provided
type ErrSignatureRequired struct{}

func (e ErrSignatureRequired) Error() string {
	return "signature is required (use --signature flag)"
}

// verifyFlags contains flags for the verify command
type verifyFlags struct {
	keyID         string
	inputPath     string
	signaturePath string
	signature     string
	hashAlgorithm string
	keyVersion    uint64
}

// newCryptoVerifyCommand creates the verify subcommand
func newCryptoVerifyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &verifyFlags{}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a digital signature",
		Long: `Verify a digital signature against data using a named key.

The verification is performed server-side using the public key associated
with the signing key. The message must be the same data that was signed,
and the hash algorithm must match.

The signature can be provided via:
  - --signature flag (base64 encoded string)
  - --signature-file flag (reads from file)

Input (message) can be provided via:
  - --input flag (reads from file)
  - stdin (pipe data to the command)

Examples:
  # Verify a signature from file
  platformctl kms crypto verify --key-id signing-key --input document.pdf --signature-file signature.sig

  # Verify with inline signature
  platformctl kms crypto verify --key-id ecdsa-key --input data.txt --signature "base64sig..."

  # Verify with specific key version
  platformctl kms crypto verify --key-id rsa-key --input msg.txt --signature-file sig.bin --key-version 2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCryptoVerify(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", "", "verification key ID (required)")
	cmd.Flags().StringVarP(&cmdFlags.inputPath, "input", "i", "", "input file path (message to verify)")
	cmd.Flags().StringVar(&cmdFlags.signaturePath, "signature-file", "", "signature file path")
	cmd.Flags().StringVar(&cmdFlags.signature, "signature", "", "base64 encoded signature")
	cmd.Flags().StringVar(&cmdFlags.hashAlgorithm, "hash", "sha256", "hash algorithm used during signing")
	cmd.Flags().Uint64Var(&cmdFlags.keyVersion, "key-version", 0, "specific key version (0 for auto-detect)")

	if err := cmd.MarkFlagRequired("key-id"); err != nil {
		panic(fmt.Sprintf("failed to mark key-id flag required: %v", err))
	}

	return cmd
}

// runCryptoVerify executes the verify operation
func runCryptoVerify(flags *cli.CommonFlags, cmdFlags *verifyFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := base.Client().KMS()
	if client == nil {
		return ErrCryptoClientNotInitialized{}
	}

	// Read message
	message, err := readInputData(cmdFlags.inputPath)
	if err != nil {
		return err
	}

	// Read signature
	var signatureBytes []byte
	if cmdFlags.signature != "" {
		signatureBytes, err = base64.StdEncoding.DecodeString(cmdFlags.signature)
		if err != nil {
			return ErrInvalidBase64{Field: "signature", Err: err}
		}
	} else if cmdFlags.signaturePath != "" {
		sigData, err := readInputData(cmdFlags.signaturePath)
		if err != nil {
			return err
		}
		// Try to decode as base64 first
		decoded, decErr := decodeBase64Input(sigData)
		if decErr != nil {
			// Use raw data
			signatureBytes = sigData
		} else {
			signatureBytes = decoded
		}
	} else {
		return ErrSignatureRequired{}
	}

	// Parse hash algorithm
	hashAlg, err := parseHashAlgorithm(cmdFlags.hashAlgorithm)
	if err != nil {
		return err
	}

	req := &platformv1.VerifyRequest{
		KeyId:         cmdFlags.keyID,
		Message:       message,
		Signature:     signatureBytes,
		HashAlgorithm: hashAlg,
		KeyVersion:    cmdFlags.keyVersion,
	}

	ctx := base.Context()
	resp, err := client.Verify(ctx, req)
	if err != nil {
		return ErrCryptoOperationFailed{Operation: "verify", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			KeyID      string `json:"key_id" yaml:"key_id"`
			KeyVersion uint64 `json:"key_version" yaml:"key_version"`
			Valid      bool   `json:"valid" yaml:"valid"`
			Timestamp  string `json:"timestamp" yaml:"timestamp"`
		}{
			KeyID:      resp.KeyId,
			KeyVersion: resp.KeyVersion,
			Valid:      resp.Valid,
			Timestamp:  formatTimestamp(resp.Timestamp),
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		if resp.Valid {
			printer.PrintSuccess("Signature verification PASSED")
		} else {
			printer.PrintError("Signature verification FAILED")
		}
		printer.PrintKeyValue("Key ID", resp.KeyId)
		printer.PrintKeyValue("Key Version", fmt.Sprintf("%d", resp.KeyVersion))
		printer.PrintKeyValue("Valid", fmt.Sprintf("%t", resp.Valid))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
