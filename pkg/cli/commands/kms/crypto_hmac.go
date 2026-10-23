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

// ErrHMACRequired is returned when an HMAC is not provided
type ErrHMACRequired struct{}

func (e ErrHMACRequired) Error() string {
	return "HMAC is required (use --hmac flag)"
}

// hmacGenerateFlags contains flags for the generate HMAC command
type hmacGenerateFlags struct {
	keyID         string
	inputPath     string
	outputPath    string
	hashAlgorithm string
	base64Out     bool
}

// hmacVerifyFlags contains flags for the verify HMAC command
type hmacVerifyFlags struct {
	keyID         string
	inputPath     string
	hmacPath      string
	hmac          string
	hashAlgorithm string
	keyVersion    uint64
}

// newCryptoHMACCommand creates the HMAC operations command group
func newCryptoHMACCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hmac",
		Short: "HMAC operations",
		Long: `Generate and verify Hash-based Message Authentication Codes (HMACs).

HMACs provide both data integrity and authentication. They use a symmetric key
combined with a hash function to produce a fixed-size authentication tag.

The HMAC key must be an HMAC-type key (hmac-sha256, hmac-sha384, or hmac-sha512).
The hash algorithm should match the key type for optimal security.

Commands:
  generate: Generate an HMAC for data
  verify:   Verify an HMAC against data

Examples:
  # Generate HMAC
  platformctl kms crypto hmac generate --key-id hmac-key --input data.txt

  # Verify HMAC
  platformctl kms crypto hmac verify --key-id hmac-key --input data.txt --hmac "base64hmac..."`,
	}

	cmd.AddCommand(newHMACGenerateCommand(getFlags))
	cmd.AddCommand(newHMACVerifyCommand(getFlags))

	return cmd
}

// newHMACGenerateCommand creates the generate HMAC subcommand
func newHMACGenerateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &hmacGenerateFlags{}

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate an HMAC",
		Long: `Generate a Hash-based Message Authentication Code (HMAC) for data.

The HMAC is computed server-side using the specified key. The result can be
used to verify data integrity and authenticity later.

Input can be provided via:
  - --input flag (reads from file)
  - stdin (pipe data to the command)

Examples:
  # Generate HMAC for a file
  platformctl kms crypto hmac generate --key-id hmac-key --input data.txt --output data.hmac

  # Generate HMAC with specific hash algorithm
  platformctl kms crypto hmac generate --key-id hmac-key --input data.txt --hash sha384

  # Generate HMAC from stdin
  echo "message" | platformctl kms crypto hmac generate --key-id hmac-key`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runHMACGenerate(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", "", "HMAC key ID (required)")
	cmd.Flags().StringVarP(&cmdFlags.inputPath, "input", "i", "", "input file path")
	cmd.Flags().StringVarP(&cmdFlags.outputPath, "output", "o", "", "output file for HMAC")
	cmd.Flags().StringVar(&cmdFlags.hashAlgorithm, "hash", "sha256", "hash algorithm")
	cmd.Flags().BoolVar(&cmdFlags.base64Out, "base64", true, "base64 encode output")

	if err := cmd.MarkFlagRequired("key-id"); err != nil {
		panic(fmt.Sprintf("failed to mark key-id flag required: %v", err))
	}

	return cmd
}

// newHMACVerifyCommand creates the verify HMAC subcommand
func newHMACVerifyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &hmacVerifyFlags{}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an HMAC",
		Long: `Verify a Hash-based Message Authentication Code (HMAC) against data.

The verification is performed server-side using the specified key. This confirms
both the integrity and authenticity of the data.

The HMAC can be provided via:
  - --hmac flag (base64 encoded string)
  - --hmac-file flag (reads from file)

Input (message) can be provided via:
  - --input flag (reads from file)
  - stdin (pipe data to the command)

Examples:
  # Verify HMAC from file
  platformctl kms crypto hmac verify --key-id hmac-key --input data.txt --hmac-file data.hmac

  # Verify with inline HMAC
  platformctl kms crypto hmac verify --key-id hmac-key --input data.txt --hmac "base64hmac..."

  # Verify with specific key version
  platformctl kms crypto hmac verify --key-id hmac-key --input data.txt --hmac-file data.hmac --key-version 2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runHMACVerify(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", "", "HMAC key ID (required)")
	cmd.Flags().StringVarP(&cmdFlags.inputPath, "input", "i", "", "input file path")
	cmd.Flags().StringVar(&cmdFlags.hmacPath, "hmac-file", "", "HMAC file path")
	cmd.Flags().StringVar(&cmdFlags.hmac, "hmac", "", "base64 encoded HMAC")
	cmd.Flags().StringVar(&cmdFlags.hashAlgorithm, "hash", "sha256", "hash algorithm")
	cmd.Flags().Uint64Var(&cmdFlags.keyVersion, "key-version", 0, "specific key version")

	if err := cmd.MarkFlagRequired("key-id"); err != nil {
		panic(fmt.Sprintf("failed to mark key-id flag required: %v", err))
	}

	return cmd
}

// runHMACGenerate executes the generate HMAC operation
func runHMACGenerate(flags *cli.CommonFlags, cmdFlags *hmacGenerateFlags) error {
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
	resp, err := sdkClient.HMACDomain(ctx, cmdFlags.keyID, message, hashAlg)
	if err != nil {
		return ErrCryptoOperationFailed{Operation: "generate HMAC", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			KeyID         string `json:"key_id" yaml:"key_id"`
			KeyVersion    uint64 `json:"key_version" yaml:"key_version"`
			HMAC          string `json:"hmac" yaml:"hmac"`
			HashAlgorithm string `json:"hash_algorithm" yaml:"hash_algorithm"`
			Timestamp     string `json:"timestamp" yaml:"timestamp"`
		}{
			KeyID:         resp.KeyID,
			KeyVersion:    resp.KeyVersion,
			HMAC:          base64.StdEncoding.EncodeToString(resp.HMAC),
			HashAlgorithm: formatHashAlgorithm(resp.HashAlgorithm),
			Timestamp:     formatTimestamp(resp.Timestamp),
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		// Write HMAC to output
		if err := writeOutputData(cmdFlags.outputPath, resp.HMAC, cmdFlags.base64Out); err != nil {
			return err
		}

		// Show metadata if writing to file
		if cmdFlags.outputPath != "" {
			printer.PrintSuccess("HMAC generated successfully")
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

// runHMACVerify executes the verify HMAC operation
func runHMACVerify(flags *cli.CommonFlags, cmdFlags *hmacVerifyFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	// Read message
	message, err := readInputData(cmdFlags.inputPath)
	if err != nil {
		return err
	}

	// Read HMAC
	var hmacBytes []byte
	switch {
	case cmdFlags.hmac != "":
		hmacBytes, err = base64.StdEncoding.DecodeString(cmdFlags.hmac)
		if err != nil {
			return ErrInvalidBase64{Field: "hmac", Err: err}
		}
	case cmdFlags.hmacPath != "":
		hmacData, err := readInputData(cmdFlags.hmacPath)
		if err != nil {
			return err
		}
		// Try to decode as base64 first
		decoded, decErr := decodeBase64Input(hmacData)
		if decErr != nil {
			// Use raw data
			hmacBytes = hmacData
		} else {
			hmacBytes = decoded
		}
	default:
		return ErrHMACRequired{}
	}

	// Parse hash algorithm
	hashAlg, err := parseHashAlgorithm(cmdFlags.hashAlgorithm)
	if err != nil {
		return err
	}

	ctx := base.Context()
	resp, err := sdkClient.VerifyHMACDomain(ctx, cmdFlags.keyID, message, hmacBytes, hashAlg, cmdFlags.keyVersion)
	if err != nil {
		return ErrCryptoOperationFailed{Operation: "verify HMAC", Err: err}
	}

	return printVerifyResult(base.Printer(), flags.OutputFormat, "HMAC", verifyResult{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  formatTimestamp(resp.Timestamp),
	})
}
