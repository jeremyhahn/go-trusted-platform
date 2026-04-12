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
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// hashFlags contains flags for the hash command
type hashFlags struct {
	inputPath  string
	outputPath string
	algorithm  string
	format     string
}

// newCryptoHashCommand creates the hash subcommand
func newCryptoHashCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &hashFlags{}

	cmd := &cobra.Command{
		Use:   "hash",
		Short: "Compute a cryptographic hash",
		Long: `Compute a cryptographic hash of data.

Supported algorithms:
  SHA-2 family:
    - sha256: SHA-256 (256-bit output)
    - sha384: SHA-384 (384-bit output)
    - sha512: SHA-512 (512-bit output)

  SHA-3 family:
    - sha3-256: SHA3-256 (256-bit output)
    - sha3-384: SHA3-384 (384-bit output)
    - sha3-512: SHA3-512 (512-bit output)

  BLAKE2:
    - blake2b-256: BLAKE2b with 256-bit output
    - blake2b-512: BLAKE2b with 512-bit output

Output formats:
  - hex: Hexadecimal encoded (default)
  - base64: Base64 encoded

Input can be provided via:
  - --input flag (reads from file)
  - stdin (pipe data to the command)

Examples:
  # Compute SHA-256 hash of a file
  platformctl kms crypto hash --input document.pdf

  # Compute SHA3-256 hash
  platformctl kms crypto hash --input data.txt --algorithm sha3-256

  # Hash from stdin with base64 output
  echo "message" | platformctl kms crypto hash --format base64

  # Save hash to file
  platformctl kms crypto hash --input large-file.bin --output hash.txt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCryptoHash(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVarP(&cmdFlags.inputPath, "input", "i", "", "input file path")
	cmd.Flags().StringVarP(&cmdFlags.outputPath, "output", "o", "", "output file path")
	cmd.Flags().StringVar(&cmdFlags.algorithm, "algorithm", "sha256", "hash algorithm")
	cmd.Flags().StringVar(&cmdFlags.format, "format", "hex", "output format (hex, base64)")

	return cmd
}

// runCryptoHash executes the hash computation
func runCryptoHash(flags *cli.CommonFlags, cmdFlags *hashFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	// Read input data
	data, err := readInputData(cmdFlags.inputPath)
	if err != nil {
		return err
	}

	// Parse algorithm
	hashAlg, err := parseHashAlgorithm(cmdFlags.algorithm)
	if err != nil {
		return err
	}

	ctx := base.Context()
	resp, err := sdkClient.HashDomain(ctx, data, hashAlg)
	if err != nil {
		return ErrCryptoOperationFailed{Operation: "hash", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			Algorithm string `json:"algorithm" yaml:"algorithm"`
			Hash      string `json:"hash" yaml:"hash"`
			Format    string `json:"format" yaml:"format"`
			Size      int    `json:"size_bytes" yaml:"size_bytes"`
			Timestamp string `json:"timestamp" yaml:"timestamp"`
		}{
			Algorithm: formatHashAlgorithm(resp.Algorithm),
			Hash:      formatHashOutput(resp.Hash, cmdFlags.format),
			Format:    cmdFlags.format,
			Size:      len(resp.Hash),
			Timestamp: formatTimestamp(resp.Timestamp),
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		// Format hash based on output format
		hashStr := formatHashOutput(resp.Hash, cmdFlags.format)

		// Write to output
		if cmdFlags.outputPath != "" {
			if err := writeOutputData(cmdFlags.outputPath, []byte(hashStr), false); err != nil {
				return err
			}
			printer.PrintSuccess("Hash computed")
			printer.PrintKeyValue("Algorithm", formatHashAlgorithm(resp.Algorithm))
			printer.PrintKeyValue("Hash", hashStr)
			printer.PrintKeyValue("Output", cmdFlags.outputPath)
		} else {
			// Print to stdout
			fmt.Println(hashStr)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// formatHashOutput formats hash bytes according to the specified format
func formatHashOutput(data []byte, format string) string {
	switch format {
	case "base64":
		return base64.StdEncoding.EncodeToString(data)
	default: // hex
		return hex.EncodeToString(data)
	}
}
