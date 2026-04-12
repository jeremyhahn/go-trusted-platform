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

// randomFlags contains flags for the random command
type randomFlags struct {
	numBytes   int32
	outputPath string
	format     string
}

// newCryptoRandomCommand creates the random subcommand
func newCryptoRandomCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &randomFlags{}

	cmd := &cobra.Command{
		Use:   "random",
		Short: "Generate random bytes",
		Long: `Generate cryptographically secure random bytes.

The random bytes are generated using a cryptographically secure random number
generator (CSPRNG) provided by the KMS backend. This ensures high-quality
randomness suitable for cryptographic operations.

Output formats:
  - base64: Base64 encoded (default, safe for terminal)
  - hex: Hexadecimal encoded
  - raw: Raw binary bytes

Common use cases:
  - Generating encryption keys
  - Creating initialization vectors (IVs) or nonces
  - Salt values for password hashing
  - Session tokens or identifiers

Examples:
  # Generate 32 random bytes (256 bits)
  platformctl kms crypto random --bytes 32

  # Generate random bytes in hex format
  platformctl kms crypto random --bytes 16 --format hex

  # Save raw random bytes to file
  platformctl kms crypto random --bytes 64 --format raw --output random.bin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCryptoRandom(flags, cmdFlags)
		},
	}

	cmd.Flags().Int32Var(&cmdFlags.numBytes, "bytes", 32, "number of random bytes to generate")
	cmd.Flags().StringVarP(&cmdFlags.outputPath, "output", "o", "", "output file path")
	cmd.Flags().StringVar(&cmdFlags.format, "format", "base64", "output format (base64, hex, raw)")

	return cmd
}

// runCryptoRandom executes the random bytes generation
func runCryptoRandom(flags *cli.CommonFlags, cmdFlags *randomFlags) error {
	if cmdFlags.numBytes <= 0 {
		return ErrInvalidByteCount{Count: cmdFlags.numBytes}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	ctx := base.Context()
	resp, err := sdkClient.GenerateRandomDomain(ctx, cmdFlags.numBytes)
	if err != nil {
		return ErrCryptoOperationFailed{Operation: "generate random", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			RandomBytes string `json:"random_bytes" yaml:"random_bytes"`
			NumBytes    int    `json:"num_bytes" yaml:"num_bytes"`
			Format      string `json:"format" yaml:"format"`
			Timestamp   string `json:"timestamp" yaml:"timestamp"`
		}{
			RandomBytes: formatRandomBytes(resp.RandomBytes, cmdFlags.format),
			NumBytes:    len(resp.RandomBytes),
			Format:      cmdFlags.format,
			Timestamp:   formatTimestamp(resp.Timestamp),
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		// Handle output based on format
		switch cmdFlags.format {
		case "raw":
			if err := writeOutputData(cmdFlags.outputPath, resp.RandomBytes, false); err != nil {
				return err
			}
		case "hex":
			hexStr := hex.EncodeToString(resp.RandomBytes)
			if cmdFlags.outputPath != "" {
				if err := writeOutputData(cmdFlags.outputPath, []byte(hexStr), false); err != nil {
					return err
				}
			} else {
				fmt.Println(hexStr)
			}
		default: // base64
			if err := writeOutputData(cmdFlags.outputPath, resp.RandomBytes, true); err != nil {
				return err
			}
		}

		// Show metadata if writing to file
		if cmdFlags.outputPath != "" {
			printer.PrintSuccess("Random bytes generated")
			printer.PrintKeyValue("Bytes", fmt.Sprintf("%d", len(resp.RandomBytes)))
			printer.PrintKeyValue("Format", cmdFlags.format)
			printer.PrintKeyValue("Output", cmdFlags.outputPath)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// formatRandomBytes formats random bytes according to the specified format
func formatRandomBytes(data []byte, format string) string {
	switch format {
	case "hex":
		return hex.EncodeToString(data)
	case "raw":
		return string(data)
	default: // base64
		return base64.StdEncoding.EncodeToString(data)
	}
}
