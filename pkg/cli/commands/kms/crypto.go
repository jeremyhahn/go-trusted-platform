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
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrCryptoClientNotInitialized is returned when the crypto client is not initialized
type ErrCryptoClientNotInitialized struct{}

func (e ErrCryptoClientNotInitialized) Error() string {
	return "crypto client not initialized"
}

// ErrCryptoOperationFailed is returned when a crypto operation fails
type ErrCryptoOperationFailed struct {
	Operation string
	Err       error
}

func (e ErrCryptoOperationFailed) Error() string {
	return fmt.Sprintf("crypto %s operation failed: %v", e.Operation, e.Err)
}

// ErrInputRequired is returned when input is required but not provided
type ErrInputRequired struct {
	Operation string
}

func (e ErrInputRequired) Error() string {
	return fmt.Sprintf("%s requires input data (use --input flag or pipe via stdin)", e.Operation)
}

// ErrInvalidInputFile is returned when an input file cannot be read
type ErrInvalidInputFile struct {
	Path string
	Err  error
}

func (e ErrInvalidInputFile) Error() string {
	return fmt.Sprintf("failed to read input file %s: %v", e.Path, e.Err)
}

// ErrInvalidOutputFile is returned when an output file cannot be written
type ErrInvalidOutputFile struct {
	Path string
	Err  error
}

func (e ErrInvalidOutputFile) Error() string {
	return fmt.Sprintf("failed to write output file %s: %v", e.Path, e.Err)
}

// ErrKeyIDRequired is returned when a key ID is required but not provided
type ErrKeyIDRequired struct {
	Operation string
}

func (e ErrKeyIDRequired) Error() string {
	return fmt.Sprintf("%s requires a key ID", e.Operation)
}

// ErrInvalidHashAlgorithm is returned when an invalid hash algorithm is specified
type ErrInvalidHashAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidHashAlgorithm) Error() string {
	return fmt.Sprintf("invalid hash algorithm: %s", e.Algorithm)
}

// ErrInvalidAlgorithm is returned when an invalid algorithm is specified
type ErrInvalidAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidAlgorithm) Error() string {
	return fmt.Sprintf("invalid algorithm: %s", e.Algorithm)
}

// ErrInvalidBase64 is returned when base64 decoding fails
type ErrInvalidBase64 struct {
	Field string
	Err   error
}

func (e ErrInvalidBase64) Error() string {
	return fmt.Sprintf("invalid base64 encoding for %s: %v", e.Field, e.Err)
}

// ErrInvalidByteCount is returned when an invalid byte count is specified
type ErrInvalidByteCount struct {
	Count int32
}

func (e ErrInvalidByteCount) Error() string {
	return fmt.Sprintf("invalid byte count: %d (must be positive)", e.Count)
}

// NewCryptoCommand creates the crypto operations command group
func NewCryptoCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crypto",
		Short: "Cryptographic operations",
		Long: `Perform cryptographic operations using KMS-managed keys.

The crypto subsystem provides encryption as a service without exposing key material.
All operations are performed server-side with automatic key versioning support.

Operations:
  - encrypt/decrypt: Symmetric encryption using managed keys
  - sign/verify: Digital signatures with asymmetric keys
  - hmac: Generate and verify HMACs
  - hash: Compute cryptographic hashes
  - random: Generate cryptographically secure random bytes
  - rewrap: Re-encrypt data with latest key version
  - datakey: Generate data encryption keys for envelope encryption
  - batch: Perform multiple encrypt/decrypt operations

Examples:
  # Encrypt a file
  platformctl kms crypto encrypt --key-id mykey --input data.txt --output data.enc

  # Decrypt data from stdin
  cat data.enc | platformctl kms crypto decrypt --key-id mykey

  # Sign a message
  platformctl kms crypto sign --key-id signing-key --input message.txt

  # Generate random bytes
  platformctl kms crypto random --bytes 32`,
	}

	cmd.AddCommand(newCryptoEncryptCommand(getFlags))
	cmd.AddCommand(newCryptoDecryptCommand(getFlags))
	cmd.AddCommand(newCryptoRewrapCommand(getFlags))
	cmd.AddCommand(newCryptoBatchCommand(getFlags))
	cmd.AddCommand(newCryptoDataKeyCommand(getFlags))
	cmd.AddCommand(newCryptoSignCommand(getFlags))
	cmd.AddCommand(newCryptoVerifyCommand(getFlags))
	cmd.AddCommand(newCryptoHMACCommand(getFlags))
	cmd.AddCommand(newCryptoRandomCommand(getFlags))
	cmd.AddCommand(newCryptoHashCommand(getFlags))

	return cmd
}

// parseHashAlgorithm converts a string to SDK HashAlgorithm
func parseHashAlgorithm(alg string) (kmssvc.HashAlgorithm, error) {
	hashAlg, err := kmssvc.ParseHashAlgorithm(alg)
	if err != nil {
		return kmssvc.HashAlgorithmUnspecified, ErrInvalidHashAlgorithm{Algorithm: alg}
	}
	return hashAlg, nil
}

// formatHashAlgorithm converts an SDK HashAlgorithm to string
func formatHashAlgorithm(alg kmssvc.HashAlgorithm) string {
	return string(alg)
}

// readInputData reads input data from file or stdin
func readInputData(inputPath string) ([]byte, error) {
	if inputPath != "" {
		data, err := os.ReadFile(inputPath)
		if err != nil {
			return nil, ErrInvalidInputFile{Path: inputPath, Err: err}
		}
		return data, nil
	}

	// Check if stdin has data
	stat, err := os.Stdin.Stat()
	if err != nil {
		return nil, ErrInputRequired{Operation: "read"}
	}

	if (stat.Mode() & os.ModeCharDevice) != 0 {
		// stdin is a terminal, no piped data
		return nil, ErrInputRequired{Operation: "read"}
	}

	// Read from stdin
	reader := bufio.NewReader(os.Stdin)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read from stdin: %w", err)
	}

	if len(data) == 0 {
		return nil, ErrInputRequired{Operation: "read"}
	}

	return data, nil
}

// writeOutputData writes output data to file or stdout
func writeOutputData(outputPath string, data []byte, base64Encode bool) error {
	var output []byte
	if base64Encode {
		output = []byte(base64.StdEncoding.EncodeToString(data))
	} else {
		output = data
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, output, 0600); err != nil {
			return ErrInvalidOutputFile{Path: outputPath, Err: err}
		}
		return nil
	}

	// Write to stdout
	if _, err := os.Stdout.Write(output); err != nil {
		return fmt.Errorf("failed to write to stdout: %w", err)
	}

	// Add newline for terminal output
	if base64Encode {
		fmt.Println()
	}

	return nil
}

// decodeBase64Input decodes base64-encoded input
func decodeBase64Input(data []byte) ([]byte, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(decoded, data)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "input", Err: err}
	}
	return decoded[:n], nil
}
