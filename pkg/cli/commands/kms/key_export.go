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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrKeyExportNotImplemented is returned when the key export command is not yet implemented
type ErrKeyExportNotImplemented struct{}

func (e ErrKeyExportNotImplemented) Error() string {
	return "key export is not yet implemented in the platform KMS service"
}

// ErrKeyExportFailed is returned when key export fails
type ErrKeyExportFailed struct {
	KeyID string
	Err   error
}

func (e ErrKeyExportFailed) Error() string {
	return fmt.Sprintf("failed to export key %s: %v", e.KeyID, e.Err)
}

// ErrKeyNotExportable is returned when attempting to export a non-exportable key
type ErrKeyNotExportable struct {
	KeyID string
}

func (e ErrKeyNotExportable) Error() string {
	return fmt.Sprintf("key %s is not marked as exportable", e.KeyID)
}

// ErrWriteExportedKeyFailed is returned when writing exported key material fails
type ErrWriteExportedKeyFailed struct {
	Path string
	Err  error
}

func (e ErrWriteExportedKeyFailed) Error() string {
	return fmt.Sprintf("failed to write exported key to %s: %v", e.Path, e.Err)
}

// newKeyExportCommand creates the key export subcommand
func newKeyExportCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var wrappingKeyID string
	var wrappingAlgorithm string
	var exportFormat string
	var version uint64
	var outputFile string

	cmd := &cobra.Command{
		Use:   "export <key-id>",
		Short: "Export a wrapped key (not yet implemented)",
		Long: `Export a key wrapped with another key for secure transport.

NOTE: This command is not yet implemented in the platform KMS service.

The exported key material is encrypted with the specified wrapping key,
ensuring the key material is never exposed in plaintext. Only keys
marked as exportable can be exported.

Wrapping Algorithms:
  - aes-kw: RFC 3394 AES Key Wrap
  - aes-kwp: RFC 5649 AES Key Wrap with Padding
  - aes-gcm: AES-GCM envelope encryption
  - rsa-oaep-sha256: RSA-OAEP with SHA-256
  - rsa-oaep-sha384: RSA-OAEP with SHA-384
  - rsa-oaep-sha512: RSA-OAEP with SHA-512
  - ecdh-es-a256kw: ECDH-ES+A256KW

Export Formats:
  - raw: Raw binary format (default)
  - jwk: JSON Web Key format
  - pem: PEM-encoded format

Examples:
  # Export a key wrapped with another key
  platformctl kms key export my-key --wrapping-key wrap-key-id

  # Export with specific algorithm and format
  platformctl kms key export my-key --wrapping-key wrap-key-id \
    --wrapping-algorithm rsa-oaep-sha256 --format pem

  # Export specific version to a file
  platformctl kms key export my-key --wrapping-key wrap-key-id \
    --version 2 --output-file exported-key.enc`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrKeyExportNotImplemented{}
		},
	}

	cmd.Flags().StringVar(&wrappingKeyID, "wrapping-key", "", "ID of the key to wrap the exported key (required)")
	cmd.Flags().StringVar(&wrappingAlgorithm, "wrapping-algorithm", "aes-kw", "wrapping algorithm")
	cmd.Flags().StringVar(&exportFormat, "format", "raw", "export format (raw, jwk, pem)")
	cmd.Flags().Uint64VarP(&version, "version", "v", 0, "specific key version (0 for latest)")
	cmd.Flags().StringVarP(&outputFile, "output-file", "o", "", "write wrapped key to file")

	return cmd
}
