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

// ErrKeyImportNotImplemented is returned when the key import command is not yet implemented
type ErrKeyImportNotImplemented struct{}

func (e ErrKeyImportNotImplemented) Error() string {
	return "key import is not yet implemented in the platform KMS service"
}

// ErrKeyImportFailed is returned when key import fails
type ErrKeyImportFailed struct {
	Err error
}

func (e ErrKeyImportFailed) Error() string {
	return fmt.Sprintf("failed to import key: %v", e.Err)
}

// ErrInvalidKeyMaterial is returned when key material is invalid
type ErrInvalidKeyMaterial struct {
	Reason string
}

func (e ErrInvalidKeyMaterial) Error() string {
	return fmt.Sprintf("invalid key material: %s", e.Reason)
}

// ErrKeyMaterialReadFailed is returned when reading key material from file fails
type ErrKeyMaterialReadFailed struct {
	Path string
	Err  error
}

func (e ErrKeyMaterialReadFailed) Error() string {
	return fmt.Sprintf("failed to read key material from %s: %v", e.Path, e.Err)
}

// ErrInvalidWrappingAlgorithm is returned when an invalid wrapping algorithm is specified
type ErrInvalidWrappingAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidWrappingAlgorithm) Error() string {
	return fmt.Sprintf("invalid wrapping algorithm: %s", e.Algorithm)
}

// ErrInvalidExportFormat is returned when an invalid export format is specified
type ErrInvalidExportFormat struct {
	Format string
}

func (e ErrInvalidExportFormat) Error() string {
	return fmt.Sprintf("invalid export format: %s", e.Format)
}

// newKeyImportCommand creates the key import subcommand
func newKeyImportCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var algorithm string
	var purpose string
	var exportable bool
	var deletionProtection bool
	var name string
	var description string
	var wrappingKeyID string
	var keyFile string
	var base64Material string

	cmd := &cobra.Command{
		Use:   "import <key-id>",
		Short: "Import an external key (not yet implemented)",
		Long: `Import an externally generated key into the KMS.

NOTE: This command is not yet implemented in the platform KMS service.

The key material can be provided either as a base64-encoded string or from a file.
If a wrapping key is specified, the key material must be encrypted with that wrapping key.

Examples:
  # Import a key from base64-encoded material
  platformctl kms key import my-key --algorithm aes-256-gcm --material "base64encodedkey..."

  # Import a key from a file
  platformctl kms key import my-key --algorithm rsa-4096 --key-file /path/to/key.pem

  # Import a wrapped key
  platformctl kms key import my-key --algorithm aes-256-gcm --key-file key.enc --wrapping-key wrap-key-id`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrKeyImportNotImplemented{}
		},
	}

	cmd.Flags().StringVarP(&algorithm, "algorithm", "a", "aes-256-gcm", "key algorithm")
	cmd.Flags().StringVarP(&purpose, "purpose", "p", "encrypt", "key purpose (comma-separated: encrypt, sign, wrap-key, etc.)")
	cmd.Flags().BoolVarP(&exportable, "exportable", "e", false, "allow key export")
	cmd.Flags().BoolVar(&deletionProtection, "deletion-protection", false, "enable deletion protection")
	cmd.Flags().StringVarP(&name, "name", "n", "", "human-readable key name")
	cmd.Flags().StringVarP(&description, "description", "d", "", "key description")
	cmd.Flags().StringVar(&wrappingKeyID, "wrapping-key", "", "ID of the key used to wrap the imported key material")
	cmd.Flags().StringVarP(&keyFile, "key-file", "f", "", "path to file containing key material")
	cmd.Flags().StringVarP(&base64Material, "material", "m", "", "base64-encoded key material")

	return cmd
}
