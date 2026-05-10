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

// Package encrypt provides the platformctl encrypt command for encrypting
// secrets into encrypted:// URIs for use in config files.
package encrypt

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config/secrets"
	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
)

// DefaultKeyID is the well-known KMS key identifier used for encrypting
// platform configuration values.
const DefaultKeyID = "platform-config-key"

// encryptFlags contains flags for the encrypt command.
type encryptFlags struct {
	value string
	file  string
	keyID string
}

// NewCommand creates the top-level encrypt command for generating encrypted://
// URIs from secret values. The output can be pasted directly into YAML config
// files.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &encryptFlags{}

	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a secret value into an encrypted:// URI",
		Long: `Encrypt a secret value using the platform KMS and output an encrypted://
URI that can be stored in configuration files.

The encryption uses AES-256-GCM with the platform config-encryption key.
The output is a single encrypted:// URI string suitable for copy-pasting
into YAML configuration files.

Input is provided via exactly one of:
  --value   A literal secret string
  --file    Path to a file containing the secret

Examples:
  # Encrypt a literal value
  platformctl encrypt --value "mysecret"

  # Encrypt a file's contents
  platformctl encrypt --file /etc/switch-password.txt

  # Use a custom KMS key
  platformctl encrypt --value "mysecret" --key-id my-custom-key`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runEncrypt(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.value, "value", "", "secret value to encrypt (mutually exclusive with --file)")
	cmd.Flags().StringVar(&cmdFlags.file, "file", "", "path to file containing secret to encrypt (mutually exclusive with --value)")
	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", DefaultKeyID, "KMS key ID to use for encryption")

	return cmd
}

// runEncrypt validates flags, connects to the platform daemon, encrypts the
// plaintext via the KMS, and writes the encrypted:// URI to stdout.
func runEncrypt(flags *cli.CommonFlags, cmdFlags *encryptFlags) error {
	// Validate mutually exclusive flags
	if cmdFlags.value == "" && cmdFlags.file == "" {
		return ErrValueOrFileRequired{}
	}
	if cmdFlags.value != "" && cmdFlags.file != "" {
		return ErrValueAndFileMutuallyExclusive{}
	}

	// Read plaintext
	plaintext, err := readPlaintext(cmdFlags)
	if err != nil {
		return err
	}

	// Connect to platform daemon
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrConnectionFailed{Cause: err}
	}
	defer base.Close()

	// Create KMS client from the platform SDK connection
	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	ctx := base.Context()
	keyID := cmdFlags.keyID

	// Build the EncryptFunc closure for the secrets.Encrypt helper.
	// The KMS EncryptDomain returns separate Nonce and Ciphertext fields.
	// The encrypted:// wire format expects nonce || ciphertext (where
	// ciphertext already includes the GCM authentication tag).
	encryptFn := func(ctx context.Context, plain []byte) ([]byte, error) {
		result, encErr := sdkClient.EncryptDomain(ctx, keyID, plain, nil, nil)
		if encErr != nil {
			return nil, encErr
		}
		// Concatenate nonce || ciphertext to match the resolver's expected format
		blob := make([]byte, 0, len(result.Nonce)+len(result.Ciphertext))
		blob = append(blob, result.Nonce...)
		blob = append(blob, result.Ciphertext...)
		return blob, nil
	}

	uri, err := secrets.Encrypt(ctx, plaintext, encryptFn)
	if err != nil {
		return ErrEncryptionFailed{Cause: err}
	}

	// Output only the URI -- no JSON wrapping, no headers
	fmt.Fprintln(os.Stdout, uri)
	return nil
}

// readPlaintext reads the secret plaintext from either the --value flag or the
// --file flag. Exactly one must be set (validated by the caller).
func readPlaintext(cmdFlags *encryptFlags) ([]byte, error) {
	if cmdFlags.value != "" {
		return []byte(cmdFlags.value), nil
	}

	data, err := os.ReadFile(cmdFlags.file)
	if err != nil {
		return nil, ErrReadSecretFile{Path: cmdFlags.file, Cause: err}
	}
	return data, nil
}
