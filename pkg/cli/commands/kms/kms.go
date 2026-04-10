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
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the kms root command for Key Management System operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kms",
		Short: "Key Management System operations",
		Long: `Manage cryptographic keys, secrets, and perform encryption operations.

The KMS subsystem provides comprehensive key lifecycle management including:
  - Key generation, rotation, and revocation
  - Data Encryption Keys (DEK) management
  - Secrets storage and retrieval
  - Cryptographic operations (encrypt, decrypt, sign, verify, etc.)

Examples:
  # List all keys
  platformctl kms key list

  # Generate a new key
  platformctl kms key generate --algorithm RSA --size 4096

  # Encrypt data
  platformctl kms crypto encrypt --key-id mykey --input data.txt

  # Manage secrets
  platformctl kms secrets set --name api-key --value secret123

  # Check KMS status
  platformctl kms status`,
	}

	// Add subcommands
	cmd.AddCommand(NewKeyCommand(getFlags))
	cmd.AddCommand(NewDEKCommand(getFlags))
	cmd.AddCommand(NewSecretsCommand(getFlags))
	cmd.AddCommand(NewStatusCommand(getFlags))
	cmd.AddCommand(NewCryptoCommand(getFlags))

	return cmd
}
