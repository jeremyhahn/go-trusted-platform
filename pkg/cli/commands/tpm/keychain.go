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

package tpm

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newXKMSCommand creates the xkms subcommand for TPM XKMS operations
func newXKMSCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "xkms",
		Short: "TPM XKMS operations",
		Long: `Perform TPM XKMS operations.

The xkms command manages TPM-backed cryptographic keys for various
purposes including CA, TLS, and HMAC operations.

Usage:
  platformctl tpm xkms [action] [cn] [store] [algorithm]

Actions:
  - generate: Generate a new key pair
  - delete: Delete a key pair
  - (default): Load and display an existing key

Arguments:
  - cn: Common name for the key
  - store: Key store type (software, pkcs11, tpm2)
  - algorithm: Key algorithm (rsa, ecdsa, ed25519)

Flags:
  --parent: Parent handle to seal against (default: 0x81000001)
  --parent-password: Parent key authorization password
  --parent-policy: Use platform PCR session as parent authorization
  --password: Key authorization password
  --ca: Key type is CA
  --tls: Key type is TLS
  --hmac: Key type is HMAC
  --policy: Attach platform policy digest to the key

Examples:
  # Generate an RSA key in TPM
  platformctl tpm xkms generate my-key tpm2 rsa

  # Generate an ECDSA CA key
  platformctl tpm xkms generate my-ca tpm2 ecdsa --ca

  # Delete a key
  platformctl tpm xkms delete my-key tpm2 rsa

  # Get key info
  platformctl tpm xkms info my-key tpm2 rsa`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ErrDaemonConnectionRequired{Operation: "xkms"}
		},
	}

	return cmd
}
