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

package bootstrap

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewSecretsCommand creates the secrets subcommand group for bootstrap operations
func NewSecretsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Manage bootstrap secrets",
		Long: `Manage secret resolution and migration during platform bootstrap.

This command group provides operations for:
  - Migrating plaintext secrets from configuration files to KMS
  - Checking the status of secret URIs in configuration
  - Verifying that all secrets can be resolved
  - Testing resolution of individual secret URIs

Supported secret URI schemes:
  - kms://       - Local KMS-managed secrets
  - remote-kms:// - Remote KMS-managed secrets
  - env://       - Environment variable references
  - autogen://   - Auto-generated secrets
  - encrypted:// - Encrypted secrets (decrypted at runtime)

Examples:
  # Migrate secrets to KMS
  platformctl bootstrap secrets migrate --config /etc/trusted-platform/config.yaml

  # Show secret resolution status
  platformctl bootstrap secrets status --config /etc/trusted-platform/config.yaml

  # Verify all secrets
  platformctl bootstrap secrets verify --config /etc/trusted-platform/config.yaml

  # Resolve a single URI
  platformctl bootstrap secrets resolve "kms://config/db/password"`,
	}

	// Add subcommands
	cmd.AddCommand(newSecretsMigrateCommand(getFlags))
	cmd.AddCommand(newSecretsStatusCommand(getFlags))
	cmd.AddCommand(newSecretsVerifyCommand(getFlags))
	cmd.AddCommand(newSecretsResolveCommand(getFlags))

	return cmd
}
