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

// Package bootstrap provides CLI commands for platform bootstrap operations,
// including secret migration, configuration management, trust establishment,
// and PXE network bootstrap orchestration.
package bootstrap

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the bootstrap root command for platform initialization operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Platform bootstrap operations",
		Long: `Manage platform bootstrap and initialization operations.

The bootstrap subsystem provides tools for:
  - Migrating plaintext secrets to KMS-managed secrets
  - Verifying secret resolution across all configured resolvers
  - Checking secret status and availability
  - Testing secret URI resolution
  - Bootstrapping trust with the platform CA
  - PXE network bootstrap: discover, deploy, provision, and teardown

Examples:
  # Migrate plaintext secrets to KMS
  platformctl bootstrap secrets migrate --config /etc/trusted-platform/config.yaml

  # Check status of all secret URIs in configuration
  platformctl bootstrap secrets status --config /etc/trusted-platform/config.yaml

  # Verify all secrets can be resolved
  platformctl bootstrap secrets verify --config /etc/trusted-platform/config.yaml

  # Test resolution of a single secret URI
  platformctl bootstrap secrets resolve "kms://config/db/password"

  # Bootstrap trust with the platform
  platformctl bootstrap trust --server-url https://platform:8443 --strategy auto

  # Run full PXE network bootstrap
  platformctl bootstrap run --config bootstrap.yaml

  # Discover node MAC addresses only
  platformctl bootstrap discover --config bootstrap.yaml

  # Deploy bootstrap container
  platformctl bootstrap deploy --config bootstrap.yaml

  # Check node health status
  platformctl bootstrap status --config bootstrap.yaml

  # Teardown bootstrap container
  platformctl bootstrap teardown --config bootstrap.yaml`,
	}

	// Add subcommands
	cmd.AddCommand(NewSecretsCommand(getFlags))
	cmd.AddCommand(NewTrustCommand(getFlags))
	cmd.AddCommand(newRunCommand(getFlags))
	cmd.AddCommand(newDiscoverCommand(getFlags))
	cmd.AddCommand(newDeployCommand(getFlags))
	cmd.AddCommand(newStatusCommand(getFlags))
	cmd.AddCommand(newTeardownCommand(getFlags))

	return cmd
}
