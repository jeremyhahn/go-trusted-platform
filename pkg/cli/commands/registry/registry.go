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

// Package registry provides CLI commands for the Trusted Registry.
// The Trusted Registry is a container registry that requires TPM-based
// host attestation for access control and supports encrypted image storage.
package registry

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the registry root command for Trusted Registry operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Trusted Registry operations",
		Long: `Manage container images in the Trusted Registry with TPM-based attestation.

The Trusted Registry provides secure container image storage with:
  - TPM-based host attestation for access control
  - Encrypted image storage using KMS-managed keys
  - Policy-based access control via OPA integration
  - Image signing and verification

Examples:
  # Push an image to the registry
  platformctl registry push myrepo/myimage:v1.0

  # Push with encryption
  platformctl registry push myrepo/myimage:v1.0 --encrypt --key-id my-encryption-key

  # Pull an image from the registry
  platformctl registry pull myrepo/myimage:v1.0

  # Pull and decrypt an encrypted image
  platformctl registry pull myrepo/myimage:v1.0 --decrypt

  # List images in a repository
  platformctl registry list --repository myrepo

  # List images with prefix filter
  platformctl registry list --prefix myrepo/myimage --limit 20

  # Inspect an image manifest
  platformctl registry inspect myrepo/myimage:v1.0

  # Delete an image
  platformctl registry delete myrepo/myimage:v1.0

  # Force delete without confirmation
  platformctl registry delete myrepo/myimage:v1.0 --force

  # Check registry status
  platformctl registry status`,
	}

	// Add subcommands
	cmd.AddCommand(NewPushCommand(getFlags))
	cmd.AddCommand(NewPullCommand(getFlags))
	cmd.AddCommand(NewListCommand(getFlags))
	cmd.AddCommand(NewDeleteCommand(getFlags))
	cmd.AddCommand(NewInspectCommand(getFlags))
	cmd.AddCommand(NewStatusCommand(getFlags))

	return cmd
}
