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

package container

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the container root command for container orchestration operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "container",
		Short: "Container orchestration operations",
		Long: `Manage containers with Trusted Computing attestation support.

The container subsystem provides comprehensive container lifecycle management including:
  - Create and configure containers with security policies
  - Start, stop, and remove containers
  - View container status
  - Attest container integrity using TPM measurements
  - Manage container networking and resources

Examples:
  # List all containers
  platformctl container list

  # Create a new container
  platformctl container create --name myapp --image nginx:latest

  # Start a container
  platformctl container start myapp

  # Attest container integrity
  platformctl container attest myapp --pcrs 0,1,2,3

  # Get container details
  platformctl container get myapp`,
	}

	// Add subcommands
	cmd.AddCommand(newCreateCommand(getFlags))
	cmd.AddCommand(newStartCommand(getFlags))
	cmd.AddCommand(newStopCommand(getFlags))
	cmd.AddCommand(newRemoveCommand(getFlags))
	cmd.AddCommand(newListCommand(getFlags))
	cmd.AddCommand(newAttestCommand(getFlags))
	cmd.AddCommand(newGetCommand(getFlags))

	return cmd
}
