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

// Package provision provides CLI commands for the device provisioning workflow,
// including config fetching and interactive QR-based provisioning.
package provision

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the provision root command for device provisioning operations.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provision",
		Short: "Device provisioning operations",
		Long: `Manage device provisioning during ISO boot.

The provision subsystem provides tools for:
  - Fetching platform configuration from a provisioning server
  - Interactive QR code-based provisioning for manual approval

These commands are used by platformctl-static during ISO boot to
fetch configuration and handle interactive provisioning flows.

Examples:
  # Fetch config from provisioning server
  platformctl provision fetch-config \
    --server-url https://platform:8443 \
    --ek-serial ABC123 \
    --mac 00:11:22:33:44:55 \
    --eab-kid key-id \
    --eab-hmac base64-hmac \
    --output /tmp/platform-config.yaml

  # Interactive QR provisioning with timeout
  platformctl provision interactive \
    --server-url https://platform:8443 \
    --ek-serial ABC123 \
    --mac 00:11:22:33:44:55 \
    --eab-kid key-id \
    --eab-hmac base64-hmac \
    --output /tmp/platform-config.yaml \
    --timeout 600`,
	}

	cmd.AddCommand(newFetchConfigCommand(getFlags))
	cmd.AddCommand(newInteractiveCommand(getFlags))

	return cmd
}
