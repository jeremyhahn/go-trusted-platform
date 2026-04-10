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

package bmc

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the bmc root command for BMC operations.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bmc",
		Short: "Baseboard Management Controller operations",
		Long: `Manage Baseboard Management Controller (BMC) operations via platformd.

The bmc subsystem provides tools for:
  - Power management (on, off, reset, cycle, status)
  - Boot device configuration
  - Virtual media management (mount/unmount ISO)
  - Sensor readings
  - System information
  - Bare metal provisioning

All commands communicate with platformd REST API and require
--server-url and --profile-id flags.

Examples:
  # Check power status
  platformctl bmc power-status \
    --server-url https://platform:8443 \
    --profile-id server-01

  # Power on a server
  platformctl bmc power-on \
    --server-url https://platform:8443 \
    --profile-id server-01

  # Mount an ISO for virtual media boot
  platformctl bmc mount-iso \
    --server-url https://platform:8443 \
    --profile-id server-01 \
    --iso-url https://images.example.com/os.iso

  # Get system information
  platformctl bmc system-info \
    --server-url https://platform:8443 \
    --profile-id server-01`,
	}

	cmd.AddCommand(newPowerOnCommand(getFlags))
	cmd.AddCommand(newPowerOffCommand(getFlags))
	cmd.AddCommand(newPowerResetCommand(getFlags))
	cmd.AddCommand(newPowerCycleCommand(getFlags))
	cmd.AddCommand(newPowerStatusCommand(getFlags))
	cmd.AddCommand(newSetBootDeviceCommand(getFlags))
	cmd.AddCommand(newGetBootDeviceCommand(getFlags))
	cmd.AddCommand(newMountISOCommand(getFlags))
	cmd.AddCommand(newUnmountISOCommand(getFlags))
	cmd.AddCommand(newMediaStatusCommand(getFlags))
	cmd.AddCommand(newSensorsCommand(getFlags))
	cmd.AddCommand(newSystemInfoCommand(getFlags))
	cmd.AddCommand(newProvisionCommand(getFlags))
	cmd.AddCommand(newConsoleCommand(getFlags))

	return cmd
}
