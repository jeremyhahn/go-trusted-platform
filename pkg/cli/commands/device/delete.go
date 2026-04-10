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

package device

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// newDeleteCommand creates the delete subcommand for deleting a device
func newDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete device by ID",
		Long: `Delete a device by its ID.

WARNING: This operation is irreversible. The device and all its
associated data will be permanently removed.

Examples:
  # Delete device by ID
  platformctl device delete 123`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runDelete(flags, args[0])
		},
	}

	return cmd
}

// runDelete executes the delete command using the SDK client
func runDelete(flags *cli.CommonFlags, idStr string) error {
	// Validate ID
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return ErrInvalidDeviceID{ID: idStr}
	}

	// Create base command to get SDK client
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create device service client from the platform client
	deviceClient := device.NewClientFromGRPC(base.Client().Device())

	// Delete device
	ctx := base.Context()
	err = deviceClient.Delete(ctx, id)
	if err != nil {
		return ErrDeleteDeviceFailed{ID: id, Reason: err.Error()}
	}

	// Output based on format
	if flags.OutputFormat == cli.OutputFormatTable {
		fmt.Printf("Device %d deleted successfully\n", id)
		return nil
	}

	// JSON/YAML output
	output := buildDeleteOutput(id, true, "Device deleted successfully")
	return base.Output(output)
}

// buildDeleteOutput creates the JSON output structure for the delete command
func buildDeleteOutput(id uint64, success bool, message string) map[string]interface{} {
	return map[string]interface{}{
		"id":      id,
		"success": success,
		"message": message,
	}
}
