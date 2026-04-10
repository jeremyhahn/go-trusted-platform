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
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// newFindSerialCommand creates the find-serial subcommand for finding a device by serial
func newFindSerialCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "find-serial <serial>",
		Short: "Find device by serial number",
		Long: `Find a device by its serial number.

Returns detailed information about the device matching the serial number.

Examples:
  # Find device by serial
  platformctl device find-serial ABC123

  # Find device as JSON output
  platformctl device find-serial ABC123 -o json

  # Find device as YAML output
  platformctl device find-serial ABC123 -o yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runFindSerial(flags, args[0])
		},
	}

	return cmd
}

// runFindSerial executes the find-serial command using the SDK client
func runFindSerial(flags *cli.CommonFlags, serial string) error {
	// Validate serial number
	if serial == "" {
		return ErrSerialNumberRequired{}
	}

	// Create base command to get SDK client
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create device service client from the platform client
	deviceClient := device.NewClientFromGRPC(base.Client().Device())

	// Find device by serial
	ctx := base.Context()
	d, err := deviceClient.FindBySerial(ctx, serial)
	if err != nil {
		return ErrFindDeviceBySerialFailed{Serial: serial, Reason: err.Error()}
	}

	if d == nil {
		return ErrDeviceNotFoundBySerial{Serial: serial}
	}

	// Convert to output format
	detail := deviceDetail{
		ID:         d.Id,
		Serial:     d.Serial,
		Model:      d.Model,
		HashAlgoID: int(d.HashAlgoId),
		EKCert:     d.EkCert,
		AttestPub:  d.AttestPub,
		SigningPub: d.SigningPub,
	}

	// Output based on format
	if flags.OutputFormat == cli.OutputFormatTable {
		printDeviceDetails(base.Printer(), detail)
		return nil
	}

	// JSON/YAML output
	output := buildGetOutput(detail)
	return base.Output(output)
}
