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
	"strconv"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// newGetCommand creates the get subcommand for retrieving a device by ID
func newGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Get device by ID",
		Long: `Retrieve a device by its ID.

Returns detailed information about the device including:
  - Device ID
  - Serial number
  - Model
  - Hash algorithm
  - EK certificate (if available)
  - Attestation public key (if available)
  - Signing public key (if available)

Examples:
  # Get device in table format
  platformctl device get 123

  # Get device as JSON
  platformctl device get 123 -o json

  # Get device as YAML
  platformctl device get 123 -o yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGet(flags, args[0])
		},
	}

	return cmd
}

// runGet executes the get command using the SDK client
func runGet(flags *cli.CommonFlags, idStr string) error {
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

	// Get device
	ctx := base.Context()
	d, err := deviceClient.Get(ctx, id)
	if err != nil {
		return ErrGetDeviceFailed{ID: id, Reason: err.Error()}
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

// deviceDetail represents detailed device information for output
type deviceDetail struct {
	ID         uint64 `json:"id"`
	Serial     string `json:"serial"`
	Model      string `json:"model"`
	HashAlgoID int    `json:"hash_algo_id"`
	EKCert     string `json:"ek_cert,omitempty"`
	AttestPub  string `json:"attest_pub,omitempty"`
	SigningPub string `json:"signing_pub,omitempty"`
}

// buildGetOutput creates the JSON output structure for the get command
func buildGetOutput(d deviceDetail) map[string]interface{} {
	output := map[string]interface{}{
		"id":           d.ID,
		"serial":       d.Serial,
		"model":        d.Model,
		"hash_algo_id": d.HashAlgoID,
	}

	if d.EKCert != "" {
		output["ek_cert"] = d.EKCert
	}
	if d.AttestPub != "" {
		output["attest_pub"] = d.AttestPub
	}
	if d.SigningPub != "" {
		output["signing_pub"] = d.SigningPub
	}

	return output
}

// printDeviceDetails prints device information in table format
func printDeviceDetails(printer *cli.Printer, d deviceDetail) {
	printer.PrintKeyValue("ID", strconv.FormatUint(d.ID, 10))
	printer.PrintKeyValue("Serial", d.Serial)
	printer.PrintKeyValue("Model", d.Model)
	printer.PrintKeyValue("Hash Algo", strconv.Itoa(d.HashAlgoID))

	if d.EKCert != "" {
		printer.PrintKeyValue("EK Cert", truncate(d.EKCert, 50)+"...")
	}
	if d.AttestPub != "" {
		printer.PrintKeyValue("Attest Pub", truncate(d.AttestPub, 50)+"...")
	}
	if d.SigningPub != "" {
		printer.PrintKeyValue("Signing", truncate(d.SigningPub, 50)+"...")
	}
}
