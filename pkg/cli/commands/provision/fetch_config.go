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

package provision

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// exitCodePending is the exit code returned when the server responds with
// pending status, signaling autoinstall.sh to try interactive mode.
const exitCodePending = 2

// newFetchConfigCommand creates the fetch-config subcommand for fetching
// provisioning configuration from the server.
func newFetchConfigCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags provisionFlags

	cmd := &cobra.Command{
		Use:   "fetch-config",
		Short: "Fetch provisioning config from server",
		Long: `Fetch platform configuration from the provisioning server.

This command is used during ISO boot by autoinstall.sh to retrieve the
platform configuration for this device. It uses the device's EK serial
number and MAC address along with EAB credentials to authenticate.

Exit codes:
  0 - Config fetched successfully and written to --output
  1 - Error occurred
  2 - Server returned "pending" status (try interactive mode)

Examples:
  # Fetch config
  platformctl provision fetch-config \
    --server-url https://platform:8443 \
    --ek-serial ABC123 \
    --mac 00:11:22:33:44:55 \
    --eab-kid key-id \
    --eab-hmac base64-hmac \
    --output /tmp/platform-config.yaml`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFetchConfig(&flags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "provisioning server URL (required)")
	cmd.Flags().StringVar(&flags.ekSerial, "ek-serial", "", "device EK serial number (required)")
	cmd.Flags().StringVar(&flags.mac, "mac", "", "device MAC address (required)")
	cmd.Flags().StringVar(&flags.eabKID, "eab-kid", "", "EAB key ID (required)")
	cmd.Flags().StringVar(&flags.eabHMAC, "eab-hmac", "", "EAB HMAC (required)")
	cmd.Flags().StringVar(&flags.output, "output", "", "output path for config YAML (required)")

	return cmd
}

// runFetchConfig executes the fetch-config command logic. It fetches a nonce,
// sends the config request, and handles the response status.
func runFetchConfig(flags *provisionFlags) error {
	if err := validateProvisionFlags(flags); err != nil {
		return err
	}

	ctx := context.Background()
	client := &http.Client{}

	// Fetch nonce from the server
	nonce, err := fetchNonce(ctx, client, flags.serverURL)
	if err != nil {
		return err
	}

	// Build and send config request
	cfgReq := buildConfigRequest(flags, nonce)
	cfgResp, err := sendConfigRequest(ctx, client, flags.serverURL, cfgReq)
	if err != nil {
		return err
	}

	switch cfgResp.Status {
	case statusOK:
		// Config received, write to output file
		if err := writeConfigToFile(cfgResp.Config, flags.output); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Config written to %s\n", flags.output)
		return nil

	case statusPending:
		// Signal autoinstall.sh to try interactive mode
		fmt.Fprintln(os.Stderr, "Device is pending approval")
		os.Exit(exitCodePending)
		return nil

	default:
		return ErrUnexpectedStatus{
			StatusCode: http.StatusOK,
			Body:       "unexpected status: " + cfgResp.Status,
		}
	}
}
