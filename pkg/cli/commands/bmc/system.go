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
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newSystemInfoCommand creates the system-info subcommand.
func newSystemInfoCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "system-info",
		Short: "Get system information via BMC",
		Long: `Query system information from a server's Baseboard Management Controller.

Returns manufacturer, model, serial number, BIOS version, BMC version,
power state, and overall health status.

Examples:
  platformctl bmc system-info \
    --server-url https://platform:8443 \
    --profile-id server-01`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				return runStandaloneSystemInfo(cmd.Context(), &standalone, getFlags)
			}
			return runSystemInfo(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd server URL (required)")
	cmd.Flags().StringVar(&flags.caCert, "ca-cert", "", "CA bundle to verify the platformd TLS certificate (defaults to $PLATFORM_CA_CERT)")
	cmd.Flags().StringVar(&flags.clientCert, "client-cert", "", "client certificate for mutual TLS (defaults to $PLATFORM_CLIENT_CERT)")
	cmd.Flags().StringVar(&flags.clientKey, "client-key", "", "client key for mutual TLS (defaults to $PLATFORM_CLIENT_KEY)")
	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// runSystemInfo queries system information from the BMC API.
func runSystemInfo(flags *bmcFlags, getFlags func() *cli.CommonFlags) error {
	if err := validateBMCFlags(flags); err != nil {
		return err
	}

	ctx := context.Background()
	client, err := newBMCHTTPClient(flags)
	if err != nil {
		return err
	}

	url := buildURL(flags.serverURL, flags.profileID, "system-info")

	var resp systemInfoResponse
	if err := doGet(ctx, client, url, &resp); err != nil {
		return err
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	fmt.Fprintf(os.Stdout, "Profile:       %s\n", resp.ProfileID)
	fmt.Fprintf(os.Stdout, "Manufacturer:  %s\n", resp.Manufacturer)
	fmt.Fprintf(os.Stdout, "Model:         %s\n", resp.Model)
	fmt.Fprintf(os.Stdout, "Serial Number: %s\n", resp.SerialNumber)
	fmt.Fprintf(os.Stdout, "BIOS Version:  %s\n", resp.BIOSVersion)
	fmt.Fprintf(os.Stdout, "BMC Version:   %s\n", resp.BMCVersion)
	fmt.Fprintf(os.Stdout, "Power State:   %s\n", resp.PowerState)
	fmt.Fprintf(os.Stdout, "Health:        %s\n", resp.Health)
	return nil
}
