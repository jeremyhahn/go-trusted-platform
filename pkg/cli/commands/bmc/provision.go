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

// newProvisionCommand creates the provision subcommand for bare metal provisioning.
func newProvisionCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags
	var isoURL string

	cmd := &cobra.Command{
		Use:   "provision",
		Short: "Provision a bare metal server via BMC",
		Long: `Trigger bare metal provisioning for a server through its BMC.

This orchestrates the full provisioning workflow: mounting the ISO (if
provided), setting the boot device, and powering on the server.

Examples:
  # Provision with an ISO
  platformctl bmc provision \
    --server-url https://platform:8443 \
    --profile-id server-01 \
    --iso-url https://images.example.com/os.iso

  # Provision using pre-configured boot settings
  platformctl bmc provision \
    --server-url https://platform:8443 \
    --profile-id server-01`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				return ErrBMCRequiresDaemon{Subcommand: "provision", Reason: "BMC profile persistence requires platformd"}
			}
			return runProvision(&flags, isoURL, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd server URL (required)")
	cmd.Flags().StringVar(&flags.caCert, "ca-cert", "", "CA bundle to verify the platformd TLS certificate (defaults to $PLATFORM_CA_CERT)")
	cmd.Flags().StringVar(&flags.clientCert, "client-cert", "", "client certificate for mutual TLS (defaults to $PLATFORM_CLIENT_CERT)")
	cmd.Flags().StringVar(&flags.clientKey, "client-key", "", "client key for mutual TLS (defaults to $PLATFORM_CLIENT_KEY)")
	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	addStandaloneFlags(cmd, &standalone)
	cmd.Flags().StringVar(&isoURL, "iso-url", "", "URL of the ISO image for provisioning (optional)")

	return cmd
}

// runProvision triggers bare metal provisioning via the BMC API.
func runProvision(flags *bmcFlags, isoURL string, getFlags func() *cli.CommonFlags) error {
	if err := validateBMCFlags(flags); err != nil {
		return err
	}

	ctx := context.Background()
	client, err := newBMCHTTPClient(flags)
	if err != nil {
		return err
	}

	url := buildURL(flags.serverURL, flags.profileID, "provision")
	payload := provisionRequest{ISOURL: isoURL}

	var resp provisionResponse
	if err := doPost(ctx, client, url, payload, &resp); err != nil {
		return err
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	fmt.Fprintf(os.Stdout, "Profile: %s\nStatus:  %s\n", resp.ProfileID, resp.Status)
	if resp.Message != "" {
		fmt.Fprintf(os.Stdout, "Message: %s\n", resp.Message)
	}
	return nil
}
