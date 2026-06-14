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

// newSetBootDeviceCommand creates the set-boot-device subcommand.
func newSetBootDeviceCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags
	var device string
	var persistent bool

	cmd := &cobra.Command{
		Use:   "set-boot-device",
		Short: "Set the boot device via BMC",
		Long: `Configure the next boot device for a server through its BMC.

Valid boot devices: pxe, disk, cdrom, bios

Examples:
  # Set one-time PXE boot
  platformctl bmc set-boot-device \
    --server-url https://platform:8443 \
    --profile-id server-01 \
    --device pxe

  # Set persistent disk boot
  platformctl bmc set-boot-device \
    --server-url https://platform:8443 \
    --profile-id server-01 \
    --device disk \
    --persistent`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				return runStandaloneSetBootDevice(cmd.Context(), &standalone, device, persistent, getFlags)
			}
			return runSetBootDevice(&flags, device, persistent, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd server URL (required)")
	cmd.Flags().StringVar(&flags.caCert, "ca-cert", "", "CA bundle to verify the platformd TLS certificate (defaults to $PLATFORM_CA_CERT)")
	cmd.Flags().StringVar(&flags.clientCert, "client-cert", "", "client certificate for mutual TLS (defaults to $PLATFORM_CLIENT_CERT)")
	cmd.Flags().StringVar(&flags.clientKey, "client-key", "", "client key for mutual TLS (defaults to $PLATFORM_CLIENT_KEY)")
	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	addStandaloneFlags(cmd, &standalone)
	cmd.Flags().StringVar(&device, "device", "", "boot device: pxe, disk, cdrom, bios (required)")
	cmd.Flags().BoolVar(&persistent, "persistent", false, "make boot device persistent across reboots")

	return cmd
}

// newGetBootDeviceCommand creates the get-boot-device subcommand.
func newGetBootDeviceCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "get-boot-device",
		Short: "Get the current boot device via BMC",
		Long: `Query the current boot device configuration from a server's BMC.

Examples:
  platformctl bmc get-boot-device \
    --server-url https://platform:8443 \
    --profile-id server-01`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				return runStandaloneGetBootDevice(cmd.Context(), &standalone, getFlags)
			}
			return runGetBootDevice(&flags, getFlags)
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

// runSetBootDevice sets the boot device for a server via the BMC API.
func runSetBootDevice(flags *bmcFlags, device string, persistent bool, getFlags func() *cli.CommonFlags) error {
	if err := validateBMCFlags(flags); err != nil {
		return err
	}
	if device == "" {
		return ErrDeviceRequired{}
	}
	if _, ok := validBootDevices[device]; !ok {
		return ErrInvalidBootDevice{Device: device}
	}

	ctx := context.Background()
	client, err := newBMCHTTPClient(flags)
	if err != nil {
		return err
	}

	url := buildURL(flags.serverURL, flags.profileID, "boot-device")
	payload := bootDeviceRequest{
		Device:     device,
		Persistent: persistent,
	}

	var resp bootDeviceResponse
	if err := doPost(ctx, client, url, payload, &resp); err != nil {
		return err
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	fmt.Fprintf(os.Stdout, "Profile:    %s\nDevice:     %s\nPersistent: %t\n",
		resp.ProfileID, resp.Device, resp.Persistent)
	return nil
}

// runGetBootDevice queries the current boot device from the BMC API.
func runGetBootDevice(flags *bmcFlags, getFlags func() *cli.CommonFlags) error {
	if err := validateBMCFlags(flags); err != nil {
		return err
	}

	ctx := context.Background()
	client, err := newBMCHTTPClient(flags)
	if err != nil {
		return err
	}

	url := buildURL(flags.serverURL, flags.profileID, "boot-device")

	var resp bootDeviceResponse
	if err := doGet(ctx, client, url, &resp); err != nil {
		return err
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	fmt.Fprintf(os.Stdout, "Profile:    %s\nDevice:     %s\nPersistent: %t\n",
		resp.ProfileID, resp.Device, resp.Persistent)
	return nil
}
