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
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newMountISOCommand creates the mount-iso subcommand.
func newMountISOCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags
	var isoURL string

	cmd := &cobra.Command{
		Use:   "mount-iso",
		Short: "Mount an ISO as virtual media via BMC",
		Long: `Mount an ISO image as virtual media on a server through its BMC.
The ISO will be available as a virtual CD-ROM drive.

Examples:
  platformctl bmc mount-iso \
    --server-url https://platform:8443 \
    --profile-id server-01 \
    --iso-url https://images.example.com/os.iso`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				if isoURL == "" {
					return ErrISOURLRequired{}
				}
				return runStandaloneMountISO(cmd.Context(), &standalone, isoURL, getFlags)
			}
			return runMountISO(&flags, isoURL, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd server URL (required)")
	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	addStandaloneFlags(cmd, &standalone)
	cmd.Flags().StringVar(&isoURL, "iso-url", "", "URL of the ISO image to mount (required)")

	return cmd
}

// newUnmountISOCommand creates the unmount-iso subcommand.
func newUnmountISOCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "unmount-iso",
		Short: "Unmount virtual media via BMC",
		Long: `Unmount the currently mounted virtual media from a server's BMC.

Examples:
  platformctl bmc unmount-iso \
    --server-url https://platform:8443 \
    --profile-id server-01`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				return runStandaloneUnmountISO(cmd.Context(), &standalone, getFlags)
			}
			return runUnmountISO(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd server URL (required)")
	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// newMediaStatusCommand creates the media-status subcommand.
func newMediaStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "media-status",
		Short: "Get virtual media status via BMC",
		Long: `Query the current virtual media status from a server's BMC.

Examples:
  platformctl bmc media-status \
    --server-url https://platform:8443 \
    --profile-id server-01`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				return runStandaloneMediaStatus(cmd.Context(), &standalone, getFlags)
			}
			return runMediaStatus(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd server URL (required)")
	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// runMountISO mounts an ISO image as virtual media via the BMC API.
func runMountISO(flags *bmcFlags, isoURL string, getFlags func() *cli.CommonFlags) error {
	if err := validateBMCFlags(flags); err != nil {
		return err
	}
	if isoURL == "" {
		return ErrISOURLRequired{}
	}

	ctx := context.Background()
	client := &http.Client{}

	url := buildURL(flags.serverURL, flags.profileID, "media")
	payload := mountMediaRequest{ISOURL: isoURL}

	var resp mediaActionResponse
	if err := doPost(ctx, client, url, payload, &resp); err != nil {
		return err
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	fmt.Fprintf(os.Stdout, "Profile: %s\nAction:  %s\nStatus:  %s\nISO URL: %s\n",
		resp.ProfileID, resp.Action, resp.Status, resp.ISOURL)
	return nil
}

// runUnmountISO unmounts virtual media via the BMC API.
func runUnmountISO(flags *bmcFlags, getFlags func() *cli.CommonFlags) error {
	if err := validateBMCFlags(flags); err != nil {
		return err
	}

	ctx := context.Background()
	client := &http.Client{}

	url := buildURL(flags.serverURL, flags.profileID, "media")

	var resp mediaActionResponse
	if err := doDelete(ctx, client, url, &resp); err != nil {
		return err
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	fmt.Fprintf(os.Stdout, "Profile: %s\nAction:  %s\nStatus:  %s\n",
		resp.ProfileID, resp.Action, resp.Status)
	return nil
}

// runMediaStatus queries the virtual media status via the BMC API.
func runMediaStatus(flags *bmcFlags, getFlags func() *cli.CommonFlags) error {
	if err := validateBMCFlags(flags); err != nil {
		return err
	}

	ctx := context.Background()
	client := &http.Client{}

	url := buildURL(flags.serverURL, flags.profileID, "media")

	var resp mediaStatusResponse
	if err := doGet(ctx, client, url, &resp); err != nil {
		return err
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	fmt.Fprintf(os.Stdout, "Profile: %s\nMounted: %t\n", resp.ProfileID, resp.Mounted)
	if resp.ISOURL != "" {
		fmt.Fprintf(os.Stdout, "ISO URL: %s\n", resp.ISOURL)
	}
	return nil
}
