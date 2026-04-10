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

// newPowerOnCommand creates the power-on subcommand.
func newPowerOnCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "power-on",
		Short: "Power on a server via BMC",
		Long: `Power on a server through its Baseboard Management Controller.

Examples:
  platformctl bmc power-on \
    --server-url https://platform:8443 \
    --profile-id server-01`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				return runStandalonePower(cmd.Context(), &standalone, PowerActionOn, getFlags)
			}
			return runPowerAction(&flags, PowerActionOn, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd server URL (required)")
	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// newPowerOffCommand creates the power-off subcommand.
func newPowerOffCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "power-off",
		Short: "Power off a server via BMC",
		Long: `Power off a server through its Baseboard Management Controller.

Examples:
  platformctl bmc power-off \
    --server-url https://platform:8443 \
    --profile-id server-01`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				return runStandalonePower(cmd.Context(), &standalone, PowerActionOff, getFlags)
			}
			return runPowerAction(&flags, PowerActionOff, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd server URL (required)")
	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// newPowerResetCommand creates the power-reset subcommand.
func newPowerResetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "power-reset",
		Short: "Hard reset a server via BMC",
		Long: `Perform a hard reset on a server through its Baseboard Management Controller.

Examples:
  platformctl bmc power-reset \
    --server-url https://platform:8443 \
    --profile-id server-01`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				return runStandalonePower(cmd.Context(), &standalone, PowerActionReset, getFlags)
			}
			return runPowerAction(&flags, PowerActionReset, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd server URL (required)")
	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// newPowerCycleCommand creates the power-cycle subcommand.
func newPowerCycleCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "power-cycle",
		Short: "Power cycle a server via BMC",
		Long: `Power cycle a server (off then on) through its Baseboard Management Controller.

Examples:
  platformctl bmc power-cycle \
    --server-url https://platform:8443 \
    --profile-id server-01`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				return runStandalonePower(cmd.Context(), &standalone, PowerActionCycle, getFlags)
			}
			return runPowerAction(&flags, PowerActionCycle, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd server URL (required)")
	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// newPowerStatusCommand creates the power-status subcommand.
func newPowerStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "power-status",
		Short: "Get power status of a server via BMC",
		Long: `Query the current power state of a server through its BMC.

Examples:
  platformctl bmc power-status \
    --server-url https://platform:8443 \
    --profile-id server-01`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				return runStandalonePowerStatus(cmd.Context(), &standalone, getFlags)
			}
			return runPowerStatus(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd server URL (required)")
	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// runPowerAction executes a power action (on, off, reset, cycle) against the BMC API.
func runPowerAction(flags *bmcFlags, action PowerAction, getFlags func() *cli.CommonFlags) error {
	if err := validateBMCFlags(flags); err != nil {
		return err
	}

	ctx := context.Background()
	client := &http.Client{}

	url := buildURL(flags.serverURL, flags.profileID, "power")
	payload := powerRequest{Action: action}

	var resp powerActionResponse
	if err := doPost(ctx, client, url, payload, &resp); err != nil {
		return err
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	fmt.Fprintf(os.Stdout, "Profile: %s\nAction:  %s\nStatus:  %s\n", resp.ProfileID, resp.Action, resp.Status)
	return nil
}

// runPowerStatus queries the power state of a server via the BMC API.
func runPowerStatus(flags *bmcFlags, getFlags func() *cli.CommonFlags) error {
	if err := validateBMCFlags(flags); err != nil {
		return err
	}

	ctx := context.Background()
	client := &http.Client{}

	url := buildURL(flags.serverURL, flags.profileID, "power")

	var resp powerStatusResponse
	if err := doGet(ctx, client, url, &resp); err != nil {
		return err
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	fmt.Fprintf(os.Stdout, "Profile:     %s\nPower State: %s\n", resp.ProfileID, resp.PowerState)
	return nil
}
