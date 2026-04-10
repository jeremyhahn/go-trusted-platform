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

// newSensorsCommand creates the sensors subcommand.
func newSensorsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags bmcFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "sensors",
		Short: "Get sensor readings via BMC",
		Long: `Query sensor readings from a server's Baseboard Management Controller.

Returns temperature, voltage, fan speed, and other sensor data.

Examples:
  platformctl bmc sensors \
    --server-url https://platform:8443 \
    --profile-id server-01`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkModeConflict(&standalone, &flags); err != nil {
				return err
			}
			if standalone.isSet() {
				return runStandaloneSensors(cmd.Context(), &standalone, getFlags)
			}
			return runSensors(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd server URL (required)")
	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// runSensors queries sensor readings from the BMC API.
func runSensors(flags *bmcFlags, getFlags func() *cli.CommonFlags) error {
	if err := validateBMCFlags(flags); err != nil {
		return err
	}

	ctx := context.Background()
	client := &http.Client{}

	url := buildURL(flags.serverURL, flags.profileID, "sensors")

	var resp sensorsResponse
	if err := doGet(ctx, client, url, &resp); err != nil {
		return err
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	fmt.Fprintf(os.Stdout, "Profile: %s\nSensors:\n", resp.ProfileID)
	for _, s := range resp.Sensors {
		fmt.Fprintf(os.Stdout, "  %-30s %8.2f %-10s [%s]\n", s.Name, s.Value, s.Units, s.Status)
	}
	return nil
}
