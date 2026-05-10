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

package switchcmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newPortStatusCommand creates the port-status subcommand.
func newPortStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags switchFlags

	cmd := &cobra.Command{
		Use:   "port-status",
		Short: "Get status of a specific port",
		Long: `Get the full observable state of a specific port on the named switch.

Output includes port name, mode, VLAN, enabled state, link state, and description.

Examples:
  platformctl switch port-status --server-url https://platform:8443 --switch core-01 --port Eth1/3
  platformctl switch port-status --server-url https://platform:8443 --switch core-01 --port Eth1/3 -o json`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPortStatus(&flags, getFlags)
		},
	}

	addServerURLFlag(cmd, &flags)
	addSwitchFlag(cmd, &flags)
	addPortFlag(cmd, &flags)

	return cmd
}

func runPortStatus(flags *switchFlags, getFlags func() *cli.CommonFlags) error {
	if flags.switchName == "" {
		return ErrSwitchNameRequired{}
	}
	if flags.port == "" {
		return ErrPortNameRequired{}
	}

	client, err := newSwitchClient(flags, getFlags)
	if err != nil {
		return err
	}

	ctx, cancel := newCLIContext()
	defer cancel()

	status, err := client.GetPortStatus(ctx, flags.switchName, flags.port)
	if err != nil {
		return ErrOperationFailed{Operation: "port-status", Cause: err}
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(status)
	}

	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatYAML {
		printer := cli.NewPrinter(cli.OutputFormatYAML, commonFlags.NoColor)
		return printer.Print(status)
	}

	// Key-value output
	noColor := false
	if commonFlags != nil {
		noColor = commonFlags.NoColor
	}
	printer := cli.NewPrinter(cli.OutputFormatTable, noColor)

	printer.PrintKeyValue("Port", status.Port)
	printer.PrintKeyValue("Mode", string(status.Mode))
	printer.PrintKeyValue("Access VLAN", strconv.Itoa(int(status.AccessVLAN)))

	if len(status.TrunkVLANs) > 0 {
		vlanStrs := make([]string, len(status.TrunkVLANs))
		for i, v := range status.TrunkVLANs {
			vlanStrs[i] = strconv.Itoa(int(v))
		}
		printer.PrintKeyValue("Trunk VLANs", strings.Join(vlanStrs, ", "))
	}

	printer.PrintKeyValue("Enabled", fmt.Sprintf("%t", status.Enabled))
	printer.PrintKeyValue("Link Up", fmt.Sprintf("%t", status.LinkUp))

	if status.Description != "" {
		printer.PrintKeyValue("Description", status.Description)
	}

	return nil
}
