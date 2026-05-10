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

// newListPortsCommand creates the list-ports subcommand.
func newListPortsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags switchFlags

	cmd := &cobra.Command{
		Use:   "list-ports",
		Short: "List all ports on a switch",
		Long: `List all physical ports and their status on the named switch.

Output includes port name, mode, VLAN, enabled state, link state, and description.

Examples:
  platformctl switch list-ports --server-url https://platform:8443 --switch core-01
  platformctl switch list-ports --server-url https://platform:8443 --switch core-01 -o json`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListPorts(&flags, getFlags)
		},
	}

	addServerURLFlag(cmd, &flags)
	addSwitchFlag(cmd, &flags)

	return cmd
}

func runListPorts(flags *switchFlags, getFlags func() *cli.CommonFlags) error {
	if flags.switchName == "" {
		return ErrSwitchNameRequired{}
	}

	client, err := newSwitchClient(flags, getFlags)
	if err != nil {
		return err
	}

	ctx, cancel := newCLIContext()
	defer cancel()

	ports, err := client.ListPorts(ctx, flags.switchName)
	if err != nil {
		return ErrOperationFailed{Operation: "list-ports", Cause: err}
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(ports)
	}

	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatYAML {
		printer := cli.NewPrinter(cli.OutputFormatYAML, commonFlags.NoColor)
		return printer.Print(ports)
	}

	// Table output
	table := cli.NewTableData("PORT", "MODE", "VLAN", "ENABLED", "LINK UP", "DESCRIPTION")
	for _, p := range ports {
		vlan := strconv.Itoa(int(p.AccessVLAN))
		if p.Mode == "trunk" {
			vlanStrs := make([]string, len(p.TrunkVLANs))
			for i, v := range p.TrunkVLANs {
				vlanStrs[i] = strconv.Itoa(int(v))
			}
			vlan = strings.Join(vlanStrs, ",")
		}

		table.AddRow(
			p.Port,
			string(p.Mode),
			vlan,
			fmt.Sprintf("%t", p.Enabled),
			fmt.Sprintf("%t", p.LinkUp),
			p.Description,
		)
	}

	noColor := false
	if commonFlags != nil {
		noColor = commonFlags.NoColor
	}
	printer := cli.NewPrinter(cli.OutputFormatTable, noColor)
	return printer.Print(table)
}
