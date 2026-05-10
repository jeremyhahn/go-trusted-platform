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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newSetVLANCommand creates the set-vlan subcommand.
func newSetVLANCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags switchFlags

	cmd := &cobra.Command{
		Use:   "set-vlan",
		Short: "Set the access VLAN on a port",
		Long: `Set the access VLAN on a port of the named switch.

The port must be in access mode. The VLAN ID must be between 1 and 4094.

Examples:
  platformctl switch set-vlan --server-url https://platform:8443 --switch core-01 --port Eth1/3 --vlan 200`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetVLAN(&flags, getFlags)
		},
	}

	addServerURLFlag(cmd, &flags)
	addSwitchFlag(cmd, &flags)
	addPortFlag(cmd, &flags)
	cmd.Flags().IntVar(&flags.vlan, "vlan", 0, "VLAN ID 1-4094 (required)")

	return cmd
}

func runSetVLAN(flags *switchFlags, getFlags func() *cli.CommonFlags) error {
	if flags.switchName == "" {
		return ErrSwitchNameRequired{}
	}
	if flags.port == "" {
		return ErrPortNameRequired{}
	}
	if flags.vlan == 0 {
		return ErrVLANIDRequired{}
	}
	if flags.vlan < 1 || flags.vlan > 4094 {
		return ErrInvalidVLANID{Value: flags.vlan}
	}

	client, err := newSwitchClient(flags, getFlags)
	if err != nil {
		return err
	}

	ctx, cancel := newCLIContext()
	defer cancel()

	if err := client.SetPortVLAN(ctx, flags.switchName, flags.port, uint16(flags.vlan)); err != nil {
		return ErrOperationFailed{Operation: "set-vlan", Cause: err}
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
			"switch":  flags.switchName,
			"port":    flags.port,
			"vlan_id": flags.vlan,
			"status":  "ok",
		})
	}

	fmt.Fprintf(os.Stdout, "Switch: %s\nPort:   %s\nVLAN:   %d\nStatus: ok\n",
		flags.switchName, flags.port, flags.vlan)

	return nil
}
