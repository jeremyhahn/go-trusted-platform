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

// newEnablePortCommand creates the enable-port subcommand.
func newEnablePortCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags switchFlags

	cmd := &cobra.Command{
		Use:   "enable-port",
		Short: "Administratively enable a port",
		Long: `Administratively enable a port on the named switch.

This is equivalent to 'no shutdown' on the switch interface.

Examples:
  platformctl switch enable-port --server-url https://platform:8443 --switch core-01 --port Eth1/3`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnablePort(&flags, getFlags)
		},
	}

	addServerURLFlag(cmd, &flags)
	addSwitchFlag(cmd, &flags)
	addPortFlag(cmd, &flags)

	return cmd
}

func runEnablePort(flags *switchFlags, getFlags func() *cli.CommonFlags) error {
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

	if err := client.EnablePort(ctx, flags.switchName, flags.port); err != nil {
		return ErrOperationFailed{Operation: "enable-port", Cause: err}
	}

	commonFlags := getFlags()
	if commonFlags != nil && commonFlags.OutputFormat == cli.OutputFormatJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
			"switch": flags.switchName,
			"port":   flags.port,
			"action": "enable",
			"status": "ok",
		})
	}

	fmt.Fprintf(os.Stdout, "Switch: %s\nPort:   %s\nAction: enable\nStatus: ok\n",
		flags.switchName, flags.port)

	return nil
}
