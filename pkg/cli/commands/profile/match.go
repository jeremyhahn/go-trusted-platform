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

package profile

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newMatchCommand creates the match subcommand for finding a matching profile
func newMatchCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		mac    string
		serial string
		model  string
	)

	cmd := &cobra.Command{
		Use:   "match",
		Short: "Find matching device profile",
		Long: `Find a device profile that matches the given criteria.

The profile matching uses prefix-based rules for MAC and serial,
and exact match for model. At least one criterion must be provided.

Match priority:
  1. MAC prefix match
  2. Serial prefix match
  3. Model exact match

Examples:
  # Find profile by MAC address
  platformctl profile match --mac 00:11:22:33:44:55

  # Find profile by serial number
  platformctl profile match --serial ABC123

  # Find profile by model
  platformctl profile match --model "Dell PowerEdge R740"

  # Find profile with multiple criteria
  platformctl profile match --mac 00:11:22 --serial ABC --model Dell

  # Get result as JSON
  platformctl profile match --mac 00:11:22 -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()

			if mac == "" && serial == "" && model == "" {
				return ErrNoMatchCriteria{}
			}

			return runMatch(flags, mac, serial, model)
		},
	}

	cmd.Flags().StringVar(&mac, "mac", "", "MAC address to match")
	cmd.Flags().StringVar(&serial, "serial", "", "Serial number to match")
	cmd.Flags().StringVar(&model, "model", "", "Model to match")

	return cmd
}

// runMatch executes the match command
func runMatch(flags *cli.CommonFlags, mac, serial, model string) error {
	// Daemon connection required - dual-mode will be added later
	return ErrDaemonConnectionRequired{}
}
