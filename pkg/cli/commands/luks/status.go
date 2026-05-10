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

package luks

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	lukssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
)

// statusFlags holds the flag values for "luks status".
type statusFlags struct {
	device string
}

// newStatusCommand creates the "luks status" subcommand.
func newStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &statusFlags{}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show LUKS volume status",
		Long:  `Display the header state of a LUKS device (version, UUID, cipher, active slots).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "LUKS device path (auto-detected if empty)")

	return cmd
}

// runStatus dispatches "luks status" to the SDK.
func runStatus(commonFlags *cli.CommonFlags, f *statusFlags) error {
	if err := checkRoot(); err != nil {
		return err
	}
	device, err := resolveDevice(f.device)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := lukssvc.NewClient()
	resp, err := client.Status(base.Context(), &lukssvc.StatusRequest{Device: device})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
