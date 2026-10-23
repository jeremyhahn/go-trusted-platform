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

// infoFlags holds the flag values for "luks info".
type infoFlags struct {
	device string
}

// newInfoCommand creates the "luks info" subcommand.
func newInfoCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &infoFlags{}

	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show detailed LUKS2 metadata",
		Long:  `Display the full LUKS2 header (JSON metadata, keyslot detail, segments).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInfo(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "LUKS device path (auto-detected if empty)")

	return cmd
}

// runInfo dispatches "luks info" to the SDK.
func runInfo(commonFlags *cli.CommonFlags, f *infoFlags) error {
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

	client, err := newService(base.Client())
	if err != nil {
		return err
	}
	resp, err := client.Info(base.Context(), &lukssvc.InfoRequest{Device: device})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
