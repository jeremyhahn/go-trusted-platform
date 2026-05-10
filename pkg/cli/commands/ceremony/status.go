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

package ceremony

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	ceremonysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
)

// newStatusCommand creates the "ceremony status" subcommand.
func newStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current ceremony status",
		Long:  `Display the current state of the ceremony including enrollment progress and Shamir threshold.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(getFlags())
		},
	}
}

// runStatus dispatches "ceremony status" to the SDK.
func runStatus(commonFlags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := ceremonysvc.NewClient()

	resp, err := client.Status(base.Context())
	if err != nil {
		return err
	}

	return base.Output(resp)
}
