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

// status.go implements the canonical "barrier status" verb.
package barrier

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newStatusCommand builds the canonical `barrier status` command.
func newStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show barrier status",
		Long:  "Show the current state of the cryptographic barrier (sealed flag, strategy, hardware-backed, initialized-at).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatus(getFlags())
		},
	}
}

// runStatus opens the SDK connection and delegates to dispatchStatus.
func runStatus(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	bc, qerr := openBarrierClient(base)
	if qerr != nil {
		return qerr
	}
	return dispatchStatus(newDispatcherFromBase(base, bc))
}
