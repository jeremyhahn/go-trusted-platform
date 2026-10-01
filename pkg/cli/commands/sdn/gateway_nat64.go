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

package sdn

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

// newGatewayNAT64Command creates the "gateway nat64" command tree.
func newGatewayNAT64Command(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nat64",
		Short: "NAT64 translator status",
		Long: `Inspect the stateful NAT64 translator (RFC 6146).

The gateway owns a Jool kernel instance and hands it the frames addressed to
the RFC 6052 translation prefix. What this reports is what the kernel said,
not what the configuration asked for: a started service whose instance has
gone reports instance_present false.

Examples:
  platformctl sdn gateway nat64 status
  platformctl sdn gateway nat64 status -o json`,
	}

	cmd.AddCommand(newGatewayNAT64StatusCommand(getFlags))

	return cmd
}

// newGatewayNAT64StatusCommand creates the "nat64 status" command.
func newGatewayNAT64StatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Get NAT64 translator status",
		Long: `Display the NAT64 translator health.

Shows whether the service is started, whether the kernel instance is
present, the translation prefix and instance name, the live session count,
pool4 usage, the module version and the last reconcile error if there was
one.

Examples:
  platformctl sdn gateway nat64 status
  platformctl sdn gateway nat64 status -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNAT64Status(getFlags())
		},
	}
}

// runNAT64Status reads the translator's health.
func runNAT64Status(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.GetNAT64Status(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to get NAT64 status", Err: err}
	}

	return base.Output(resp)
}
