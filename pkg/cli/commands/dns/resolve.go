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

package dns

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newResolveCommand creates the dns resolve subcommand.
func newResolveCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var recordType string
	cmd := &cobra.Command{
		Use:   "resolve <fqdn>",
		Short: "Resolve a name from the service's zones (Resolve)",
		Long: `Resolve a name from the zones the service holds. Without --type every
record type at the name is returned.

Examples:
  platformctl dns resolve www.example.test. --type A
  platformctl dns resolve example.test. --type MX -o json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runResolve(getFlags(), args[0], recordType)
		},
	}
	cmd.Flags().StringVar(&recordType, "type", "", "only records of this type")
	return cmd
}

// runResolve executes the resolve subcommand.
func runResolve(flags *cli.CommonFlags, fqdn, mnemonic string) error {
	recordType, err := parseRecordType(mnemonic)
	if err != nil {
		return err
	}
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.Resolve(ctx, &platformv1.ResolveRequest{Fqdn: fqdn, Type: recordType})
		if err != nil {
			return &WrappedError{Msg: "failed to resolve " + fqdn, Err: err}
		}
		return respond(flags, resp, recordsTable(resp.GetRecords()))
	})
}

// newRegisterCommand creates the dns register subcommand.
func newRegisterCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "register <fqdn> <ip>",
		Short: "Register a host address in its zone (Register)",
		Long: `Register a host's address record in the zone that holds the name.

Examples:
  platformctl dns register node1.example.test. 192.0.2.21`,
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegister(getFlags(), args[0], args[1])
		},
	}
}

// runRegister executes the register subcommand.
func runRegister(flags *cli.CommonFlags, fqdn, ip string) error {
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.Register(ctx, &platformv1.RegisterRequest{Fqdn: fqdn, Ip: ip})
		if err != nil {
			return &WrappedError{Msg: "failed to register " + fqdn, Err: err}
		}
		return respond(flags, resp, zoneTable(resp.GetZone()))
	})
}
