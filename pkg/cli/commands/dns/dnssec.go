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
	"strconv"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newDNSSECCommand creates the dns dnssec command group.
func newDNSSECCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dnssec",
		Short: "Sign zones and show their DNSSEC state",
	}
	cmd.AddCommand(newDNSSECSignCommand(getFlags))
	cmd.AddCommand(newDNSSECStatusCommand(getFlags))
	return cmd
}

// newDNSSECSignCommand creates the dns dnssec sign subcommand.
func newDNSSECSignCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "sign <zone>",
		Short: "Sign a zone (SignZone)",
		Long: `Sign a zone with the daemon's DNSSEC keys. The zone is published
with its DNSKEY, RRSIG and NSEC records.

Examples:
  platformctl dns dnssec sign example.test.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDNSSECSign(getFlags(), args[0])
		},
	}
}

// runDNSSECSign executes the dnssec sign subcommand.
func runDNSSECSign(flags *cli.CommonFlags, zone string) error {
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.SignZone(ctx, &platformv1.SignZoneRequest{ZoneName: zone})
		if err != nil {
			return &WrappedError{Msg: "failed to sign zone " + zone, Err: err}
		}
		return respond(flags, resp, zoneTable(resp.GetZone()))
	})
}

// newDNSSECStatusCommand creates the dns dnssec status subcommand.
func newDNSSECStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status <zone>",
		Short: "Show a zone's DNSSEC state (GetDNSSECStatus)",
		Long: `Show whether DNSSEC is enabled and the zone signed, the algorithm,
the key count and the DS records to publish in the parent zone.

Examples:
  platformctl dns dnssec status example.test.
  platformctl dns dnssec status example.test. -o json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDNSSECStatus(getFlags(), args[0])
		},
	}
}

// runDNSSECStatus executes the dnssec status subcommand.
func runDNSSECStatus(flags *cli.CommonFlags, zone string) error {
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.GetDNSSECStatus(ctx, &platformv1.GetDNSSECStatusRequest{ZoneName: zone})
		if err != nil {
			return &WrappedError{Msg: "failed to read DNSSEC status of zone " + zone, Err: err}
		}
		return respond(flags, resp, dnssecTable(zone, resp.GetStatus()))
	})
}

// dnssecTable renders a zone's DNSSEC state as a two-column table.
func dnssecTable(zone string, status *platformv1.DNSSECStatus) *cli.TableData {
	table := cli.NewTableData("FIELD", "VALUE")
	table.AddRow("zone", zone)
	table.AddRow("enabled", strconv.FormatBool(status.GetEnabled()))
	table.AddRow("signed", strconv.FormatBool(status.GetZoneSigned()))
	table.AddRow("algorithm", status.GetAlgorithm())
	table.AddRow("key size", status.GetKeySize())
	table.AddRow("keys", strconv.Itoa(len(status.GetKeys())))
	for _, ds := range status.GetDsRecords() {
		table.AddRow("ds", joinFields(uintField(ds.GetKeyTag()), uintField(ds.GetAlgorithm()),
			uintField(ds.GetDigestType()), ds.GetDigest()))
	}
	return table
}
