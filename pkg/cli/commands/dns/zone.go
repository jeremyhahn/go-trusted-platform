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

// defaultZoneTTL is the zone TTL when --ttl is not given.
const defaultZoneTTL = 3600

// zoneCreateFlags carries the zone create command line.
type zoneCreateFlags struct {
	TTL         uint32
	Description string
	Internal    bool
	SOAMName    string
	SOARName    string
	SOASerial   uint32
	SOARefresh  uint32
	SOARetry    uint32
	SOAExpire   uint32
	SOAMinimum  uint32
	NameServers []string
}

// newZoneCommand creates the dns zone command group.
func newZoneCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zone",
		Short: "Create, inspect, update, list and delete zones",
	}
	cmd.AddCommand(newZoneCreateCommand(getFlags))
	cmd.AddCommand(newZoneGetCommand(getFlags))
	cmd.AddCommand(newZoneUpdateCommand(getFlags))
	cmd.AddCommand(newZoneDeleteCommand(getFlags))
	cmd.AddCommand(newZoneListCommand(getFlags))
	return cmd
}

// newZoneCreateCommand creates the dns zone create subcommand.
func newZoneCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var f zoneCreateFlags
	cmd := &cobra.Command{
		Use:   "create <zone>",
		Short: "Create a zone (CreateZone)",
		Long: `Create a zone. Only the name is required; the SOA is sent when
--soa-mname or --soa-rname is given, and each --ns adds an apex NS record.
Creating a name that already exists saves over it.

Examples:
  platformctl dns zone create example.test.
  platformctl dns zone create example.test. --ttl 3600 --internal \
    --soa-mname ns1.example.test. --soa-rname hostmaster.example.test. \
    --ns ns1.example.test.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneCreate(getFlags(), args[0], f)
		},
	}
	cmd.Flags().Uint32Var(&f.TTL, "ttl", defaultZoneTTL, "default TTL in seconds")
	cmd.Flags().StringVar(&f.Description, "description", "", "zone description")
	cmd.Flags().BoolVar(&f.Internal, "internal", false, "mark the zone internal (not published)")
	cmd.Flags().StringVar(&f.SOAMName, "soa-mname", "", "SOA primary name server")
	cmd.Flags().StringVar(&f.SOARName, "soa-rname", "", "SOA responsible mailbox, in domain form")
	cmd.Flags().Uint32Var(&f.SOASerial, "soa-serial", 1, "SOA serial")
	cmd.Flags().Uint32Var(&f.SOARefresh, "soa-refresh", 86400, "SOA refresh in seconds")
	cmd.Flags().Uint32Var(&f.SOARetry, "soa-retry", 7200, "SOA retry in seconds")
	cmd.Flags().Uint32Var(&f.SOAExpire, "soa-expire", 86400, "SOA expire in seconds")
	cmd.Flags().Uint32Var(&f.SOAMinimum, "soa-minimum-ttl", 3600, "SOA minimum (negative caching) TTL in seconds")
	cmd.Flags().StringSliceVar(&f.NameServers, "ns", nil, "apex name server; repeat for more")
	return cmd
}

// zoneCreateRequest builds the CreateZone request from the command line.
func zoneCreateRequest(name string, f zoneCreateFlags) *platformv1.CreateZoneRequest {
	req := &platformv1.CreateZoneRequest{
		Name:        name,
		Ttl:         f.TTL,
		Description: f.Description,
		Internal:    f.Internal,
	}
	if f.SOAMName != "" || f.SOARName != "" {
		req.Soa = &platformv1.SOARecord{
			Name:       name,
			Mname:      f.SOAMName,
			Rname:      f.SOARName,
			Serial:     f.SOASerial,
			Refresh:    f.SOARefresh,
			Retry:      f.SOARetry,
			Expire:     f.SOAExpire,
			MinimumTtl: f.SOAMinimum,
			Ttl:        f.TTL,
		}
	}
	for _, ns := range f.NameServers {
		req.NsRecords = append(req.NsRecords, &platformv1.NSRecord{Name: name, Value: ns, Ttl: f.TTL})
	}
	return req
}

// runZoneCreate executes the zone create subcommand.
func runZoneCreate(flags *cli.CommonFlags, name string, f zoneCreateFlags) error {
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.CreateZone(ctx, zoneCreateRequest(name, f))
		if err != nil {
			return &WrappedError{Msg: "failed to create zone " + name, Err: err}
		}
		return respond(flags, resp, zoneTable(resp.GetZone()))
	})
}

// newZoneGetCommand creates the dns zone get subcommand.
func newZoneGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <zone>",
		Short: "Show a zone (GetZone)",
		Long: `Show a zone: its id, TTL, description, internal flag, SOA and
record count. -o json or -o yaml prints the zone with every record.

Examples:
  platformctl dns zone get example.test.
  platformctl dns zone get example.test. -o json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneGet(getFlags(), args[0])
		},
	}
}

// runZoneGet executes the zone get subcommand.
func runZoneGet(flags *cli.CommonFlags, name string) error {
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.GetZone(ctx, &platformv1.GetZoneRequest{Name: name})
		if err != nil {
			return &WrappedError{Msg: "failed to get zone " + name, Err: err}
		}
		return respond(flags, resp, zoneTable(resp.GetZone()))
	})
}

// newZoneUpdateCommand creates the dns zone update subcommand.
func newZoneUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		ttl         uint32
		description string
	)
	cmd := &cobra.Command{
		Use:   "update <zone>",
		Short: "Change a zone's TTL and description (UpdateZone)",
		Long: `Change a zone's default TTL and description.

Examples:
  platformctl dns zone update example.test. --ttl 7200 --description "lab zone"`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneUpdate(getFlags(), &platformv1.UpdateZoneRequest{Name: args[0], Ttl: ttl, Description: description})
		},
	}
	cmd.Flags().Uint32Var(&ttl, "ttl", 0, "default TTL in seconds")
	cmd.Flags().StringVar(&description, "description", "", "zone description")
	return cmd
}

// runZoneUpdate executes the zone update subcommand.
func runZoneUpdate(flags *cli.CommonFlags, req *platformv1.UpdateZoneRequest) error {
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.UpdateZone(ctx, req)
		if err != nil {
			return &WrappedError{Msg: "failed to update zone " + req.GetName(), Err: err}
		}
		return respond(flags, resp, zoneTable(resp.GetZone()))
	})
}

// newZoneDeleteCommand creates the dns zone delete subcommand.
func newZoneDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <zone>",
		Short: "Delete a zone and every record in it (DeleteZone)",
		Long: `Delete a zone and every record in it.

Examples:
  platformctl dns zone delete example.test.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneDelete(getFlags(), args[0])
		},
	}
}

// runZoneDelete executes the zone delete subcommand.
func runZoneDelete(flags *cli.CommonFlags, name string) error {
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.DeleteZone(ctx, &platformv1.DeleteZoneRequest{Name: name})
		if err != nil {
			return &WrappedError{Msg: "failed to delete zone " + name, Err: err}
		}
		table := cli.NewTableData("FIELD", "VALUE")
		table.AddRow("zone", name)
		table.AddRow("deleted", strconv.FormatBool(resp.GetStatus().GetSuccess()))
		return respond(flags, resp, table)
	})
}

// newZoneListCommand creates the dns zone list subcommand.
func newZoneListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		req      platformv1.ListZonesRequest
		page     uint32
		pageSize uint32
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List zones (ListZones)",
		Long: `List zones, optionally only internal or only public ones.

Examples:
  platformctl dns zone list
  platformctl dns zone list --internal-only
  platformctl dns zone list --page 2 --page-size 50 -o json`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if page > 0 || pageSize > 0 {
				req.Pagination = &platformv1.PaginationRequest{Page: page, PageSize: pageSize}
			}
			return runZoneList(getFlags(), &req)
		},
	}
	cmd.Flags().BoolVar(&req.InternalOnly, "internal-only", false, "only internal zones")
	cmd.Flags().BoolVar(&req.PublicOnly, "public-only", false, "only public zones")
	cmd.Flags().Uint32Var(&page, "page", 0, "page number")
	cmd.Flags().Uint32Var(&pageSize, "page-size", 0, "zones per page")
	cmd.MarkFlagsMutuallyExclusive("internal-only", "public-only")
	return cmd
}

// runZoneList executes the zone list subcommand.
func runZoneList(flags *cli.CommonFlags, req *platformv1.ListZonesRequest) error {
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.ListZones(ctx, req)
		if err != nil {
			return &WrappedError{Msg: "failed to list zones", Err: err}
		}
		table := cli.NewTableData("NAME", "ID", "TTL", "INTERNAL", "RECORDS")
		for _, zone := range resp.GetZones() {
			table.AddRow(zone.GetName(), strconv.FormatUint(zone.GetId(), 10), uintField(zone.GetTtl()),
				strconv.FormatBool(zone.GetInternal()), strconv.Itoa(countRecords(zone.GetRecords())))
		}
		return respond(flags, resp, table)
	})
}

// zoneTable renders a zone as a two-column table.
func zoneTable(zone *platformv1.Zone) *cli.TableData {
	table := cli.NewTableData("FIELD", "VALUE")
	if zone == nil {
		return table
	}
	table.AddRow("name", zone.GetName())
	table.AddRow("id", strconv.FormatUint(zone.GetId(), 10))
	table.AddRow("ttl", uintField(zone.GetTtl()))
	table.AddRow("description", zone.GetDescription())
	table.AddRow("internal", strconv.FormatBool(zone.GetInternal()))
	if soa := zone.GetRecords().GetSoa(); soa != nil {
		table.AddRow("soa", joinFields(soa.GetMname(), soa.GetRname(), uintField(soa.GetSerial()),
			uintField(soa.GetRefresh()), uintField(soa.GetRetry()), uintField(soa.GetExpire()), uintField(soa.GetMinimumTtl())))
	}
	table.AddRow("records", strconv.Itoa(countRecords(zone.GetRecords())))
	return table
}

// countRecords counts every record a zone holds, the SOA included.
func countRecords(set *platformv1.RecordSet) int {
	if set == nil {
		return 0
	}
	count := len(set.GetARecords()) + len(set.GetAaaaRecords()) + len(set.GetCnameRecords()) +
		len(set.GetMxRecords()) + len(set.GetNsRecords()) + len(set.GetTxtRecords()) +
		len(set.GetSrvRecords()) + len(set.GetCaaRecords()) + len(set.GetTlsaRecords()) +
		len(set.GetDnskeyRecords()) + len(set.GetDsRecords()) + len(set.GetRrsigRecords()) +
		len(set.GetNsecRecords()) + len(set.GetNsec3Records()) + len(set.GetNsec3ParamRecords())
	if set.GetSoa() != nil {
		count++
	}
	return count
}
