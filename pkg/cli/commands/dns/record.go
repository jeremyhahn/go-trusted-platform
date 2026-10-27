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
	"github.com/spf13/pflag"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// defaultRecordTTL is the record TTL when --ttl is not given.
const defaultRecordTTL = 3600

// newRecordCommand creates the dns record command group.
func newRecordCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "record",
		Short: "Add, update, delete, list and show records in a zone",
	}
	cmd.AddCommand(newRecordAddCommand(getFlags))
	cmd.AddCommand(newRecordUpdateCommand(getFlags))
	cmd.AddCommand(newRecordDeleteCommand(getFlags))
	cmd.AddCommand(newRecordListCommand(getFlags))
	cmd.AddCommand(newRecordGetCommand(getFlags))
	return cmd
}

// addRecordDataFlags registers the flags that carry a record's data.
func addRecordDataFlags(fs *pflag.FlagSet, f *recordFlags) {
	fs.StringVar(&f.Type, "type", "", "record type: A, AAAA, CNAME, MX, NS, TXT, SRV, CAA or TLSA")
	fs.StringVar(&f.Name, "name", "", "record owner name, relative to the zone or fully qualified")
	fs.StringVar(&f.Value, "value", "", "record data: address, target, text, CAA value or TLSA hex data")
	fs.Uint32Var(&f.TTL, "ttl", defaultRecordTTL, "TTL in seconds")
	fs.Uint32Var(&f.Priority, "priority", 0, "MX or SRV priority")
	fs.Uint32Var(&f.Weight, "weight", 0, "SRV weight")
	fs.Uint32Var(&f.Port, "port", 0, "SRV port")
	fs.Uint32Var(&f.Flags, "flags", 0, "CAA flags")
	fs.StringVar(&f.Tag, "tag", "", "CAA tag: issue, issuewild or iodef")
	fs.Uint32Var(&f.Usage, "usage", 0, "TLSA certificate usage")
	fs.Uint32Var(&f.Selector, "selector", 0, "TLSA selector")
	fs.Uint32Var(&f.MatchingType, "matching-type", 0, "TLSA matching type")
}

// newRecordAddCommand creates the dns record add subcommand.
func newRecordAddCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var f recordFlags
	cmd := &cobra.Command{
		Use:   "add <zone>",
		Short: "Add a record to a zone (AddRecord)",
		Long: `Add a record to a zone. --type and --name are required; --value is
the record's data, and the type-specific flags carry the rest.

Examples:
  platformctl dns record add example.test. --type A --name www --value 192.0.2.10
  platformctl dns record add example.test. --type MX --name example.test. --value mail.example.test. --priority 10
  platformctl dns record add example.test. --type SRV --name _sip._tcp --value sip.example.test. --priority 10 --weight 5 --port 5060
  platformctl dns record add example.test. --type CAA --name example.test. --tag issue --value ca.example.test
  platformctl dns record add example.test. --type TLSA --name _443._tcp.www --usage 3 --selector 1 --matching-type 1 --value <hex>`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecordAdd(getFlags(), args[0], f)
		},
	}
	addRecordDataFlags(cmd.Flags(), &f)
	return cmd
}

// runRecordAdd executes the record add subcommand.
func runRecordAdd(flags *cli.CommonFlags, zone string, f recordFlags) error {
	record, err := buildRecord(f)
	if err != nil {
		return err
	}
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.AddRecord(ctx, &platformv1.AddRecordRequest{ZoneName: zone, Record: record})
		if err != nil {
			return &WrappedError{Msg: "failed to add record to zone " + zone, Err: err}
		}
		return respond(flags, resp, recordsTable([]*platformv1.Record{record}))
	})
}

// newRecordUpdateCommand creates the dns record update subcommand.
func newRecordUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var f recordFlags
	cmd := &cobra.Command{
		Use:   "update <zone>",
		Short: "Replace the record of a type and name (UpdateRecord)",
		Long: `Replace the record of a type and name with the one the flags describe.
The service finds the existing record by --type and --name.

Examples:
  platformctl dns record update example.test. --type A --name www --value 192.0.2.20 --ttl 600`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecordUpdate(getFlags(), args[0], f)
		},
	}
	addRecordDataFlags(cmd.Flags(), &f)
	return cmd
}

// runRecordUpdate executes the record update subcommand. The old record
// carries only the type and name the service matches on.
func runRecordUpdate(flags *cli.CommonFlags, zone string, f recordFlags) error {
	record, err := buildRecord(f)
	if err != nil {
		return err
	}
	old, err := buildRecord(recordFlags{Type: f.Type, Name: f.Name})
	if err != nil {
		return err
	}
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.UpdateRecord(ctx, &platformv1.UpdateRecordRequest{ZoneName: zone, OldRecord: old, NewRecord: record})
		if err != nil {
			return &WrappedError{Msg: "failed to update record in zone " + zone, Err: err}
		}
		return respond(flags, resp, recordsTable([]*platformv1.Record{record}))
	})
}

// newRecordDeleteCommand creates the dns record delete subcommand.
func newRecordDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var recordType, name string
	cmd := &cobra.Command{
		Use:   "delete <zone>",
		Short: "Delete the records of a type and name (DeleteRecord)",
		Long: `Delete the records of a type and name from a zone.

Examples:
  platformctl dns record delete example.test. --type A --name www`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecordDelete(getFlags(), args[0], recordType, name)
		},
	}
	cmd.Flags().StringVar(&recordType, "type", "", "record type")
	cmd.Flags().StringVar(&name, "name", "", "record owner name")
	return cmd
}

// runRecordDelete executes the record delete subcommand.
func runRecordDelete(flags *cli.CommonFlags, zone, mnemonic, name string) error {
	recordType, err := requireRecordType(mnemonic)
	if err != nil {
		return err
	}
	if name == "" {
		return &ErrFlagRequired{Flag: "name"}
	}
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.DeleteRecord(ctx, &platformv1.DeleteRecordRequest{ZoneName: zone, Type: recordType, Name: name})
		if err != nil {
			return &WrappedError{Msg: "failed to delete record from zone " + zone, Err: err}
		}
		table := cli.NewTableData("TYPE", "NAME", "DELETED")
		table.AddRow(recordTypeName(recordType), name, strconv.FormatBool(resp.GetStatus().GetSuccess()))
		return respond(flags, resp, table)
	})
}

// newRecordListCommand creates the dns record list subcommand.
func newRecordListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		recordType string
		page       uint32
		pageSize   uint32
	)
	cmd := &cobra.Command{
		Use:   "list <zone>",
		Short: "List a zone's records (ListRecords)",
		Long: `List a zone's records, optionally of one type.

Examples:
  platformctl dns record list example.test.
  platformctl dns record list example.test. --type A -o json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecordList(getFlags(), args[0], recordType, page, pageSize)
		},
	}
	cmd.Flags().StringVar(&recordType, "type", "", "only records of this type")
	cmd.Flags().Uint32Var(&page, "page", 0, "page number")
	cmd.Flags().Uint32Var(&pageSize, "page-size", 0, "records per page")
	return cmd
}

// runRecordList executes the record list subcommand.
func runRecordList(flags *cli.CommonFlags, zone, mnemonic string, page, pageSize uint32) error {
	recordType, err := parseRecordType(mnemonic)
	if err != nil {
		return err
	}
	req := &platformv1.ListRecordsRequest{ZoneName: zone, Type: recordType}
	if page > 0 || pageSize > 0 {
		req.Pagination = &platformv1.PaginationRequest{Page: page, PageSize: pageSize}
	}
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.ListRecords(ctx, req)
		if err != nil {
			return &WrappedError{Msg: "failed to list records in zone " + zone, Err: err}
		}
		return respond(flags, resp, recordsTable(resp.GetRecords()))
	})
}

// newRecordGetCommand creates the dns record get subcommand.
func newRecordGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var recordType, name string
	cmd := &cobra.Command{
		Use:   "get <zone>",
		Short: "Show the records of a type and name",
		Long: `Show the records of a type and name. DNSService has no single-record
read, so this lists the zone's records of --type and keeps those named --name.

Examples:
  platformctl dns record get example.test. --type A --name www`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecordGet(getFlags(), args[0], recordType, name)
		},
	}
	cmd.Flags().StringVar(&recordType, "type", "", "record type")
	cmd.Flags().StringVar(&name, "name", "", "record owner name")
	return cmd
}

// runRecordGet executes the record get subcommand.
func runRecordGet(flags *cli.CommonFlags, zone, mnemonic, name string) error {
	recordType, err := requireRecordType(mnemonic)
	if err != nil {
		return err
	}
	if name == "" {
		return &ErrFlagRequired{Flag: "name"}
	}
	return call(flags, func(ctx context.Context, client platformv1.DNSServiceClient) error {
		resp, err := client.ListRecords(ctx, &platformv1.ListRecordsRequest{ZoneName: zone, Type: recordType})
		if err != nil {
			return &WrappedError{Msg: "failed to read records in zone " + zone, Err: err}
		}
		matched := &platformv1.ListRecordsResponse{}
		for _, record := range resp.GetRecords() {
			if viewRecord(record).Name == name {
				matched.Records = append(matched.Records, record)
			}
		}
		if len(matched.Records) == 0 {
			return &ErrRecordNotFound{Zone: zone, Type: recordTypeName(recordType), Name: name}
		}
		return respond(flags, matched, recordsTable(matched.GetRecords()))
	})
}
