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

// Package dns provides the platformctl dns command group: zone, record and
// DNSSEC management, resolution and registration against the platform's
// authoritative DNS service. Every command calls DNSService through the SDK
// client, so the global --transport flag selects REST, gRPC, QUIC, MCP, the
// Unix socket or an embedded daemon with identical behaviour; a capability a
// transport does not carry fails with that transport's error
// (docs/dns/api.md §2).
package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// defaultCLITimeout is the context deadline for all DNS CLI operations.
const defaultCLITimeout = 30 * time.Second

// newCLIContext returns a context with the default CLI timeout and its cancel
// function. Callers must defer cancel().
func newCLIContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultCLITimeout)
}

// clientFactory builds a DNSService client from the common CLI flags. Tests
// replace it with a fake to exercise command wiring without a daemon.
type clientFactory func(flags *cli.CommonFlags) (platformv1.DNSServiceClient, func() error, error)

// newDNSClient is the production client factory. It honours the global
// --transport/--server flags via cli.NewBaseCommand.
var newDNSClient clientFactory = func(flags *cli.CommonFlags) (platformv1.DNSServiceClient, func() error, error) {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return nil, nil, err
	}
	return base.Client().DNS(), base.Close, nil
}

// outputFunc renders a command result. Tests replace it to capture output.
type outputFunc func(flags *cli.CommonFlags, v any) error

// output is the production output renderer.
var output outputFunc = func(flags *cli.CommonFlags, v any) error {
	return render(os.Stdout, flags, v)
}

// render writes v to w in the selected output format.
func render(w io.Writer, flags *cli.CommonFlags, v any) error {
	return cli.NewPrinterWithWriter(flags.OutputFormat, flags.NoColor, w).Print(v)
}

// protoJSON renders responses with their proto field names, the names the
// REST reference and the proto use.
var protoJSON = protojson.MarshalOptions{UseProtoNames: true}

// respond renders a DNSService response: the whole response message for JSON
// or YAML, the table otherwise.
func respond(flags *cli.CommonFlags, msg proto.Message, table *cli.TableData) error {
	if !isStructuredOutput(flags) {
		return output(flags, table)
	}
	view, err := protoView(msg)
	if err != nil {
		return err
	}
	return output(flags, view)
}

// protoView converts a proto message to a generic value through protojson, so
// the oneof record bodies and enum names render as the proto defines them.
// Numbers stay json.Number, so a uint32 TTL is printed exactly.
func protoView(msg proto.Message) (any, error) {
	raw, err := protoJSON.Marshal(msg)
	if err != nil {
		return nil, &ErrRenderFailed{Err: err}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var view any
	if err := decoder.Decode(&view); err != nil {
		return nil, &ErrRenderFailed{Err: err}
	}
	return view, nil
}

// isStructuredOutput reports whether the caller asked for JSON or YAML.
func isStructuredOutput(flags *cli.CommonFlags) bool {
	if flags == nil {
		return false
	}
	return flags.OutputFormat == cli.OutputFormatJSON || flags.OutputFormat == cli.OutputFormatYAML
}

// call opens a DNSService client, runs fn under the CLI deadline and closes
// the client.
func call(flags *cli.CommonFlags, fn func(ctx context.Context, client platformv1.DNSServiceClient) error) error {
	client, closeFn, err := newDNSClient(flags)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()
	return fn(ctx, client)
}

// NewCommand creates the root dns command.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Authoritative DNS zones, records and DNSSEC",
		Long: `Manage the platform's authoritative DNS service.

Zones, records, DNSSEC signing, resolution and host registration all go
through DNSService over the transport the active context selects
(--transport). See docs/dns/cli.md.

Examples:
  platformctl dns zone create example.test. --ttl 3600 --soa-mname ns1.example.test. --soa-rname admin.example.test.
  platformctl dns zone list
  platformctl dns record add example.test. --type A --name www --value 192.0.2.10
  platformctl dns record list example.test. --type A
  platformctl dns dnssec sign example.test.
  platformctl dns resolve www.example.test. --type A`,
	}

	cmd.AddCommand(newZoneCommand(getFlags))
	cmd.AddCommand(newRecordCommand(getFlags))
	cmd.AddCommand(newDNSSECCommand(getFlags))
	cmd.AddCommand(newResolveCommand(getFlags))
	cmd.AddCommand(newRegisterCommand(getFlags))

	return cmd
}
