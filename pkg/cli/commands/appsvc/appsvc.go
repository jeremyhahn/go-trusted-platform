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

// Package appsvc implements the platformctl cache, scheduler and messaging
// command groups (#704). Each command calls one RPC of its service through
// the SDK client and prints the reply.
package appsvc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

// defaultCLITimeout bounds every RPC a command makes.
const defaultCLITimeout = 30 * time.Second

// newCLIContext returns a context with the default CLI timeout and its cancel
// function. Callers must defer cancel().
func newCLIContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultCLITimeout)
}

// clientFactory builds a service client from the common CLI flags. Tests
// replace the factories with fakes to exercise the commands without a daemon.
type clientFactory[C any] func(flags *cli.CommonFlags) (C, func() error, error)

// sdkClient returns the production factory for one service. It honors the
// global --protocol/--endpoint flags via cli.NewBaseCommand.
func sdkClient[C any](service func(platform.Client) C) clientFactory[C] {
	return func(flags *cli.CommonFlags) (C, func() error, error) {
		base, err := cli.NewBaseCommand(flags)
		if err != nil {
			var none C
			return none, nil, err
		}
		return service(base.Client()), base.Close, nil
	}
}

var (
	newCacheClient     = sdkClient(platform.Client.Cache)
	newSchedulerClient = sdkClient(platform.Client.Scheduler)
	newMessagingClient = sdkClient(platform.Client.Messaging)
)

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

// isStructuredOutput reports whether the caller asked for JSON or YAML, in
// which case the reply is printed whole instead of as a table.
func isStructuredOutput(flags *cli.CommonFlags) bool {
	if flags == nil {
		return false
	}
	return flags.OutputFormat == cli.OutputFormatJSON || flags.OutputFormat == cli.OutputFormatYAML
}

// newCommand creates a leaf command that runs with the common flags and its
// positional arguments.
func newCommand(getFlags func() *cli.CommonFlags, use, short string, args cobra.PositionalArgs,
	run func(flags *cli.CommonFlags, args []string) error) *cobra.Command {
	return &cobra.Command{
		Use:          use,
		Short:        short,
		Args:         args,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return run(getFlags(), args)
		},
	}
}

// call opens a client, sends one request and prints the reply: the proto3
// JSON mapping for JSON and YAML output, the table otherwise.
func call[C any, Q, R proto.Message](flags *cli.CommonFlags, open clientFactory[C], failure string,
	rpc func(C, context.Context, Q, ...grpc.CallOption) (R, error), request Q, table func(reply R) *cli.TableData) error {
	client, closeFn, err := open(flags)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	reply, err := rpc(client, ctx, request)
	if err != nil {
		return &WrappedError{Msg: failure, Err: err}
	}
	if isStructuredOutput(flags) {
		view, err := protoView(reply)
		if err != nil {
			return &WrappedError{Msg: "failed to render the reply", Err: err}
		}
		return output(flags, view)
	}
	return output(flags, table(reply))
}

// replyJSON is the proto3 JSON mapping the REST and MCP transports use, with
// every field present so a zero counter still prints.
var replyJSON = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}

// protoView converts a reply to the generic value the printer renders as JSON
// or YAML: proto field names, enum names, and 64-bit integers as strings.
func protoView(reply proto.Message) (map[string]any, error) {
	data, err := replyJSON.Marshal(reply)
	if err != nil {
		return nil, err
	}
	var view map[string]any
	if err := json.Unmarshal(data, &view); err != nil {
		return nil, err
	}
	return view, nil
}

// fieldsTable renders the fields of a message as a FIELD/VALUE table, in
// declaration order. A nil message renders an empty table.
func fieldsTable[M proto.Message](message M) *cli.TableData {
	table := cli.NewTableData("FIELD", "VALUE")
	m := message.ProtoReflect()
	if !m.IsValid() {
		return table
	}
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		table.AddRow(fieldLabel(field.Name()), formatField(field, m.Get(field)))
	}
	return table
}

// listTable renders one row per message, with the named fields as columns.
func listTable[M proto.Message](items []M, columns ...protoreflect.Name) *cli.TableData {
	headers := make([]string, len(columns))
	for i, column := range columns {
		headers[i] = strings.ToUpper(fieldLabel(column))
	}
	table := cli.NewTableData(headers...)
	for _, item := range items {
		m := item.ProtoReflect()
		row := make([]string, len(columns))
		for i, column := range columns {
			if field := m.Descriptor().Fields().ByName(column); field != nil {
				row[i] = formatField(field, m.Get(field))
			}
		}
		table.AddRow(row...)
	}
	return table
}

// confirmation renders the reply of an RPC that returns nothing as a one-row
// table naming what was done to which object.
func confirmation[R proto.Message](object, name, outcome string) func(R) *cli.TableData {
	return func(R) *cli.TableData {
		table := cli.NewTableData("FIELD", "VALUE")
		table.AddRow(object, name)
		table.AddRow("result", outcome)
		return table
	}
}

// Fields named for a unit carry it in the name; the label drops it and the
// value is rendered in it.
const (
	unixMillisSuffix = "_unix_ms"
	millisSuffix     = "_ms"
)

// fieldLabel is the table label of a field: its name without a unit suffix,
// with spaces for underscores.
func fieldLabel(name protoreflect.Name) string {
	label := strings.TrimSuffix(string(name), unixMillisSuffix)
	label = strings.TrimSuffix(label, millisSuffix)
	return strings.ReplaceAll(label, "_", " ")
}

// formatField renders one field value for a table cell.
func formatField(field protoreflect.FieldDescriptor, value protoreflect.Value) string {
	if field.IsMap() {
		return formatMap(value.Map())
	}
	if field.IsList() {
		return formatCount(value.List().Len())
	}
	name := string(field.Name())
	if field.Kind() == protoreflect.Int64Kind {
		if strings.HasSuffix(name, unixMillisSuffix) {
			return formatUnixMillis(value.Int())
		}
		if strings.HasSuffix(name, millisSuffix) {
			return (time.Duration(value.Int()) * time.Millisecond).String()
		}
	}
	if format, ok := kindFormatters[field.Kind()]; ok {
		return format(field, value)
	}
	return value.String()
}

// kindFormatters renders the kinds whose protoreflect string form is not
// readable. Every other kind prints as value.String().
var kindFormatters = map[protoreflect.Kind]func(protoreflect.FieldDescriptor, protoreflect.Value) string{
	protoreflect.EnumKind: func(field protoreflect.FieldDescriptor, value protoreflect.Value) string {
		return formatEnum(field.Enum(), value.Enum())
	},
	protoreflect.BytesKind: func(_ protoreflect.FieldDescriptor, value protoreflect.Value) string {
		return base64.StdEncoding.EncodeToString(value.Bytes())
	},
	protoreflect.MessageKind: func(_ protoreflect.FieldDescriptor, value protoreflect.Value) string {
		return protojson.Format(value.Message().Interface())
	},
}

// formatMap renders a string map as sorted key=value pairs.
func formatMap(m protoreflect.Map) string {
	pairs := make([]string, 0, m.Len())
	m.Range(func(key protoreflect.MapKey, value protoreflect.Value) bool {
		pairs = append(pairs, key.String()+"="+value.String())
		return true
	})
	sort.Strings(pairs)
	return strings.Join(pairs, ", ")
}

// formatCount renders the length of a repeated field.
func formatCount(n int) string {
	if n == 1 {
		return "1 entry"
	}
	return strconv.Itoa(n) + " entries"
}

// formatUnixMillis renders a UNIX time in milliseconds, reporting "never" for
// the zero value.
func formatUnixMillis(ms int64) string {
	if ms <= 0 {
		return "never"
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

// formatEnum renders an enum value by its CLI label, or by its number when
// the value is newer than this client.
func formatEnum(enum protoreflect.EnumDescriptor, number protoreflect.EnumNumber) string {
	value := enum.Values().ByNumber(number)
	if value == nil {
		return strconv.Itoa(int(number))
	}
	return enumLabel(enum, value)
}

// enumLabel is the CLI spelling of an enum value: its name without the enum's
// prefix, in lower kebab case, so SCHEDULER_JOB_TYPE_ONE_SHOT is one-shot.
func enumLabel(enum protoreflect.EnumDescriptor, value protoreflect.EnumValueDescriptor) string {
	name := strings.TrimPrefix(string(value.Name()), enumPrefix(enum))
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

// enumPrefix is the prefix every value name of an enum shares, taken from
// its zero value, which the style guide names <PREFIX>UNSPECIFIED.
func enumPrefix(enum protoreflect.EnumDescriptor) string {
	zero := enum.Values().ByNumber(0)
	if zero == nil {
		return ""
	}
	name := string(zero.Name())
	if !strings.HasSuffix(name, "UNSPECIFIED") {
		return ""
	}
	return strings.TrimSuffix(name, "UNSPECIFIED")
}

// enumLabels lists the labels a flag of the enum accepts. The zero value is
// left out: an unset flag already means it.
func enumLabels(enum protoreflect.EnumDescriptor) []string {
	values := enum.Values()
	labels := make([]string, 0, values.Len())
	for i := 0; i < values.Len(); i++ {
		if value := values.Get(i); value.Number() != 0 {
			labels = append(labels, enumLabel(enum, value))
		}
	}
	return labels
}

// parseEnum reads an enum flag by its label. An empty value is the zero
// value.
func parseEnum(flag string, enum protoreflect.EnumDescriptor, text string) (protoreflect.EnumNumber, error) {
	if text == "" {
		return 0, nil
	}
	values := enum.Values()
	for i := 0; i < values.Len(); i++ {
		if value := values.Get(i); value.Number() != 0 && enumLabel(enum, value) == text {
			return value.Number(), nil
		}
	}
	return 0, ErrInvalidFlag{Flag: flag, Value: text, Want: "one of " + strings.Join(enumLabels(enum), ", ")}
}

// parseTime reads an RFC 3339 time flag as UNIX milliseconds. An empty value
// is zero.
func parseTime(flag, text string) (int64, error) {
	if text == "" {
		return 0, nil
	}
	t, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return 0, ErrInvalidFlag{Flag: flag, Value: text, Want: "an RFC 3339 time such as 2026-10-13T08:00:00Z"}
	}
	return t.UnixMilli(), nil
}

// enumUsage is the help text of an enum flag.
func enumUsage(what string, enum protoreflect.EnumDescriptor) string {
	return what + ": " + strings.Join(enumLabels(enum), "|")
}
