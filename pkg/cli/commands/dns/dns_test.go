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
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errRPC is the transport error the fake returns when err is set.
var errRPC = errors.New("rpc unavailable")

// fakeDNSClient records each request by method name and returns the canned
// response, or err when it is set.
type fakeDNSClient struct {
	err       error
	requests  map[string]any
	zone      *platformv1.Zone
	zones     []*platformv1.Zone
	records   []*platformv1.Record
	dnssec    *platformv1.DNSSECStatus
	resolved  []*platformv1.Record
	succeeded bool
}

func newFakeDNSClient() *fakeDNSClient {
	return &fakeDNSClient{
		requests:  map[string]any{},
		zone:      &platformv1.Zone{Name: "example.test.", Id: 7, Ttl: 3600},
		succeeded: true,
	}
}

func (f *fakeDNSClient) record(method string, req any) error {
	f.requests[method] = req
	return f.err
}

func (f *fakeDNSClient) status() *platformv1.Status {
	return &platformv1.Status{Success: f.succeeded}
}

func (f *fakeDNSClient) CreateZone(_ context.Context, req *platformv1.CreateZoneRequest, _ ...grpc.CallOption) (*platformv1.CreateZoneResponse, error) {
	if err := f.record("CreateZone", req); err != nil {
		return nil, err
	}
	return &platformv1.CreateZoneResponse{Status: f.status(), Zone: f.zone}, nil
}

func (f *fakeDNSClient) GetZone(_ context.Context, req *platformv1.GetZoneRequest, _ ...grpc.CallOption) (*platformv1.GetZoneResponse, error) {
	if err := f.record("GetZone", req); err != nil {
		return nil, err
	}
	return &platformv1.GetZoneResponse{Zone: f.zone}, nil
}

func (f *fakeDNSClient) UpdateZone(_ context.Context, req *platformv1.UpdateZoneRequest, _ ...grpc.CallOption) (*platformv1.UpdateZoneResponse, error) {
	if err := f.record("UpdateZone", req); err != nil {
		return nil, err
	}
	return &platformv1.UpdateZoneResponse{Status: f.status(), Zone: f.zone}, nil
}

func (f *fakeDNSClient) DeleteZone(_ context.Context, req *platformv1.DeleteZoneRequest, _ ...grpc.CallOption) (*platformv1.DeleteZoneResponse, error) {
	if err := f.record("DeleteZone", req); err != nil {
		return nil, err
	}
	return &platformv1.DeleteZoneResponse{Status: f.status()}, nil
}

func (f *fakeDNSClient) ListZones(_ context.Context, req *platformv1.ListZonesRequest, _ ...grpc.CallOption) (*platformv1.ListZonesResponse, error) {
	if err := f.record("ListZones", req); err != nil {
		return nil, err
	}
	return &platformv1.ListZonesResponse{Zones: f.zones}, nil
}

func (f *fakeDNSClient) AddRecord(_ context.Context, req *platformv1.AddRecordRequest, _ ...grpc.CallOption) (*platformv1.AddRecordResponse, error) {
	if err := f.record("AddRecord", req); err != nil {
		return nil, err
	}
	return &platformv1.AddRecordResponse{Status: f.status(), Zone: f.zone}, nil
}

func (f *fakeDNSClient) DeleteRecord(_ context.Context, req *platformv1.DeleteRecordRequest, _ ...grpc.CallOption) (*platformv1.DeleteRecordResponse, error) {
	if err := f.record("DeleteRecord", req); err != nil {
		return nil, err
	}
	return &platformv1.DeleteRecordResponse{Status: f.status(), Zone: f.zone}, nil
}

func (f *fakeDNSClient) UpdateRecord(_ context.Context, req *platformv1.UpdateRecordRequest, _ ...grpc.CallOption) (*platformv1.UpdateRecordResponse, error) {
	if err := f.record("UpdateRecord", req); err != nil {
		return nil, err
	}
	return &platformv1.UpdateRecordResponse{Status: f.status(), Zone: f.zone}, nil
}

func (f *fakeDNSClient) ListRecords(_ context.Context, req *platformv1.ListRecordsRequest, _ ...grpc.CallOption) (*platformv1.ListRecordsResponse, error) {
	if err := f.record("ListRecords", req); err != nil {
		return nil, err
	}
	return &platformv1.ListRecordsResponse{Records: f.records}, nil
}

func (f *fakeDNSClient) SignZone(_ context.Context, req *platformv1.SignZoneRequest, _ ...grpc.CallOption) (*platformv1.SignZoneResponse, error) {
	if err := f.record("SignZone", req); err != nil {
		return nil, err
	}
	return &platformv1.SignZoneResponse{Status: f.status(), Zone: f.zone}, nil
}

func (f *fakeDNSClient) GetDNSSECStatus(_ context.Context, req *platformv1.GetDNSSECStatusRequest, _ ...grpc.CallOption) (*platformv1.GetDNSSECStatusResponse, error) {
	if err := f.record("GetDNSSECStatus", req); err != nil {
		return nil, err
	}
	return &platformv1.GetDNSSECStatusResponse{Status: f.dnssec}, nil
}

func (f *fakeDNSClient) Resolve(_ context.Context, req *platformv1.ResolveRequest, _ ...grpc.CallOption) (*platformv1.ResolveResponse, error) {
	if err := f.record("Resolve", req); err != nil {
		return nil, err
	}
	return &platformv1.ResolveResponse{Records: f.resolved, Authoritative: true}, nil
}

func (f *fakeDNSClient) Register(_ context.Context, req *platformv1.RegisterRequest, _ ...grpc.CallOption) (*platformv1.RegisterResponse, error) {
	if err := f.record("Register", req); err != nil {
		return nil, err
	}
	return &platformv1.RegisterResponse{Status: f.status(), Zone: f.zone}, nil
}

// withFakeClient installs fake as the client factory and captures output.
func withFakeClient(t *testing.T, fake *fakeDNSClient) *any {
	t.Helper()
	origFactory := newDNSClient
	origOutput := output
	var lastOutput any
	newDNSClient = func(*cli.CommonFlags) (platformv1.DNSServiceClient, func() error, error) {
		return fake, func() error { return nil }, nil
	}
	output = func(_ *cli.CommonFlags, v any) error {
		lastOutput = v
		return nil
	}
	t.Cleanup(func() {
		newDNSClient = origFactory
		output = origOutput
	})
	return &lastOutput
}

// execute runs the dns command tree with table output.
func execute(t *testing.T, args ...string) error {
	t.Helper()
	return executeWithFlags(t, &cli.CommonFlags{}, args...)
}

// executeWithFlags runs the dns command tree with the given global flags.
func executeWithFlags(t *testing.T, flags *cli.CommonFlags, args ...string) error {
	t.Helper()
	cmd := NewCommand(func() *cli.CommonFlags { return flags })
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd.Execute()
}

// requireTable asserts the captured output is a table and returns it.
func requireTable(t *testing.T, out *any) *cli.TableData {
	t.Helper()
	table, ok := (*out).(*cli.TableData)
	if !ok {
		t.Fatalf("output = %T, want *cli.TableData", *out)
	}
	return table
}

// tableValue returns the VALUE of a FIELD/VALUE table row.
func tableValue(t *testing.T, table *cli.TableData, field string) string {
	t.Helper()
	for _, row := range table.Rows {
		if row[0] == field {
			return row[1]
		}
	}
	t.Fatalf("table has no %q row: %v", field, table.Rows)
	return ""
}

// requireRPCError asserts err wraps the fake's transport error.
func requireRPCError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, errRPC) {
		t.Fatalf("err = %v, want it to wrap %v", err, errRPC)
	}
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) {
		t.Fatalf("err = %T, want *WrappedError", err)
	}
}

func TestNewCommand_RegistersEveryVerb(t *testing.T) {
	cmd := NewCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	want := []string{
		"zone create", "zone get", "zone update", "zone delete", "zone list",
		"record add", "record update", "record delete", "record list", "record get",
		"dnssec sign", "dnssec status", "resolve", "register",
	}
	for _, path := range want {
		found, _, err := cmd.Find(strings.Fields(path))
		if err != nil || found.Name() != strings.Fields(path)[len(strings.Fields(path))-1] {
			t.Errorf("dns %s is not registered (err=%v)", path, err)
		}
	}
}

func TestNewCommand_MissingArgumentFails(t *testing.T) {
	withFakeClient(t, newFakeDNSClient())
	if err := execute(t, "zone", "create"); err == nil {
		t.Fatal("zone create without a zone name succeeded")
	}
}

func TestCall_FactoryError(t *testing.T) {
	origFactory := newDNSClient
	t.Cleanup(func() { newDNSClient = origFactory })
	errFactory := errors.New("no daemon")
	newDNSClient = func(*cli.CommonFlags) (platformv1.DNSServiceClient, func() error, error) {
		return nil, nil, errFactory
	}
	if err := execute(t, "zone", "list"); !errors.Is(err, errFactory) {
		t.Fatalf("err = %v, want %v", err, errFactory)
	}
}

func TestCall_ClosesClient(t *testing.T) {
	origFactory := newDNSClient
	t.Cleanup(func() { newDNSClient = origFactory })
	withFakeClient(t, newFakeDNSClient())
	closed := false
	fake := newFakeDNSClient()
	newDNSClient = func(*cli.CommonFlags) (platformv1.DNSServiceClient, func() error, error) {
		return fake, func() error { closed = true; return nil }, nil
	}
	if err := execute(t, "zone", "get", "example.test."); err != nil {
		t.Fatalf("zone get: %v", err)
	}
	if !closed {
		t.Fatal("the client was not closed")
	}
}

func TestRespond_JSONUsesProtoNames(t *testing.T) {
	fake := newFakeDNSClient()
	fake.records = []*platformv1.Record{{
		Type:   platformv1.RecordType_RECORD_TYPE_A,
		Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.0.2.10", Ttl: 300}},
	}}
	out := withFakeClient(t, fake)
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	if err := executeWithFlags(t, flags, "record", "list", "example.test."); err != nil {
		t.Fatalf("record list: %v", err)
	}
	view, ok := (*out).(map[string]any)
	if !ok {
		t.Fatalf("output = %T, want map", *out)
	}
	records, ok := view["records"].([]any)
	if !ok || len(records) != 1 {
		t.Fatalf("records = %v", view["records"])
	}
	record := records[0].(map[string]any)
	if record["type"] != "RECORD_TYPE_A" {
		t.Errorf("type = %v, want RECORD_TYPE_A", record["type"])
	}
	a := record["a"].(map[string]any)
	if a["value"] != "192.0.2.10" || a["ttl"].(interface{ String() string }).String() != "300" {
		t.Errorf("a = %v", a)
	}
}

func TestRespond_YAMLIsStructured(t *testing.T) {
	out := withFakeClient(t, newFakeDNSClient())
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatYAML}
	if err := executeWithFlags(t, flags, "zone", "get", "example.test."); err != nil {
		t.Fatalf("zone get: %v", err)
	}
	view, ok := (*out).(map[string]any)
	if !ok {
		t.Fatalf("output = %T, want map", *out)
	}
	zone := view["zone"].(map[string]any)
	if zone["name"] != "example.test." {
		t.Errorf("zone = %v", zone)
	}
}

func TestProtoView_InvalidUTF8Fails(t *testing.T) {
	_, err := protoView(&platformv1.GetZoneRequest{Name: "bad\xff"})
	var renderErr *ErrRenderFailed
	if !errors.As(err, &renderErr) {
		t.Fatalf("err = %v, want *ErrRenderFailed", err)
	}
}

func TestRespond_RenderErrorReturned(t *testing.T) {
	withFakeClient(t, newFakeDNSClient())
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	err := respond(flags, &platformv1.GetZoneRequest{Name: "bad\xff"}, nil)
	var renderErr *ErrRenderFailed
	if !errors.As(err, &renderErr) {
		t.Fatalf("err = %v, want *ErrRenderFailed", err)
	}
}

func TestIsStructuredOutput(t *testing.T) {
	cases := map[string]struct {
		flags *cli.CommonFlags
		want  bool
	}{
		"nil":   {nil, false},
		"table": {&cli.CommonFlags{OutputFormat: cli.OutputFormatTable}, false},
		"json":  {&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, true},
		"yaml":  {&cli.CommonFlags{OutputFormat: cli.OutputFormatYAML}, true},
	}
	for name, tc := range cases {
		if got := isStructuredOutput(tc.flags); got != tc.want {
			t.Errorf("%s: isStructuredOutput = %v, want %v", name, got, tc.want)
		}
	}
}

func TestRender_WritesTable(t *testing.T) {
	var buf bytes.Buffer
	table := cli.NewTableData("FIELD", "VALUE")
	table.AddRow("name", "example.test.")
	if err := render(&buf, &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}, table); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "example.test.") {
		t.Fatalf("render wrote %q", buf.String())
	}
}

func TestRender_JSONOfUnencodableFails(t *testing.T) {
	var buf bytes.Buffer
	if err := render(&buf, &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, make(chan int)); err == nil {
		t.Fatal("render of a channel as JSON succeeded")
	}
}
