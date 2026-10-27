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
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestRecordAdd_EveryWritableType(t *testing.T) {
	cases := []struct {
		args  []string
		want  *platformv1.Record
		value string
	}{
		{
			args:  []string{"--type", "A", "--name", "www", "--value", "192.0.2.10", "--ttl", "300"},
			want:  &platformv1.Record{Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.0.2.10", Ttl: 300}}},
			value: "192.0.2.10",
		},
		{
			args:  []string{"--type", "aaaa", "--name", "www", "--value", "2001:db8::10"},
			want:  &platformv1.Record{Record: &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: "www", Value: "2001:db8::10", Ttl: defaultRecordTTL}}},
			value: "2001:db8::10",
		},
		{
			args:  []string{"--type", "CNAME", "--name", "web", "--value", "www.example.test."},
			want:  &platformv1.Record{Record: &platformv1.Record_Cname{Cname: &platformv1.CNAMERecord{Name: "web", Value: "www.example.test.", Ttl: defaultRecordTTL}}},
			value: "www.example.test.",
		},
		{
			args:  []string{"--type", "MX", "--name", "example.test.", "--value", "mail.example.test.", "--priority", "10"},
			want:  &platformv1.Record{Record: &platformv1.Record_Mx{Mx: &platformv1.MXRecord{Name: "example.test.", Value: "mail.example.test.", Priority: 10, Ttl: defaultRecordTTL}}},
			value: "10 mail.example.test.",
		},
		{
			args:  []string{"--type", "NS", "--name", "sub", "--value", "ns1.example.test."},
			want:  &platformv1.Record{Record: &platformv1.Record_Ns{Ns: &platformv1.NSRecord{Name: "sub", Value: "ns1.example.test.", Ttl: defaultRecordTTL}}},
			value: "ns1.example.test.",
		},
		{
			args:  []string{"--type", "TXT", "--name", "example.test.", "--value", "v=spf1 -all"},
			want:  &platformv1.Record{Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: "example.test.", Value: "v=spf1 -all", Ttl: defaultRecordTTL}}},
			value: "v=spf1 -all",
		},
		{
			args: []string{"--type", "SRV", "--name", "_sip._tcp", "--value", "sip.example.test.", "--priority", "10", "--weight", "5", "--port", "5060"},
			want: &platformv1.Record{Record: &platformv1.Record_Srv{Srv: &platformv1.SRVRecord{
				Name: "_sip._tcp", Target: "sip.example.test.", Priority: 10, Weight: 5, Port: 5060, Ttl: defaultRecordTTL,
			}}},
			value: "10 5 5060 sip.example.test.",
		},
		{
			args: []string{"--type", "CAA", "--name", "example.test.", "--flags", "128", "--tag", "issue", "--value", "ca.example.test"},
			want: &platformv1.Record{Record: &platformv1.Record_Caa{Caa: &platformv1.CAARecord{
				Name: "example.test.", Flags: 128, Tag: "issue", Value: "ca.example.test", Ttl: defaultRecordTTL,
			}}},
			value: "128 issue ca.example.test",
		},
		{
			args: []string{"--type", "TLSA", "--name", "_443._tcp.www", "--usage", "3", "--selector", "1", "--matching-type", "1", "--value", "abcd"},
			want: &platformv1.Record{Record: &platformv1.Record_Tlsa{Tlsa: &platformv1.TLSARecord{
				Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "abcd", Ttl: defaultRecordTTL,
			}}},
			value: "3 1 1 abcd",
		},
	}
	for _, tc := range cases {
		t.Run(tc.args[1], func(t *testing.T) {
			fake := newFakeDNSClient()
			out := withFakeClient(t, fake)
			args := append([]string{"record", "add", "example.test."}, tc.args...)
			if err := execute(t, args...); err != nil {
				t.Fatalf("record add: %v", err)
			}
			req := fake.requests["AddRecord"].(*platformv1.AddRecordRequest)
			got := req.GetRecord()
			if recordTypeName(got.GetType()) != strings.ToUpper(tc.args[1]) {
				t.Fatalf("type = %v, want %s", got.GetType(), tc.args[1])
			}
			tc.want.Type = got.GetType()
			if req.GetZoneName() != "example.test." || !proto.Equal(got, tc.want) {
				t.Fatalf("request = %v, want record %v", req, tc.want)
			}
			table := requireTable(t, out)
			if len(table.Rows) != 1 || table.Rows[0][2] != tc.value {
				t.Fatalf("rows = %v, want value %q", table.Rows, tc.value)
			}
		})
	}
}

func TestRecordAdd_InvalidFlags(t *testing.T) {
	cases := map[string]struct {
		args  []string
		check func(error) bool
	}{
		"missing type": {
			[]string{"--name", "www"},
			func(err error) bool { var e *ErrFlagRequired; return errors.As(err, &e) && e.Flag == "type" },
		},
		"missing name": {
			[]string{"--type", "A"},
			func(err error) bool { var e *ErrFlagRequired; return errors.As(err, &e) && e.Flag == "name" },
		},
		"unknown type": {
			[]string{"--type", "BOGUS", "--name", "www"},
			func(err error) bool { var e *ErrUnknownRecordType; return errors.As(err, &e) && e.Type == "BOGUS" },
		},
		"unspecified type": {
			[]string{"--type", "unspecified", "--name", "www"},
			func(err error) bool { var e *ErrUnknownRecordType; return errors.As(err, &e) },
		},
		"SOA not writable": {
			[]string{"--type", "SOA", "--name", "example.test."},
			func(err error) bool { var e *ErrRecordTypeNotWritable; return errors.As(err, &e) && e.Type == "SOA" },
		},
		"RRSIG not writable": {
			[]string{"--type", "RRSIG", "--name", "www"},
			func(err error) bool { var e *ErrRecordTypeNotWritable; return errors.As(err, &e) && e.Type == "RRSIG" },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fake := newFakeDNSClient()
			withFakeClient(t, fake)
			err := execute(t, append([]string{"record", "add", "example.test."}, tc.args...)...)
			if !tc.check(err) {
				t.Fatalf("err = %v (%T)", err, err)
			}
			if _, called := fake.requests["AddRecord"]; called {
				t.Fatal("AddRecord was called")
			}
		})
	}
}

func TestRecordAdd_RPCError(t *testing.T) {
	fake := newFakeDNSClient()
	fake.err = errRPC
	withFakeClient(t, fake)
	requireRPCError(t, execute(t, "record", "add", "example.test.", "--type", "A", "--name", "www", "--value", "192.0.2.10"))
}

func TestRecordUpdate_OldRecordIsTypeAndName(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	if err := execute(t, "record", "update", "example.test.", "--type", "A", "--name", "www", "--value", "192.0.2.20", "--ttl", "600"); err != nil {
		t.Fatalf("record update: %v", err)
	}
	req := fake.requests["UpdateRecord"].(*platformv1.UpdateRecordRequest)
	old, updated := req.GetOldRecord(), req.GetNewRecord()
	if old.GetType() != platformv1.RecordType_RECORD_TYPE_A || old.GetA().GetName() != "www" || old.GetA().GetValue() != "" {
		t.Errorf("old record = %v", old)
	}
	if updated.GetA().GetValue() != "192.0.2.20" || updated.GetA().GetTtl() != 600 || req.GetZoneName() != "example.test." {
		t.Errorf("request = %v", req)
	}
}

func TestRecordUpdate_Errors(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	var flagErr *ErrFlagRequired
	if err := execute(t, "record", "update", "example.test.", "--type", "A"); !errors.As(err, &flagErr) {
		t.Fatalf("err = %v, want *ErrFlagRequired", err)
	}
	fake.err = errRPC
	requireRPCError(t, execute(t, "record", "update", "example.test.", "--type", "A", "--name", "www", "--value", "192.0.2.20"))
}

func TestRecordDelete_SendsTypeAndName(t *testing.T) {
	fake := newFakeDNSClient()
	out := withFakeClient(t, fake)
	if err := execute(t, "record", "delete", "example.test.", "--type", "txt", "--name", "example.test."); err != nil {
		t.Fatalf("record delete: %v", err)
	}
	req := fake.requests["DeleteRecord"].(*platformv1.DeleteRecordRequest)
	if req.GetZoneName() != "example.test." || req.GetType() != platformv1.RecordType_RECORD_TYPE_TXT || req.GetName() != "example.test." {
		t.Errorf("request = %v", req)
	}
	table := requireTable(t, out)
	if len(table.Rows) != 1 || table.Rows[0][0] != "TXT" || table.Rows[0][2] != "true" {
		t.Errorf("rows = %v", table.Rows)
	}
}

func TestRecordDelete_Errors(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	var flagErr *ErrFlagRequired
	if err := execute(t, "record", "delete", "example.test.", "--name", "www"); !errors.As(err, &flagErr) || flagErr.Flag != "type" {
		t.Fatalf("missing type: err = %v", err)
	}
	if err := execute(t, "record", "delete", "example.test.", "--type", "A"); !errors.As(err, &flagErr) || flagErr.Flag != "name" {
		t.Fatalf("missing name: err = %v", err)
	}
	if _, called := fake.requests["DeleteRecord"]; called {
		t.Fatal("DeleteRecord was called")
	}
	fake.err = errRPC
	requireRPCError(t, execute(t, "record", "delete", "example.test.", "--type", "A", "--name", "www"))
}

func TestRecordList_TypeAndPagination(t *testing.T) {
	fake := newFakeDNSClient()
	fake.records = []*platformv1.Record{
		{Type: platformv1.RecordType_RECORD_TYPE_A, Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.0.2.10", Ttl: 60}}},
		{Type: platformv1.RecordType_RECORD_TYPE_DNSKEY},
	}
	out := withFakeClient(t, fake)
	if err := execute(t, "record", "list", "example.test.", "--type", "A", "--page", "1", "--page-size", "10"); err != nil {
		t.Fatalf("record list: %v", err)
	}
	req := fake.requests["ListRecords"].(*platformv1.ListRecordsRequest)
	if req.GetType() != platformv1.RecordType_RECORD_TYPE_A || req.GetPagination().GetPageSize() != 10 || req.GetPagination().GetPage() != 1 {
		t.Errorf("request = %v", req)
	}
	table := requireTable(t, out)
	if len(table.Rows) != 2 || table.Rows[0][1] != "www" || table.Rows[0][3] != "60" || table.Rows[1][0] != "DNSKEY" || table.Rows[1][1] != "" {
		t.Errorf("rows = %v", table.Rows)
	}
}

func TestRecordList_AllTypesWithoutPagination(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	if err := execute(t, "record", "list", "example.test."); err != nil {
		t.Fatalf("record list: %v", err)
	}
	req := fake.requests["ListRecords"].(*platformv1.ListRecordsRequest)
	if req.GetType() != platformv1.RecordType_RECORD_TYPE_UNSPECIFIED || req.GetPagination() != nil {
		t.Errorf("request = %v", req)
	}
}

func TestRecordList_Errors(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	var typeErr *ErrUnknownRecordType
	if err := execute(t, "record", "list", "example.test.", "--type", "BOGUS"); !errors.As(err, &typeErr) {
		t.Fatalf("err = %v, want *ErrUnknownRecordType", err)
	}
	fake.err = errRPC
	requireRPCError(t, execute(t, "record", "list", "example.test."))
}

func TestRecordGet_KeepsMatchingName(t *testing.T) {
	fake := newFakeDNSClient()
	fake.records = []*platformv1.Record{
		{Type: platformv1.RecordType_RECORD_TYPE_A, Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "api", Value: "192.0.2.5"}}},
		{Type: platformv1.RecordType_RECORD_TYPE_A, Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.0.2.10"}}},
	}
	out := withFakeClient(t, fake)
	if err := execute(t, "record", "get", "example.test.", "--type", "A", "--name", "www"); err != nil {
		t.Fatalf("record get: %v", err)
	}
	if fake.requests["ListRecords"].(*platformv1.ListRecordsRequest).GetType() != platformv1.RecordType_RECORD_TYPE_A {
		t.Errorf("request = %v", fake.requests["ListRecords"])
	}
	table := requireTable(t, out)
	if len(table.Rows) != 1 || table.Rows[0][2] != "192.0.2.10" {
		t.Errorf("rows = %v", table.Rows)
	}
}

func TestRecordGet_Errors(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	var notFound *ErrRecordNotFound
	if err := execute(t, "record", "get", "example.test.", "--type", "A", "--name", "www"); !errors.As(err, &notFound) || notFound.Name != "www" || notFound.Type != "A" {
		t.Fatalf("err = %v, want *ErrRecordNotFound", err)
	}
	var flagErr *ErrFlagRequired
	if err := execute(t, "record", "get", "example.test.", "--name", "www"); !errors.As(err, &flagErr) || flagErr.Flag != "type" {
		t.Fatalf("missing type: err = %v", err)
	}
	if err := execute(t, "record", "get", "example.test.", "--type", "A"); !errors.As(err, &flagErr) || flagErr.Flag != "name" {
		t.Fatalf("missing name: err = %v", err)
	}
	fake.err = errRPC
	requireRPCError(t, execute(t, "record", "get", "example.test.", "--type", "A", "--name", "www"))
}

func TestParseRecordType(t *testing.T) {
	got, err := parseRecordType("nsec3param")
	if err != nil || got != platformv1.RecordType_RECORD_TYPE_NSEC3PARAM {
		t.Fatalf("parseRecordType(nsec3param) = %v, %v", got, err)
	}
	got, err = parseRecordType("")
	if err != nil || got != platformv1.RecordType_RECORD_TYPE_UNSPECIFIED {
		t.Fatalf("parseRecordType(\"\") = %v, %v", got, err)
	}
	var typeErr *ErrUnknownRecordType
	if _, err := parseRecordType("RECORD_TYPE_A"); !errors.As(err, &typeErr) {
		t.Fatalf("parseRecordType(RECORD_TYPE_A) err = %v, want *ErrUnknownRecordType", err)
	}
}

func TestViewRecord_UnknownTypeIsEmpty(t *testing.T) {
	if row := viewRecord(&platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_NSEC}); row != (recordRow{}) {
		t.Fatalf("row = %v", row)
	}
	if row := viewRecord(nil); row != (recordRow{}) {
		t.Fatalf("nil row = %v", row)
	}
}
