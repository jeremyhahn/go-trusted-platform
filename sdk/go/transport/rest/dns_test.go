// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// dnsSent is the request the DNS test server received.
type dnsSent struct {
	method, path, query string
	body                map[string]interface{}
}

// dnsOverREST returns a DNS client whose REST transport talks to a server
// that records the request and answers with payload in the platform envelope.
func dnsOverREST(t *testing.T, payload string) (platformv1.DNSServiceClient, *dnsSent) {
	t.Helper()
	sent := &dnsSent{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		sent.method, sent.path, sent.query = r.Method, r.URL.EscapedPath(), r.URL.RawQuery
		raw, err := io.ReadAll(r.Body)
		if err != nil || (len(raw) > 0 && json.Unmarshal(raw, &sent.body) != nil) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"success":true,"payload":` + payload + `}`))
	})
	return platformv1.NewDNSServiceClient(a.Connection()), sent
}

const dnsZonePayload = `{"id":7,"name":"example.com.","ttl":3600,"internal":true,` +
	`"created_at":"2026-10-14T00:00:00Z","records":{` +
	`"soa":{"name":"@","mname":"ns1.example.com.","rname":"admin.example.com.","serial":2026101401,"ttl":3600},` +
	`"a":[{"name":"www","value":"10.0.0.1","ttl":300}],` +
	`"mx":[{"name":"@","value":"mail.example.com.","priority":10,"ttl":300}]}}`

const dnsRecordsPayload = `{"records":[` +
	`{"type":"A","a":{"name":"www","value":"10.0.0.1","ttl":300}},` +
	`{"type":"MX","mx":{"name":"@","value":"mail.example.com.","priority":10,"ttl":300}}],` +
	`"authoritative":true}`

// TestDNS_SDKOverREST_IdentifiersTravelInThePath: each record and zone call
// reaches the route the webservice serves, with the zone, record type and
// record name in the path and the filters in the query.
func TestDNS_SDKOverREST_IdentifiersTravelInThePath(t *testing.T) {
	cases := []struct {
		name      string
		payload   string
		call      func(platformv1.DNSServiceClient) error
		method    string
		path      string
		query     string
		bodyEmpty bool
	}{
		{
			name:    "DeleteZone",
			payload: `{"success":true,"message":"zone deleted successfully"}`,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.DeleteZone(context.Background(), &platformv1.DeleteZoneRequest{Name: "example.com."})
				return err
			},
			method: http.MethodDelete, path: "/api/v1/dns/zones/example.com.", bodyEmpty: true,
		},
		{
			name:    "DeleteRecord",
			payload: dnsZonePayload,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.DeleteRecord(context.Background(), &platformv1.DeleteRecordRequest{
					ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_AAAA, Name: "www"})
				return err
			},
			method: http.MethodDelete, path: "/api/v1/dns/zones/example.com./records/AAAA/www", bodyEmpty: true,
		},
		{
			name:    "ListRecords filtered",
			payload: dnsRecordsPayload,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.ListRecords(context.Background(), &platformv1.ListRecordsRequest{
					ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_MX})
				return err
			},
			method: http.MethodGet, path: "/api/v1/dns/zones/example.com./records", query: "type=MX", bodyEmpty: true,
		},
		{
			name:    "ListRecords unfiltered",
			payload: dnsRecordsPayload,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.ListRecords(context.Background(), &platformv1.ListRecordsRequest{ZoneName: "example.com."})
				return err
			},
			method: http.MethodGet, path: "/api/v1/dns/zones/example.com./records", bodyEmpty: true,
		},
		{
			name:    "ListRecords paged from the start",
			payload: dnsRecordsPayload,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.ListRecords(context.Background(), &platformv1.ListRecordsRequest{
					ZoneName: "example.com.", Limit: proto.Uint32(25), Offset: proto.Uint32(0)})
				return err
			},
			method: http.MethodGet, path: "/api/v1/dns/zones/example.com./records", query: "limit=25&offset=0", bodyEmpty: true,
		},
		{
			name:    "Resolve",
			payload: dnsRecordsPayload,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.Resolve(context.Background(), &platformv1.ResolveRequest{
					Fqdn: "www.example.com.", Type: platformv1.RecordType_RECORD_TYPE_A})
				return err
			},
			method: http.MethodGet, path: "/api/v1/dns/resolve", query: "fqdn=www.example.com.&type=A", bodyEmpty: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, sent := dnsOverREST(t, tc.payload)
			if err := tc.call(client); err != nil {
				t.Fatalf("%s over REST: %v", tc.name, err)
			}
			if sent.method != tc.method || sent.path != tc.path || sent.query != tc.query {
				t.Errorf("sent %s %s?%s, want %s %s?%s", sent.method, sent.path, sent.query, tc.method, tc.path, tc.query)
			}
			if tc.bodyEmpty && len(sent.body) != 0 {
				t.Errorf("body = %v, want no fields: every identifier travels in the URL", sent.body)
			}
		})
	}
}

func TestDNS_SDKOverREST_ListRecordsReadsThePage(t *testing.T) {
	client, _ := dnsOverREST(t, `{"total":9,"limit":2,"offset":4,"records":[]}`)

	resp, err := client.ListRecords(context.Background(), &platformv1.ListRecordsRequest{
		ZoneName: "example.com.", Limit: proto.Uint32(2), Offset: proto.Uint32(4)})
	if err != nil {
		t.Fatalf("ListRecords over REST: %v", err)
	}
	if resp.GetTotal() != 9 || resp.GetLimit() != 2 || resp.GetOffset() != 4 {
		t.Errorf("page = total %d limit %d offset %d, want 9 2 4", resp.GetTotal(), resp.GetLimit(), resp.GetOffset())
	}
}

// TestDNS_SDKOverREST_AddRecord: the zone travels in the path and the record
// as the server's AddRecordRequest, its type spelled as the mnemonic.
func TestDNS_SDKOverREST_AddRecord(t *testing.T) {
	client, sent := dnsOverREST(t, dnsZonePayload)

	resp, err := client.AddRecord(context.Background(), &platformv1.AddRecordRequest{
		ZoneName: "example.com.",
		Record: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "10.0.0.1", Ttl: 300}},
		},
	})
	if err != nil {
		t.Fatalf("AddRecord over REST: %v", err)
	}

	if sent.method != http.MethodPost || sent.path != "/api/v1/dns/zones/example.com./records" {
		t.Errorf("sent %s %s, want POST /api/v1/dns/zones/example.com./records", sent.method, sent.path)
	}
	a, _ := sent.body["a"].(map[string]interface{})
	if sent.body["type"] != "A" || a["name"] != "www" || a["value"] != "10.0.0.1" || a["ttl"] != float64(300) {
		t.Errorf("body = %v, want type A and the A record", sent.body)
	}
	if _, ok := sent.body["zone_name"]; ok {
		t.Errorf("body = %v: the zone travels in the path, not the body", sent.body)
	}
	if !resp.GetStatus().GetSuccess() || resp.GetZone().GetName() != "example.com." {
		t.Errorf("reply = %v, want success and the example.com. zone", resp)
	}
}

// TestDNS_SDKOverREST_RefusesARequestTheRouteCannotCarry: a record request
// without its type is refused before anything is sent.
func TestDNS_SDKOverREST_RefusesARequestTheRouteCannotCarry(t *testing.T) {
	cases := []struct {
		name string
		call func(platformv1.DNSServiceClient) error
	}{
		{"DeleteRecord without type", func(c platformv1.DNSServiceClient) error {
			_, err := c.DeleteRecord(context.Background(), &platformv1.DeleteRecordRequest{ZoneName: "example.com.", Name: "www"})
			return err
		}},
		{"DeleteRecord without name", func(c platformv1.DNSServiceClient) error {
			_, err := c.DeleteRecord(context.Background(), &platformv1.DeleteRecordRequest{
				ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_A})
			return err
		}},
		{"DeleteZone without name", func(c platformv1.DNSServiceClient) error {
			_, err := c.DeleteZone(context.Background(), &platformv1.DeleteZoneRequest{})
			return err
		}},
		{"AddRecord without record", func(c platformv1.DNSServiceClient) error {
			_, err := c.AddRecord(context.Background(), &platformv1.AddRecordRequest{ZoneName: "example.com."})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, sent := dnsOverREST(t, `{}`)
			err := tc.call(client)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument (err %v)", status.Code(err), err)
			}
			if sent.path != "" {
				t.Errorf("the refused request reached the server: %s %s", sent.method, sent.path)
			}
		})
	}
}

func TestEncodeDNSAddRecord_RequiresAType(t *testing.T) {
	_, err := encodeDNSAddRecord(&platformv1.AddRecordRequest{Record: &platformv1.Record{
		Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www"}},
	}})
	var want ErrDNSRecordTypeRequired
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrDNSRecordTypeRequired", err)
	}
	if want.Error() == "" {
		t.Error("ErrDNSRecordTypeRequired has an empty message")
	}
}

// TestDecodeDNSAddRecord_ReadsTheZone: the server's record-set lists land on
// the proto RecordSet fields, and fields the reply does not carry are dropped.
func TestDecodeDNSAddRecord_ReadsTheZone(t *testing.T) {
	resp, err := decodeDNSAddRecord([]byte(dnsZonePayload))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	zone := resp.GetZone()
	if zone.GetId() != 7 || zone.GetName() != "example.com." || zone.GetTtl() != 3600 || !zone.GetInternal() {
		t.Errorf("zone = %v", zone)
	}
	records := zone.GetRecords()
	if records.GetSoa().GetMname() != "ns1.example.com." || records.GetSoa().GetSerial() != 2026101401 {
		t.Errorf("soa = %v", records.GetSoa())
	}
	if len(records.GetARecords()) != 1 || records.GetARecords()[0].GetValue() != "10.0.0.1" {
		t.Errorf("a_records = %v", records.GetARecords())
	}
	if len(records.GetMxRecords()) != 1 || records.GetMxRecords()[0].GetPriority() != 10 {
		t.Errorf("mx_records = %v", records.GetMxRecords())
	}
	if !resp.GetStatus().GetSuccess() {
		t.Errorf("status = %v, want success", resp.GetStatus())
	}
}

// TestDecodeDNSResolve_ReadsRecordTypes: the mnemonic becomes the RecordType
// and the matching oneof is set; a type the proto does not define is
// UNSPECIFIED rather than an error.
func TestDecodeDNSResolve_ReadsRecordTypes(t *testing.T) {
	resp, err := decodeDNSResolve([]byte(dnsRecordsPayload))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := resp.GetRecords()
	if len(got) != 2 || !resp.GetAuthoritative() {
		t.Fatalf("reply = %v, want 2 records, authoritative", resp)
	}
	if got[0].GetType() != platformv1.RecordType_RECORD_TYPE_A || got[0].GetA().GetName() != "www" {
		t.Errorf("records[0] = %v", got[0])
	}
	if got[1].GetType() != platformv1.RecordType_RECORD_TYPE_MX || got[1].GetMx().GetValue() != "mail.example.com." {
		t.Errorf("records[1] = %v", got[1])
	}

	unknown, err := decodeDNSListRecords([]byte(`{"records":[{"type":"LOC"}]}`))
	if err != nil {
		t.Fatalf("decode unknown type: %v", err)
	}
	if unknown.GetRecords()[0].GetType() != platformv1.RecordType_RECORD_TYPE_UNSPECIFIED {
		t.Errorf("type = %v, want UNSPECIFIED", unknown.GetRecords()[0].GetType())
	}
}

func TestDecodeDNSDeleteZone_ReadsTheStatus(t *testing.T) {
	resp, err := decodeDNSDeleteZone([]byte(`{"success":true,"message":"zone deleted successfully"}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.GetStatus().GetSuccess() || resp.GetStatus().GetMessage() != "zone deleted successfully" {
		t.Errorf("status = %v", resp.GetStatus())
	}
}

// TestDNSDecoders_RejectMalformedAnswers: every decoder reports an answer it
// cannot read as ErrUnmarshalFailed, never as an empty reply.
func TestDNSDecoders_RejectMalformedAnswers(t *testing.T) {
	cases := map[string]struct {
		method string
		raw    string
		reply  interface{}
	}{
		"DeleteZone not JSON":   {platformv1.DNSService_DeleteZone_FullMethodName, `nope`, &platformv1.DeleteZoneResponse{}},
		"AddRecord not JSON":    {platformv1.DNSService_AddRecord_FullMethodName, `nope`, &platformv1.AddRecordResponse{}},
		"AddRecord bad set":     {platformv1.DNSService_AddRecord_FullMethodName, `{"records":[1]}`, &platformv1.AddRecordResponse{}},
		"AddRecord bad field":   {platformv1.DNSService_AddRecord_FullMethodName, `{"ttl":"x"}`, &platformv1.AddRecordResponse{}},
		"DeleteRecord bad zone": {platformv1.DNSService_DeleteRecord_FullMethodName, `[]`, &platformv1.DeleteRecordResponse{}},
		"ListRecords not JSON":  {platformv1.DNSService_ListRecords_FullMethodName, `nope`, &platformv1.ListRecordsResponse{}},
		"ListRecords bad type":  {platformv1.DNSService_ListRecords_FullMethodName, `{"records":[{"type":1}]}`, &platformv1.ListRecordsResponse{}},
		"ListRecords bad item":  {platformv1.DNSService_ListRecords_FullMethodName, `{"records":[1]}`, &platformv1.ListRecordsResponse{}},
		"Resolve bad record":    {platformv1.DNSService_Resolve_FullMethodName, `{"records":[{"a":{"ttl":"x"}}]}`, &platformv1.ResolveResponse{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := restResponseDecoders[tc.method]([]byte(tc.raw), tc.reply)
			var want ErrUnmarshalFailed
			if !errors.As(err, &want) {
				t.Fatalf("err = %v, want ErrUnmarshalFailed", err)
			}
		})
	}
}

func TestDNSDecoders_RejectTheWrongReplyType(t *testing.T) {
	for _, method := range []string{
		platformv1.DNSService_DeleteZone_FullMethodName,
		platformv1.DNSService_AddRecord_FullMethodName,
		platformv1.DNSService_DeleteRecord_FullMethodName,
		platformv1.DNSService_ListRecords_FullMethodName,
		platformv1.DNSService_Resolve_FullMethodName,
	} {
		err := restResponseDecoders[method]([]byte(`{}`), &platformv1.Status{})
		var want ErrUnexpectedReplyType
		if !errors.As(err, &want) || want.Method != method {
			t.Errorf("%s: err = %v, want ErrUnexpectedReplyType", method, err)
		}
	}
}
