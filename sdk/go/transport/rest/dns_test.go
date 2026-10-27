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
	"google.golang.org/protobuf/encoding/protojson"
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

// dnsZoneJSON is a Zone as the server's protojson writes it.
const dnsZoneJSON = `{"id":7,"name":"example.com.","ttl":3600,"description":"","internal":true,"records":{` +
	`"soa":{"name":"@","mname":"ns1.example.com.","rname":"admin.example.com.","serial":2026101401,"ttl":3600},` +
	`"aRecords":[{"name":"www","value":"10.0.0.1","ttl":300}],` +
	`"mxRecords":[{"name":"@","value":"mail.example.com.","priority":10,"ttl":300}]}}`

// dnsRecordsJSON is a records reply as the server's protojson writes it.
const dnsRecordsJSON = `{"records":[` +
	`{"type":"RECORD_TYPE_A","a":{"name":"www","value":"10.0.0.1","ttl":300}},` +
	`{"type":"RECORD_TYPE_MX","mx":{"name":"@","value":"mail.example.com.","priority":10,"ttl":300}}],` +
	`"authoritative":true}`

var dnsTestRecord = &platformv1.Record{
	Type:   platformv1.RecordType_RECORD_TYPE_A,
	Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "10.0.0.1", Ttl: 300}},
}

// TestDNS_SDKOverREST_EveryCallReachesItsRoute: each DNS call reaches the
// route the webservice serves, with the zone, record type and record name in
// the path, the filters in the query, and the rest of the proto request as
// the body.
func TestDNS_SDKOverREST_EveryCallReachesItsRoute(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		payload string
		call    func(platformv1.DNSServiceClient) error
		method  string
		path    string
		query   string
		body    map[string]interface{}
	}{
		{
			name: "CreateZone", payload: `{"status":{"success":true},"zone":` + dnsZoneJSON + `}`,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.CreateZone(ctx, &platformv1.CreateZoneRequest{Name: "example.com.", Ttl: 3600})
				return err
			},
			method: http.MethodPost, path: "/api/v1/dns/zones",
			body: map[string]interface{}{"name": "example.com.", "ttl": float64(3600)},
		},
		{
			name: "ListZones", payload: `{"zones":[` + dnsZoneJSON + `]}`,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.ListZones(ctx, &platformv1.ListZonesRequest{InternalOnly: true})
				return err
			},
			method: http.MethodGet, path: "/api/v1/dns/zones",
			body: map[string]interface{}{"internalOnly": true},
		},
		{
			name: "GetZone", payload: `{"zone":` + dnsZoneJSON + `}`,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.GetZone(ctx, &platformv1.GetZoneRequest{Name: "example.com."})
				return err
			},
			method: http.MethodGet, path: "/api/v1/dns/zones/example.com.",
		},
		{
			name: "UpdateZone", payload: `{"status":{"success":true},"zone":` + dnsZoneJSON + `}`,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.UpdateZone(ctx, &platformv1.UpdateZoneRequest{Name: "example.com.", Ttl: 7200})
				return err
			},
			method: http.MethodPut, path: "/api/v1/dns/zones/example.com.",
			body: map[string]interface{}{"ttl": float64(7200)},
		},
		{
			name: "DeleteZone", payload: `{"status":{"success":true}}`,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.DeleteZone(ctx, &platformv1.DeleteZoneRequest{Name: "example.com."})
				return err
			},
			method: http.MethodDelete, path: "/api/v1/dns/zones/example.com.",
		},
		{
			name: "AddRecord", payload: `{"status":{"success":true},"zone":` + dnsZoneJSON + `}`,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.AddRecord(ctx, &platformv1.AddRecordRequest{ZoneName: "example.com.", Record: dnsTestRecord})
				return err
			},
			method: http.MethodPost, path: "/api/v1/dns/zones/example.com./records",
			body: map[string]interface{}{"record": map[string]interface{}{
				"type": "RECORD_TYPE_A",
				"a":    map[string]interface{}{"name": "www", "value": "10.0.0.1", "ttl": float64(300)},
			}},
		},
		{
			name: "UpdateRecord", payload: `{"status":{"success":true},"zone":` + dnsZoneJSON + `}`,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.UpdateRecord(ctx, &platformv1.UpdateRecordRequest{ZoneName: "example.com.", NewRecord: dnsTestRecord})
				return err
			},
			method: http.MethodPut, path: "/api/v1/dns/zones/example.com./records",
			body: map[string]interface{}{"newRecord": map[string]interface{}{
				"type": "RECORD_TYPE_A",
				"a":    map[string]interface{}{"name": "www", "value": "10.0.0.1", "ttl": float64(300)},
			}},
		},
		{
			name: "ListRecords filtered", payload: dnsRecordsJSON,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.ListRecords(ctx, &platformv1.ListRecordsRequest{
					ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_MX})
				return err
			},
			method: http.MethodGet, path: "/api/v1/dns/zones/example.com./records", query: "type=MX",
		},
		{
			name: "ListRecords unfiltered", payload: dnsRecordsJSON,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.ListRecords(ctx, &platformv1.ListRecordsRequest{ZoneName: "example.com."})
				return err
			},
			method: http.MethodGet, path: "/api/v1/dns/zones/example.com./records",
		},
		{
			name: "DeleteRecord", payload: `{"status":{"success":true},"zone":` + dnsZoneJSON + `}`,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.DeleteRecord(ctx, &platformv1.DeleteRecordRequest{
					ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_AAAA, Name: "www"})
				return err
			},
			method: http.MethodDelete, path: "/api/v1/dns/zones/example.com./records/AAAA/www",
		},
		{
			name: "SignZone", payload: `{"status":{"success":true},"zone":` + dnsZoneJSON + `}`,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.SignZone(ctx, &platformv1.SignZoneRequest{ZoneName: "example.com."})
				return err
			},
			method: http.MethodPost, path: "/api/v1/dns/zones/example.com./sign",
		},
		{
			name: "GetDNSSECStatus", payload: `{"status":{"enabled":true,"zoneSigned":true}}`,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.GetDNSSECStatus(ctx, &platformv1.GetDNSSECStatusRequest{ZoneName: "example.com."})
				return err
			},
			method: http.MethodGet, path: "/api/v1/dns/zones/example.com./dnssec",
		},
		{
			name: "Resolve", payload: dnsRecordsJSON,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.Resolve(ctx, &platformv1.ResolveRequest{
					Fqdn: "www.example.com.", Type: platformv1.RecordType_RECORD_TYPE_A})
				return err
			},
			method: http.MethodGet, path: "/api/v1/dns/resolve", query: "fqdn=www.example.com.&type=A",
		},
		{
			name: "Register", payload: `{"status":{"success":true},"zone":` + dnsZoneJSON + `}`,
			call: func(c platformv1.DNSServiceClient) error {
				_, err := c.Register(ctx, &platformv1.RegisterRequest{Fqdn: "host.example.com.", Ip: "10.0.0.9"})
				return err
			},
			method: http.MethodPost, path: "/api/v1/dns/register",
			body: map[string]interface{}{"fqdn": "host.example.com.", "ip": "10.0.0.9"},
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
			for field, want := range tc.body {
				got, _ := json.Marshal(sent.body[field])
				wantJSON, _ := json.Marshal(want)
				if string(got) != string(wantJSON) {
					t.Errorf("body[%s] = %s, want %s", field, got, wantJSON)
				}
			}
			if len(tc.body) == 0 {
				for field, value := range sent.body {
					if value != "" && value != nil && value != float64(0) && value != false {
						t.Errorf("body[%s] = %v: every identifier travels in the URL", field, value)
					}
				}
			}
		})
	}
}

// TestDNS_SDKOverREST_RepliesAreTheProto: the server's protojson reply is
// the gRPC reply, with no translation.
func TestDNS_SDKOverREST_RepliesAreTheProto(t *testing.T) {
	client, _ := dnsOverREST(t, `{"zone":`+dnsZoneJSON+`}`)
	zone, err := client.GetZone(context.Background(), &platformv1.GetZoneRequest{Name: "example.com."})
	if err != nil {
		t.Fatalf("GetZone over REST: %v", err)
	}
	records := zone.GetZone().GetRecords()
	if zone.GetZone().GetId() != 7 || !zone.GetZone().GetInternal() || records.GetSoa().GetSerial() != 2026101401 {
		t.Errorf("zone = %v", zone.GetZone())
	}
	if len(records.GetARecords()) != 1 || len(records.GetMxRecords()) != 1 || records.GetMxRecords()[0].GetPriority() != 10 {
		t.Errorf("records = %v", records)
	}

	client, _ = dnsOverREST(t, dnsRecordsJSON)
	resolved, err := client.Resolve(context.Background(), &platformv1.ResolveRequest{Fqdn: "www.example.com."})
	if err != nil {
		t.Fatalf("Resolve over REST: %v", err)
	}
	if !resolved.GetAuthoritative() || len(resolved.GetRecords()) != 2 || !proto.Equal(resolved.GetRecords()[0], dnsTestRecord) {
		t.Errorf("reply = %v", resolved)
	}
	if resolved.GetRecords()[1].GetType() != platformv1.RecordType_RECORD_TYPE_MX {
		t.Errorf("records[1] = %v", resolved.GetRecords()[1])
	}
}

// TestDNS_SDKOverREST_RefusesARequestTheRouteCannotCarry: a request whose
// path identifier is unset is refused before anything is sent.
func TestDNS_SDKOverREST_RefusesARequestTheRouteCannotCarry(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		call func(platformv1.DNSServiceClient) error
	}{
		{"DeleteRecord without type", func(c platformv1.DNSServiceClient) error {
			_, err := c.DeleteRecord(ctx, &platformv1.DeleteRecordRequest{ZoneName: "example.com.", Name: "www"})
			return err
		}},
		{"DeleteRecord without name", func(c platformv1.DNSServiceClient) error {
			_, err := c.DeleteRecord(ctx, &platformv1.DeleteRecordRequest{
				ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_A})
			return err
		}},
		{"DeleteZone without name", func(c platformv1.DNSServiceClient) error {
			_, err := c.DeleteZone(ctx, &platformv1.DeleteZoneRequest{})
			return err
		}},
		{"GetZone without name", func(c platformv1.DNSServiceClient) error {
			_, err := c.GetZone(ctx, &platformv1.GetZoneRequest{})
			return err
		}},
		{"AddRecord without zone", func(c platformv1.DNSServiceClient) error {
			_, err := c.AddRecord(ctx, &platformv1.AddRecordRequest{Record: dnsTestRecord})
			return err
		}},
		{"SignZone without zone", func(c platformv1.DNSServiceClient) error {
			_, err := c.SignZone(ctx, &platformv1.SignZoneRequest{})
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

// TestDNSBodyEncoder_SendsProtoJSON: the body is the proto JSON mapping, so
// a record's oneof and type enum reach the server as protojson spells them.
func TestDNSBodyEncoder_SendsProtoJSON(t *testing.T) {
	encode := restRequestEncoders[platformv1.DNSService_AddRecord_FullMethodName]
	body, err := encode(&platformv1.AddRecordRequest{Record: dnsTestRecord})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	raw, ok := body.(json.RawMessage)
	if !ok {
		t.Fatalf("body = %T, want json.RawMessage", body)
	}
	decoded := &platformv1.AddRecordRequest{}
	if err := protojson.Unmarshal(raw, decoded); err != nil || !proto.Equal(decoded.GetRecord(), dnsTestRecord) {
		t.Errorf("body %s decodes to %v (err %v), want the record", raw, decoded, err)
	}
}

// TestDNSBodyEncoder_RefusesABodyThatIsNotTheRequest: a DNS method's encoder
// sends only that method's request message.
func TestDNSBodyEncoder_RefusesABodyThatIsNotTheRequest(t *testing.T) {
	encode := restRequestEncoders[platformv1.DNSService_AddRecord_FullMethodName]
	for name, body := range map[string]interface{}{
		"not a proto":     map[string]string{},
		"another request": &platformv1.DeleteRecordRequest{ZoneName: "example.com."},
		"no body":         nil,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := encode(body)
			var want ErrUnexpectedRequestType
			if !errors.As(err, &want) || want.Method != platformv1.DNSService_AddRecord_FullMethodName {
				t.Fatalf("err = %v, want ErrUnexpectedRequestType for AddRecord", err)
			}
		})
	}
}
