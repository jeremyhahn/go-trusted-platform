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
package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// The SDK has no GetRecord rpc (docs/dns/api.md §2), so the single-record
// route is proven by the handler and router tests, not here.

// dnsOverSDK serves the real DNS router under /api/v1 and returns an SDK DNS
// client connected to it over the REST transport.
func dnsOverSDK(t *testing.T, service *mockDNSService) platformv1.DNSServiceClient {
	t.Helper()
	logger := newTestLogger()
	root := mux.NewRouter()
	root.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	NewDNSRouter(logger, service, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)
	trust := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(server.URL), platform.WithTLSConfig(trust)))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	return platformv1.NewDNSServiceClient(adapter.Connection())
}

// TestSDKRoundTrip_ListRecords: the zone in the path selects the zone and
// the type in the query filters it.
func TestSDKRoundTrip_ListRecords(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = recordLookupZone()
	client := dnsOverSDK(t, service)

	all, err := client.ListRecords(context.Background(), &platformv1.ListRecordsRequest{ZoneName: "example.com."})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(all.GetRecords()) != 4 {
		t.Errorf("records = %v, want the zone's 4 records", all.GetRecords())
	}

	aaaa, err := client.ListRecords(context.Background(), &platformv1.ListRecordsRequest{
		ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_AAAA})
	if err != nil {
		t.Fatalf("ListRecords AAAA: %v", err)
	}
	got := aaaa.GetRecords()
	if len(got) != 1 || got[0].GetType() != platformv1.RecordType_RECORD_TYPE_AAAA || got[0].GetAaaa().GetValue() != "2001:db8::1" {
		t.Errorf("records = %v, want only the AAAA record", got)
	}
}

// TestSDKRoundTrip_ListRecordsOfAnUnknownZoneIsNotFound: the route's 404
// reaches the SDK caller as NotFound.
func TestSDKRoundTrip_ListRecordsOfAnUnknownZoneIsNotFound(t *testing.T) {
	client := dnsOverSDK(t, newMockDNSService())

	_, err := client.ListRecords(context.Background(), &platformv1.ListRecordsRequest{ZoneName: "missing.com."})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound (err %v)", status.Code(err), err)
	}
}

func TestSDKRoundTrip_DeleteZone(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = recordLookupZone()
	service.zones["other.com."] = createTestZone("other.com.")
	client := dnsOverSDK(t, service)

	resp, err := client.DeleteZone(context.Background(), &platformv1.DeleteZoneRequest{Name: "example.com."})
	if err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}
	if !resp.GetStatus().GetSuccess() {
		t.Errorf("status = %v, want success", resp.GetStatus())
	}
	if _, ok := service.zones["example.com."]; ok {
		t.Error("example.com. is still in the service")
	}
	if _, ok := service.zones["other.com."]; !ok {
		t.Error("other.com. was deleted too")
	}
}

func TestSDKRoundTrip_DeleteZoneThatDoesNotExistIsNotFound(t *testing.T) {
	client := dnsOverSDK(t, newMockDNSService())

	_, err := client.DeleteZone(context.Background(), &platformv1.DeleteZoneRequest{Name: "missing.com."})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound (err %v)", status.Code(err), err)
	}
}

// TestSDKRoundTrip_DeleteRecord: the type and name in the path select one
// record; the www AAAA record and the api A record survive.
func TestSDKRoundTrip_DeleteRecord(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = recordLookupZone()
	client := dnsOverSDK(t, service)

	resp, err := client.DeleteRecord(context.Background(), &platformv1.DeleteRecordRequest{
		ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_A, Name: "www"})
	if err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	records := resp.GetZone().GetRecords()
	if len(records.GetARecords()) != 1 || records.GetARecords()[0].GetName() != "api" {
		t.Errorf("a_records = %v, want only api", records.GetARecords())
	}
	if len(records.GetAaaaRecords()) != 1 || records.GetAaaaRecords()[0].GetName() != "www" {
		t.Errorf("aaaa_records = %v, want www kept", records.GetAaaaRecords())
	}
}

func TestSDKRoundTrip_AddRecord(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	client := dnsOverSDK(t, service)

	resp, err := client.AddRecord(context.Background(), &platformv1.AddRecordRequest{
		ZoneName: "example.com.",
		Record: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_TXT,
			Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: "@", Value: "v=spf1 -all", Ttl: 300}},
		},
	})
	if err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	stored := service.zones["example.com."].RecordSet.TXTRecords
	if len(stored) != 1 || stored[0].Value != "v=spf1 -all" {
		t.Errorf("stored TXT records = %v", stored)
	}
	if txt := resp.GetZone().GetRecords().GetTxtRecords(); len(txt) != 1 || txt[0].GetValue() != "v=spf1 -all" {
		t.Errorf("reply txt_records = %v", txt)
	}
}

func TestSDKRoundTrip_Resolve(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = recordLookupZone()
	client := dnsOverSDK(t, service)

	resp, err := client.Resolve(context.Background(), &platformv1.ResolveRequest{
		Fqdn: "www.example.com.", Type: platformv1.RecordType_RECORD_TYPE_AAAA})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := resp.GetRecords()
	if !resp.GetAuthoritative() || len(got) != 1 || got[0].GetAaaa().GetValue() != "2001:db8::1" {
		t.Errorf("reply = %v, want the one AAAA record, authoritative", resp)
	}
}
