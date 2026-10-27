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
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// The SDK has no GetRecord rpc (docs/dns/api.md §2), so the single-record
// route is proven by the handler tests, not here.

// dnsOverSDK serves the real DNS router under /api/v1 and returns an SDK DNS
// client connected to it over the REST transport.
func dnsOverSDK(t *testing.T, server platformv1.DNSServiceServer) platformv1.DNSServiceClient {
	t.Helper()
	logger := newTestLogger()
	root := mux.NewRouter()
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	NewDNSRouter(logger, server, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	httpServer := httptest.NewTLSServer(root)
	t.Cleanup(httpServer.Close)
	trust := httpServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(httpServer.URL), platform.WithTLSConfig(trust)))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := adapter.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	})
	return platformv1.NewDNSServiceClient(adapter.Connection())
}

// TestSDKRoundTrip_EveryRPC: the request the SDK sends over REST is the
// request the DNS service receives, and the service's reply is the reply the
// SDK caller gets: one wire shape for REST and gRPC.
func TestSDKRoundTrip_EveryRPC(t *testing.T) {
	zone := testZone()
	txt := &platformv1.Record{
		Type:   platformv1.RecordType_RECORD_TYPE_TXT,
		Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: "@", Value: "v=spf1 -all", Ttl: 300}},
	}
	ok := &platformv1.Status{Success: true, Message: "done"}
	page := &platformv1.PaginationRequest{Page: 2, PageSize: 5}

	tests := []struct {
		name string
		req  proto.Message
		resp proto.Message
		call func(context.Context, platformv1.DNSServiceClient, proto.Message) (proto.Message, error)
	}{
		{
			name: "CreateZone",
			req: &platformv1.CreateZoneRequest{Name: "example.com.", Ttl: 3600, Internal: true,
				NsRecords: []*platformv1.NSRecord{{Name: "@", Value: "ns1.example.com.", Ttl: 3600}}},
			resp: &platformv1.CreateZoneResponse{Status: ok, Zone: zone},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.CreateZone(ctx, req.(*platformv1.CreateZoneRequest))
			},
		},
		{
			name: "GetZone",
			req:  &platformv1.GetZoneRequest{Name: "example.com."},
			resp: &platformv1.GetZoneResponse{Zone: zone},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.GetZone(ctx, req.(*platformv1.GetZoneRequest))
			},
		},
		{
			name: "UpdateZone",
			req:  &platformv1.UpdateZoneRequest{Name: "example.com.", Ttl: 7200, Description: "lab"},
			resp: &platformv1.UpdateZoneResponse{Status: ok, Zone: zone},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.UpdateZone(ctx, req.(*platformv1.UpdateZoneRequest))
			},
		},
		{
			name: "DeleteZone",
			req:  &platformv1.DeleteZoneRequest{Name: "example.com."},
			resp: &platformv1.DeleteZoneResponse{Status: ok},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.DeleteZone(ctx, req.(*platformv1.DeleteZoneRequest))
			},
		},
		{
			name: "ListZones",
			req:  &platformv1.ListZonesRequest{InternalOnly: true, Pagination: page},
			resp: &platformv1.ListZonesResponse{Zones: []*platformv1.Zone{zone}, Pagination: &platformv1.PaginationResponse{Page: 2, PageSize: 5, TotalItems: 6, TotalPages: 2}},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.ListZones(ctx, req.(*platformv1.ListZonesRequest))
			},
		},
		{
			name: "AddRecord",
			req:  &platformv1.AddRecordRequest{ZoneName: "example.com.", Record: txt},
			resp: &platformv1.AddRecordResponse{Status: ok, Zone: zone},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.AddRecord(ctx, req.(*platformv1.AddRecordRequest))
			},
		},
		{
			name: "UpdateRecord",
			req:  &platformv1.UpdateRecordRequest{ZoneName: "example.com.", OldRecord: txt, NewRecord: txt},
			resp: &platformv1.UpdateRecordResponse{Status: ok, Zone: zone},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.UpdateRecord(ctx, req.(*platformv1.UpdateRecordRequest))
			},
		},
		{
			name: "DeleteRecord",
			req:  &platformv1.DeleteRecordRequest{ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_A, Name: "www"},
			resp: &platformv1.DeleteRecordResponse{Status: ok, Zone: zone},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.DeleteRecord(ctx, req.(*platformv1.DeleteRecordRequest))
			},
		},
		{
			name: "ListRecords",
			req:  &platformv1.ListRecordsRequest{ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_TXT},
			resp: &platformv1.ListRecordsResponse{Records: []*platformv1.Record{txt}},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.ListRecords(ctx, req.(*platformv1.ListRecordsRequest))
			},
		},
		{
			name: "SignZone",
			req:  &platformv1.SignZoneRequest{ZoneName: "example.com."},
			resp: &platformv1.SignZoneResponse{Status: ok, Zone: zone},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.SignZone(ctx, req.(*platformv1.SignZoneRequest))
			},
		},
		{
			name: "GetDNSSECStatus",
			req:  &platformv1.GetDNSSECStatusRequest{ZoneName: "example.com."},
			resp: &platformv1.GetDNSSECStatusResponse{Status: &platformv1.DNSSECStatus{Enabled: true, ZoneSigned: true, Algorithm: "ECDSAP256SHA256"}},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.GetDNSSECStatus(ctx, req.(*platformv1.GetDNSSECStatusRequest))
			},
		},
		{
			name: "Resolve",
			req:  &platformv1.ResolveRequest{Fqdn: "www.example.com.", Type: platformv1.RecordType_RECORD_TYPE_TXT},
			resp: &platformv1.ResolveResponse{Records: []*platformv1.Record{txt}, Authoritative: true},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.Resolve(ctx, req.(*platformv1.ResolveRequest))
			},
		},
		{
			name: "Register",
			req:  &platformv1.RegisterRequest{Fqdn: "host.example.com.", Ip: "192.0.2.9"},
			resp: &platformv1.RegisterResponse{Status: ok, Zone: zone},
			call: func(ctx context.Context, c platformv1.DNSServiceClient, req proto.Message) (proto.Message, error) {
				return c.Register(ctx, req.(*platformv1.RegisterRequest))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := &scriptedDNSServer{resp: tc.resp}
			reply, err := tc.call(context.Background(), dnsOverSDK(t, server), tc.req)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if !proto.Equal(server.got, tc.req) {
				t.Errorf("service got %v, want %v", server.got, tc.req)
			}
			if !proto.Equal(reply, tc.resp) {
				t.Errorf("reply = %v, want %v", reply, tc.resp)
			}
		})
	}
}

// TestSDKRoundTrip_ServiceErrorsKeepTheirCode: a service error reaches the
// SDK caller with the code the gRPC transport would carry.
func TestSDKRoundTrip_ServiceErrorsKeepTheirCode(t *testing.T) {
	deleteZone := func(client platformv1.DNSServiceClient) error {
		_, err := client.DeleteZone(context.Background(), &platformv1.DeleteZoneRequest{Name: "example.com."})
		return err
	}
	createZone := func(client platformv1.DNSServiceClient) error {
		_, err := client.CreateZone(context.Background(), &platformv1.CreateZoneRequest{Name: "example.com."})
		return err
	}
	// AlreadyExists and FailedPrecondition share 409 (#665): the SDK reads a
	// create's 409 as AlreadyExists and a delete's as FailedPrecondition.
	tests := []struct {
		code codes.Code
		call func(platformv1.DNSServiceClient) error
	}{
		{codes.NotFound, deleteZone},
		{codes.InvalidArgument, deleteZone},
		{codes.FailedPrecondition, deleteZone},
		{codes.AlreadyExists, createZone},
	}
	for _, tc := range tests {
		t.Run(tc.code.String(), func(t *testing.T) {
			server := &scriptedDNSServer{err: status.Error(tc.code, "refused")}
			err := tc.call(dnsOverSDK(t, server))
			if status.Code(err) != tc.code {
				t.Fatalf("code = %v, want %v (err %v)", status.Code(err), tc.code, err)
			}
		})
	}
}
