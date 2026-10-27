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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// scriptedDNSServer records the request a handler hands the DNS service and
// answers with resp, or with err when it is set.
type scriptedDNSServer struct {
	platformv1.UnimplementedDNSServiceServer
	got  proto.Message
	resp proto.Message
	err  error
}

func answer[T proto.Message](s *scriptedDNSServer, req proto.Message) (T, error) {
	s.got = req
	var zero T
	if s.err != nil {
		return zero, s.err
	}
	return s.resp.(T), nil
}

func (s *scriptedDNSServer) CreateZone(_ context.Context, req *platformv1.CreateZoneRequest) (*platformv1.CreateZoneResponse, error) {
	return answer[*platformv1.CreateZoneResponse](s, req)
}

func (s *scriptedDNSServer) GetZone(_ context.Context, req *platformv1.GetZoneRequest) (*platformv1.GetZoneResponse, error) {
	return answer[*platformv1.GetZoneResponse](s, req)
}

func (s *scriptedDNSServer) UpdateZone(_ context.Context, req *platformv1.UpdateZoneRequest) (*platformv1.UpdateZoneResponse, error) {
	return answer[*platformv1.UpdateZoneResponse](s, req)
}

func (s *scriptedDNSServer) DeleteZone(_ context.Context, req *platformv1.DeleteZoneRequest) (*platformv1.DeleteZoneResponse, error) {
	return answer[*platformv1.DeleteZoneResponse](s, req)
}

func (s *scriptedDNSServer) ListZones(_ context.Context, req *platformv1.ListZonesRequest) (*platformv1.ListZonesResponse, error) {
	return answer[*platformv1.ListZonesResponse](s, req)
}

func (s *scriptedDNSServer) AddRecord(_ context.Context, req *platformv1.AddRecordRequest) (*platformv1.AddRecordResponse, error) {
	return answer[*platformv1.AddRecordResponse](s, req)
}

func (s *scriptedDNSServer) DeleteRecord(_ context.Context, req *platformv1.DeleteRecordRequest) (*platformv1.DeleteRecordResponse, error) {
	return answer[*platformv1.DeleteRecordResponse](s, req)
}

func (s *scriptedDNSServer) UpdateRecord(_ context.Context, req *platformv1.UpdateRecordRequest) (*platformv1.UpdateRecordResponse, error) {
	return answer[*platformv1.UpdateRecordResponse](s, req)
}

func (s *scriptedDNSServer) ListRecords(_ context.Context, req *platformv1.ListRecordsRequest) (*platformv1.ListRecordsResponse, error) {
	return answer[*platformv1.ListRecordsResponse](s, req)
}

func (s *scriptedDNSServer) SignZone(_ context.Context, req *platformv1.SignZoneRequest) (*platformv1.SignZoneResponse, error) {
	return answer[*platformv1.SignZoneResponse](s, req)
}

func (s *scriptedDNSServer) GetDNSSECStatus(_ context.Context, req *platformv1.GetDNSSECStatusRequest) (*platformv1.GetDNSSECStatusResponse, error) {
	return answer[*platformv1.GetDNSSECStatusResponse](s, req)
}

func (s *scriptedDNSServer) Resolve(_ context.Context, req *platformv1.ResolveRequest) (*platformv1.ResolveResponse, error) {
	return answer[*platformv1.ResolveResponse](s, req)
}

func (s *scriptedDNSServer) Register(_ context.Context, req *platformv1.RegisterRequest) (*platformv1.RegisterResponse, error) {
	return answer[*platformv1.RegisterResponse](s, req)
}

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

// newTestRouter mounts the DNS routes under /api/v1 on server, with the
// production response writer so the envelope is the one clients read.
func newTestRouter(server platformv1.DNSServiceServer) *mux.Router {
	logger := newTestLogger()
	root := mux.NewRouter()
	NewDNSRouter(logger, server, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

// serve sends one request through the DNS routes.
func serve(server platformv1.DNSServiceServer, method, target, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	newTestRouter(server).ServeHTTP(rec, req)
	return rec
}

// payload decodes the envelope's payload into msg with protojson, the way
// the SDK REST transport does.
func payload(t *testing.T, rec *httptest.ResponseRecorder, msg proto.Message) {
	t.Helper()
	var envelope struct {
		Success bool            `json:"success"`
		Payload json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope), rec.Body.String())
	require.True(t, envelope.Success, rec.Body.String())
	require.NoError(t, protojson.Unmarshal(envelope.Payload, msg), string(envelope.Payload))
}

func testZone() *platformv1.Zone {
	return &platformv1.Zone{
		Id:   1,
		Name: "example.com.",
		Ttl:  3600,
		Records: &platformv1.RecordSet{
			ARecords: []*platformv1.ARecord{{Name: "www", Value: "192.0.2.1", Ttl: 300}},
		},
	}
}

// TestRoutesDecodeTheProtoRequest: every route hands the service the proto
// request its JSON body, path and query make, and answers the proto
// response in the envelope.
func TestRoutesDecodeTheProtoRequest(t *testing.T) {
	ok := &platformv1.Status{Success: true}
	aRecord := &platformv1.Record{
		Type:   platformv1.RecordType_RECORD_TYPE_A,
		Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.0.2.1", Ttl: 300}},
	}
	newRecord := &platformv1.Record{
		Type:   platformv1.RecordType_RECORD_TYPE_A,
		Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.0.2.2", Ttl: 300}},
	}
	tests := []struct {
		name   string
		method string
		target string
		body   string
		want   proto.Message
		resp   proto.Message
		reply  proto.Message
	}{
		{
			name: "CreateZone", method: http.MethodPost, target: "/api/v1/dns/zones",
			body: `{"name":"example.com.","ttl":3600,"internal":true,"nsRecords":[{"name":"@","value":"ns1.example.com.","ttl":3600}]}`,
			want: &platformv1.CreateZoneRequest{Name: "example.com.", Ttl: 3600, Internal: true,
				NsRecords: []*platformv1.NSRecord{{Name: "@", Value: "ns1.example.com.", Ttl: 3600}}},
			resp: &platformv1.CreateZoneResponse{Status: ok, Zone: testZone()}, reply: &platformv1.CreateZoneResponse{},
		},
		{
			name: "ListZones", method: http.MethodGet, target: "/api/v1/dns/zones?internal=true&page=2&page_size=10",
			want: &platformv1.ListZonesRequest{InternalOnly: true, Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 10}},
			resp: &platformv1.ListZonesResponse{Zones: []*platformv1.Zone{testZone()},
				Pagination: &platformv1.PaginationResponse{Page: 2, PageSize: 10, TotalPages: 2, TotalItems: 11}},
			reply: &platformv1.ListZonesResponse{},
		},
		{
			name: "ListZonesPublicFromTheBody", method: http.MethodGet, target: "/api/v1/dns/zones?public=true",
			body:  `{"pagination":{"page":1,"pageSize":5,"sortBy":"name"}}`,
			want:  &platformv1.ListZonesRequest{PublicOnly: true, Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 5, SortBy: "name"}},
			resp:  &platformv1.ListZonesResponse{},
			reply: &platformv1.ListZonesResponse{},
		},
		{
			name: "GetZone", method: http.MethodGet, target: "/api/v1/dns/zones/example.com.",
			want: &platformv1.GetZoneRequest{Name: "example.com."},
			resp: &platformv1.GetZoneResponse{Zone: testZone()}, reply: &platformv1.GetZoneResponse{},
		},
		{
			name: "UpdateZone", method: http.MethodPut, target: "/api/v1/dns/zones/example.com.",
			body: `{"name":"ignored.com.","ttl":7200,"description":"lab"}`,
			want: &platformv1.UpdateZoneRequest{Name: "example.com.", Ttl: 7200, Description: "lab"},
			resp: &platformv1.UpdateZoneResponse{Status: ok, Zone: testZone()}, reply: &platformv1.UpdateZoneResponse{},
		},
		{
			name: "DeleteZone", method: http.MethodDelete, target: "/api/v1/dns/zones/example.com.",
			want: &platformv1.DeleteZoneRequest{Name: "example.com."},
			resp: &platformv1.DeleteZoneResponse{Status: ok}, reply: &platformv1.DeleteZoneResponse{},
		},
		{
			name: "AddRecord", method: http.MethodPost, target: "/api/v1/dns/zones/example.com./records",
			body: `{"record":{"type":"RECORD_TYPE_A","a":{"name":"www","value":"192.0.2.1","ttl":300}}}`,
			want: &platformv1.AddRecordRequest{ZoneName: "example.com.", Record: aRecord},
			resp: &platformv1.AddRecordResponse{Status: ok, Zone: testZone()}, reply: &platformv1.AddRecordResponse{},
		},
		{
			name: "UpdateRecord", method: http.MethodPut, target: "/api/v1/dns/zones/example.com./records",
			body: `{"oldRecord":{"type":"RECORD_TYPE_A","a":{"name":"www","value":"192.0.2.1","ttl":300}},` +
				`"newRecord":{"type":"RECORD_TYPE_A","a":{"name":"www","value":"192.0.2.2","ttl":300}}}`,
			want: &platformv1.UpdateRecordRequest{ZoneName: "example.com.", OldRecord: aRecord, NewRecord: newRecord},
			resp: &platformv1.UpdateRecordResponse{Status: ok, Zone: testZone()}, reply: &platformv1.UpdateRecordResponse{},
		},
		{
			name: "ListRecords", method: http.MethodGet, target: "/api/v1/dns/zones/example.com./records?type=a&page=1&page_size=50",
			want: &platformv1.ListRecordsRequest{ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_A,
				Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 50}},
			resp: &platformv1.ListRecordsResponse{Records: []*platformv1.Record{aRecord}}, reply: &platformv1.ListRecordsResponse{},
		},
		{
			name: "ListRecordsTypeFromTheBody", method: http.MethodGet, target: "/api/v1/dns/zones/example.com./records",
			body:  `{"type":"RECORD_TYPE_MX"}`,
			want:  &platformv1.ListRecordsRequest{ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_MX},
			resp:  &platformv1.ListRecordsResponse{},
			reply: &platformv1.ListRecordsResponse{},
		},
		{
			name: "DeleteRecord", method: http.MethodDelete, target: "/api/v1/dns/zones/example.com./records/A/www",
			want: &platformv1.DeleteRecordRequest{ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_A, Name: "www"},
			resp: &platformv1.DeleteRecordResponse{Status: ok, Zone: testZone()}, reply: &platformv1.DeleteRecordResponse{},
		},
		{
			name: "Resolve", method: http.MethodGet, target: "/api/v1/dns/resolve?fqdn=www.example.com.&type=RECORD_TYPE_AAAA",
			want: &platformv1.ResolveRequest{Fqdn: "www.example.com.", Type: platformv1.RecordType_RECORD_TYPE_AAAA},
			resp: &platformv1.ResolveResponse{Records: []*platformv1.Record{aRecord}, Authoritative: true}, reply: &platformv1.ResolveResponse{},
		},
		{
			name: "SignZone", method: http.MethodPost, target: "/api/v1/dns/zones/example.com./sign",
			want: &platformv1.SignZoneRequest{ZoneName: "example.com."},
			resp: &platformv1.SignZoneResponse{Status: ok, Zone: testZone()}, reply: &platformv1.SignZoneResponse{},
		},
		{
			name: "GetDNSSECStatus", method: http.MethodGet, target: "/api/v1/dns/zones/example.com./dnssec",
			want:  &platformv1.GetDNSSECStatusRequest{ZoneName: "example.com."},
			resp:  &platformv1.GetDNSSECStatusResponse{Status: &platformv1.DNSSECStatus{Enabled: true, ZoneSigned: true, Algorithm: "ECDSAP256SHA256"}},
			reply: &platformv1.GetDNSSECStatusResponse{},
		},
		{
			name: "Register", method: http.MethodPost, target: "/api/v1/dns/register",
			body: `{"fqdn":"host.example.com.","ip":"192.0.2.9"}`,
			want: &platformv1.RegisterRequest{Fqdn: "host.example.com.", Ip: "192.0.2.9"},
			resp: &platformv1.RegisterResponse{Status: ok, Zone: testZone()}, reply: &platformv1.RegisterResponse{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := &scriptedDNSServer{resp: tc.resp}
			rec := serve(server, tc.method, tc.target, tc.body)

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.True(t, proto.Equal(tc.want, server.got), "request = %v, want %v", server.got, tc.want)
			payload(t, rec, tc.reply)
			assert.True(t, proto.Equal(tc.resp, tc.reply), "reply = %v, want %v", tc.reply, tc.resp)
		})
	}
}

// TestZoneReplyIsTheProtoJSONShape: the payload carries the proto JSON
// names (aRecords, RECORD_TYPE_ enums) and emits unpopulated fields, not the
// retired REST shape.
func TestZoneReplyIsTheProtoJSONShape(t *testing.T) {
	server := &scriptedDNSServer{resp: &platformv1.GetZoneResponse{Zone: testZone()}}
	rec := serve(server, http.MethodGet, "/api/v1/dns/zones/example.com.", "")

	require.Equal(t, http.StatusOK, rec.Code)
	var envelope struct {
		Payload struct {
			Zone map[string]json.RawMessage `json:"zone"`
		} `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	zone := envelope.Payload.Zone
	assert.Contains(t, zone, "internal", "unpopulated fields are emitted")
	assert.NotContains(t, zone, "createdAt")
	var records map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(zone["records"], &records))
	assert.Contains(t, records, "aRecords")
	assert.NotContains(t, records, "a")
}

// TestServiceErrorsMapToHTTP: a gRPC status from the service is the HTTP
// status the other proto-shaped routes answer.
func TestServiceErrorsMapToHTTP(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"InvalidArgument", status.Error(codes.InvalidArgument, "zone name is required"), http.StatusBadRequest},
		{"NotFound", status.Error(codes.NotFound, "zone not found"), http.StatusNotFound},
		{"AlreadyExists", status.Error(codes.AlreadyExists, "zone exists"), http.StatusConflict},
		{"Internal", status.Error(codes.Internal, "save failed"), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(&scriptedDNSServer{err: tc.err}, http.MethodGet, "/api/v1/dns/zones/example.com.", "")
			assert.Equal(t, tc.want, rec.Code, rec.Body.String())
		})
	}
}

// TestNoServerIsServiceUnavailable: every route answers 503 when the DNS
// service is not wired.
// everyRoute is one request to each DNS route.
var everyRoute = []struct{ method, target string }{
	{http.MethodPost, "/api/v1/dns/zones"},
	{http.MethodGet, "/api/v1/dns/zones"},
	{http.MethodGet, "/api/v1/dns/zones/example.com."},
	{http.MethodPut, "/api/v1/dns/zones/example.com."},
	{http.MethodDelete, "/api/v1/dns/zones/example.com."},
	{http.MethodPost, "/api/v1/dns/zones/example.com./records"},
	{http.MethodPut, "/api/v1/dns/zones/example.com./records"},
	{http.MethodGet, "/api/v1/dns/zones/example.com./records"},
	{http.MethodGet, "/api/v1/dns/zones/example.com./records/A/www"},
	{http.MethodDelete, "/api/v1/dns/zones/example.com./records/A/www"},
	{http.MethodGet, "/api/v1/dns/resolve?fqdn=www.example.com."},
	{http.MethodPost, "/api/v1/dns/zones/example.com./sign"},
	{http.MethodGet, "/api/v1/dns/zones/example.com./dnssec"},
	{http.MethodPost, "/api/v1/dns/register"},
}

func TestNoServerIsServiceUnavailable(t *testing.T) {
	for _, route := range everyRoute {
		t.Run(route.method+" "+route.target, func(t *testing.T) {
			rec := serve(nil, route.method, route.target, "")
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
		})
	}
}

// TestEveryRouteWritesTheServiceError: each route answers a service error
// with its status, not a payload.
func TestEveryRouteWritesTheServiceError(t *testing.T) {
	for _, route := range everyRoute {
		t.Run(route.method+" "+route.target, func(t *testing.T) {
			server := &scriptedDNSServer{err: status.Error(codes.NotFound, "zone not found")}
			rec := serve(server, route.method, route.target, "")
			assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
			assert.NotNil(t, server.got, "the route did not reach the service")
		})
	}
}

// TestBadInputIsBadRequest: a body, query or path value the route cannot
// decode is a 400 and never reaches the service.
func TestBadInputIsBadRequest(t *testing.T) {
	tests := []struct {
		name, method, target, body string
	}{
		{"BodyIsNotJSON", http.MethodPost, "/api/v1/dns/zones", `{"name":`},
		{"InternalIsNotABool", http.MethodGet, "/api/v1/dns/zones?internal=maybe", ""},
		{"PublicIsNotABool", http.MethodGet, "/api/v1/dns/zones?public=maybe", ""},
		{"PageIsNotANumber", http.MethodGet, "/api/v1/dns/zones?page=one", ""},
		{"PageSizeIsNotANumber", http.MethodGet, "/api/v1/dns/zones/example.com./records?page_size=-1", ""},
		{"ListTypeIsUnknown", http.MethodGet, "/api/v1/dns/zones/example.com./records?type=BOGUS", ""},
		{"DeleteTypeIsUnknown", http.MethodDelete, "/api/v1/dns/zones/example.com./records/BOGUS/www", ""},
		{"GetTypeIsUnknown", http.MethodGet, "/api/v1/dns/zones/example.com./records/BOGUS/www", ""},
		{"ResolveTypeIsUnknown", http.MethodGet, "/api/v1/dns/resolve?fqdn=www.example.com.&type=BOGUS", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := &scriptedDNSServer{}
			rec := serve(server, tc.method, tc.target, tc.body)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Nil(t, server.got, "the service was called")
		})
	}
}

// TestGetRecord: the single-record route answers the Record of that type and
// name from ListRecords.
func TestGetRecord(t *testing.T) {
	www := &platformv1.Record{
		Type:   platformv1.RecordType_RECORD_TYPE_A,
		Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.0.2.1", Ttl: 300}},
	}
	api := &platformv1.Record{
		Type:   platformv1.RecordType_RECORD_TYPE_A,
		Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "api", Value: "192.0.2.2", Ttl: 300}},
	}
	server := &scriptedDNSServer{resp: &platformv1.ListRecordsResponse{Records: []*platformv1.Record{api, www}}}
	rec := serve(server, http.MethodGet, "/api/v1/dns/zones/example.com./records/a/www", "")

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, proto.Equal(&platformv1.ListRecordsRequest{ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_A}, server.got))
	got := &platformv1.Record{}
	payload(t, rec, got)
	assert.True(t, proto.Equal(www, got), "record = %v", got)
}

func TestGetRecordNotInTheZoneIsNotFound(t *testing.T) {
	server := &scriptedDNSServer{resp: &platformv1.ListRecordsResponse{}}
	rec := serve(server, http.MethodGet, "/api/v1/dns/zones/example.com./records/A/missing", "")

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "record not found: A missing")
}

func TestGetRecordOfAnUnknownZoneIsNotFound(t *testing.T) {
	server := &scriptedDNSServer{err: status.Error(codes.NotFound, "zone not found")}
	rec := serve(server, http.MethodGet, "/api/v1/dns/zones/missing.com./records/A/www", "")

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestParseRecordType(t *testing.T) {
	tests := []struct {
		value string
		want  platformv1.RecordType
	}{
		{"", platformv1.RecordType_RECORD_TYPE_UNSPECIFIED},
		{"A", platformv1.RecordType_RECORD_TYPE_A},
		{"aaaa", platformv1.RecordType_RECORD_TYPE_AAAA},
		{"RECORD_TYPE_TLSA", platformv1.RecordType_RECORD_TYPE_TLSA},
		{"record_type_mx", platformv1.RecordType_RECORD_TYPE_MX},
	}
	for _, tc := range tests {
		got, err := parseRecordType(tc.value)
		require.NoError(t, err, tc.value)
		assert.Equal(t, tc.want, got, tc.value)
	}
}

func TestParseRecordTypeRejectsUnknownNames(t *testing.T) {
	for _, value := range []string{"BOGUS", "UNSPECIFIED", "RECORD_TYPE_UNSPECIFIED", "RECORD_TYPE_"} {
		_, err := parseRecordType(value)
		var invalid *ErrInvalidRecordType
		require.ErrorAs(t, err, &invalid, value)
		assert.Equal(t, value, invalid.Type)
	}
}

func TestRecordName(t *testing.T) {
	srv := &platformv1.Record{Record: &platformv1.Record_Srv{Srv: &platformv1.SRVRecord{Name: "_sip._tcp"}}}
	assert.Equal(t, "_sip._tcp", recordName(srv))
}

func TestRecordNameOfAnEmptyRecordIsEmpty(t *testing.T) {
	assert.Equal(t, "", recordName(&platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_A}))
}

// TestEnvelopeIsTheRestWireShape: the reply decodes as the shared envelope.
func TestEnvelopeIsTheRestWireShape(t *testing.T) {
	server := &scriptedDNSServer{resp: &platformv1.DeleteZoneResponse{Status: &platformv1.Status{Success: true}}}
	rec := serve(server, http.MethodDelete, "/api/v1/dns/zones/example.com.", "")

	var envelope restwire.WebServiceResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	assert.True(t, envelope.Success)
	assert.Equal(t, http.StatusOK, envelope.Code)
}
