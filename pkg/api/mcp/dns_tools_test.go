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

package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// fakeMCPDNS is a DNSServiceServer that records the RPC it served. GetZone
// answers NotFound for missingZone; ListRecords answers listErr when set.
type fakeMCPDNS struct {
	platformv1.UnimplementedDNSServiceServer
	called  string
	listed  *platformv1.ListRecordsRequest
	listErr error
}

const missingZone = "missing.internal."

func (f *fakeMCPDNS) CreateZone(_ context.Context, in *platformv1.CreateZoneRequest) (*platformv1.CreateZoneResponse, error) {
	f.called = "CreateZone"
	return &platformv1.CreateZoneResponse{Zone: &platformv1.Zone{Name: in.GetName()}}, nil
}

func (f *fakeMCPDNS) GetZone(_ context.Context, in *platformv1.GetZoneRequest) (*platformv1.GetZoneResponse, error) {
	f.called = "GetZone"
	if in.GetName() == missingZone {
		return nil, status.Error(codes.NotFound, "zone not found")
	}
	return &platformv1.GetZoneResponse{Zone: &platformv1.Zone{Name: in.GetName(), Ttl: 3600}}, nil
}

func (f *fakeMCPDNS) UpdateZone(_ context.Context, in *platformv1.UpdateZoneRequest) (*platformv1.UpdateZoneResponse, error) {
	f.called = "UpdateZone"
	return &platformv1.UpdateZoneResponse{Zone: &platformv1.Zone{Name: in.GetName(), Ttl: in.GetTtl()}}, nil
}

func (f *fakeMCPDNS) DeleteZone(context.Context, *platformv1.DeleteZoneRequest) (*platformv1.DeleteZoneResponse, error) {
	f.called = "DeleteZone"
	return &platformv1.DeleteZoneResponse{}, nil
}

func (f *fakeMCPDNS) ListZones(context.Context, *platformv1.ListZonesRequest) (*platformv1.ListZonesResponse, error) {
	f.called = "ListZones"
	return &platformv1.ListZonesResponse{Zones: []*platformv1.Zone{{Name: "example.internal."}}}, nil
}

func (f *fakeMCPDNS) AddRecord(context.Context, *platformv1.AddRecordRequest) (*platformv1.AddRecordResponse, error) {
	f.called = "AddRecord"
	return &platformv1.AddRecordResponse{}, nil
}

func (f *fakeMCPDNS) DeleteRecord(context.Context, *platformv1.DeleteRecordRequest) (*platformv1.DeleteRecordResponse, error) {
	f.called = "DeleteRecord"
	return &platformv1.DeleteRecordResponse{}, nil
}

func (f *fakeMCPDNS) UpdateRecord(context.Context, *platformv1.UpdateRecordRequest) (*platformv1.UpdateRecordResponse, error) {
	f.called = "UpdateRecord"
	return &platformv1.UpdateRecordResponse{}, nil
}

func (f *fakeMCPDNS) SignZone(_ context.Context, in *platformv1.SignZoneRequest) (*platformv1.SignZoneResponse, error) {
	f.called = "SignZone"
	if in.GetZoneName() == missingZone {
		return nil, status.Error(codes.NotFound, "zone not found")
	}
	return &platformv1.SignZoneResponse{Zone: &platformv1.Zone{Name: in.GetZoneName()}}, nil
}

func (f *fakeMCPDNS) GetDNSSECStatus(_ context.Context, in *platformv1.GetDNSSECStatusRequest) (*platformv1.GetDNSSECStatusResponse, error) {
	f.called = "GetDNSSECStatus"
	return &platformv1.GetDNSSECStatusResponse{Status: &platformv1.DNSSECStatus{Enabled: true, ZoneSigned: in.GetZoneName() != ""}}, nil
}

func (f *fakeMCPDNS) Register(_ context.Context, in *platformv1.RegisterRequest) (*platformv1.RegisterResponse, error) {
	f.called = "Register"
	return &platformv1.RegisterResponse{Zone: &platformv1.Zone{Name: in.GetFqdn()}}, nil
}

// ListRecords serves two A records and an AAAA record named like one of
// them, so a lookup must match the type as well as the name.
func (f *fakeMCPDNS) ListRecords(_ context.Context, in *platformv1.ListRecordsRequest) (*platformv1.ListRecordsResponse, error) {
	f.called = "ListRecords"
	f.listed = in
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &platformv1.ListRecordsResponse{Records: []*platformv1.Record{
		{Type: platformv1.RecordType_RECORD_TYPE_AAAA, Record: &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: "www", Value: "fd00::1"}}},
		{Type: platformv1.RecordType_RECORD_TYPE_A, Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "api", Value: "10.0.0.2"}}},
		{Type: platformv1.RecordType_RECORD_TYPE_A, Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "10.0.0.1", Ttl: 300}}},
	}}, nil
}

func (f *fakeMCPDNS) Resolve(context.Context, *platformv1.ResolveRequest) (*platformv1.ResolveResponse, error) {
	f.called = "Resolve"
	return &platformv1.ResolveResponse{Authoritative: true}, nil
}

// dnsTestProvider is a ServiceProvider that serves the DNS service.
type dnsTestProvider struct {
	*mockServiceProvider
	server platformv1.DNSServiceServer
}

func (p dnsTestProvider) DNSServiceServer() platformv1.DNSServiceServer { return p.server }

func newDNSTestProvider(server platformv1.DNSServiceServer) dnsTestProvider {
	return dnsTestProvider{mockServiceProvider: newMockServiceProvider(), server: server}
}

func newDNSTestRegistry(server platformv1.DNSServiceServer) *ToolRegistry {
	return NewToolRegistry(newDNSTestProvider(server), logging.DefaultLogger())
}

// dnsToolArgs are well-formed arguments for every bound DNS tool.
var dnsToolArgs = map[string]map[string]interface{}{
	"dns_zone_create": {"name": "example.internal.", "ttl": 3600},
	"dns_zone_get":    {"name": "example.internal."},
	"dns_zone_list":   {},
	"dns_zone_update": {"name": "example.internal.", "ttl": 600},
	"dns_zone_delete": {"name": "example.internal."},
	"dns_record_create": {
		"zone_name": "example.internal.",
		"record":    map[string]interface{}{"type": "RECORD_TYPE_A", "a": map[string]interface{}{"name": "www", "value": "10.0.0.1", "ttl": 300}},
	},
	"dns_record_get":  {"zone_name": "example.internal.", "type": "RECORD_TYPE_A", "name": "www"},
	"dns_record_list": {"zone_name": "example.internal."},
	"dns_record_update": {
		"zone_name":  "example.internal.",
		"old_record": map[string]interface{}{"type": "RECORD_TYPE_A", "a": map[string]interface{}{"name": "www", "value": "10.0.0.1"}},
		"new_record": map[string]interface{}{"type": "RECORD_TYPE_A", "a": map[string]interface{}{"name": "www", "value": "10.0.0.9"}},
	},
	"dns_record_delete":      {"zone_name": "example.internal.", "type": "RECORD_TYPE_A", "name": "www"},
	"dns_lookup":             {"fqdn": "www.example.internal.", "type": "RECORD_TYPE_A"},
	"dns_zone_sign":          {"zone_name": "example.internal."},
	"dns_zone_dnssec_status": {"zone_name": "example.internal."},
	"dns_register":           {"fqdn": "host1.example.internal.", "ip": "10.0.0.7"},
}

// callDNSTool sends a tools/call through the server, as a client does.
func callDNSTool(ctx context.Context, server *Server, name string, args map[string]interface{}) *mcpwire.JSONRPCResponse {
	return server.handleRequest(ctx, &mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  map[string]interface{}{"name": name, "arguments": args},
	})
}

// Each bound DNS tool calls one DNSService RPC and requires that RPC's gRPC
// scope. dns_record_get has no RPC and reads.
func TestDNSTools_RequireTheirGRPCScope(t *testing.T) {
	want := map[string]string{
		"dns_zone_create":        platformv1.DNSService_CreateZone_FullMethodName,
		"dns_zone_get":           platformv1.DNSService_GetZone_FullMethodName,
		"dns_zone_list":          platformv1.DNSService_ListZones_FullMethodName,
		"dns_zone_update":        platformv1.DNSService_UpdateZone_FullMethodName,
		"dns_zone_delete":        platformv1.DNSService_DeleteZone_FullMethodName,
		"dns_record_create":      platformv1.DNSService_AddRecord_FullMethodName,
		"dns_record_list":        platformv1.DNSService_ListRecords_FullMethodName,
		"dns_record_update":      platformv1.DNSService_UpdateRecord_FullMethodName,
		"dns_record_delete":      platformv1.DNSService_DeleteRecord_FullMethodName,
		"dns_lookup":             platformv1.DNSService_Resolve_FullMethodName,
		"dns_zone_sign":          platformv1.DNSService_SignZone_FullMethodName,
		"dns_zone_dnssec_status": platformv1.DNSService_GetDNSSECStatus_FullMethodName,
		"dns_register":           platformv1.DNSService_Register_FullMethodName,
	}
	permissions := toolPermissionCatalog()

	for name, method := range want {
		tool, ok := dnsTools[name]
		require.True(t, ok, "%s is not bound", name)
		assert.Equal(t, method, tool.method, name)
		scope := grpcapi.ScopeForMethod(method)
		require.NotEmpty(t, scope, "%s has no gRPC scope", method)
		assert.Equal(t, scope, permissions[name], name)
	}

	assert.Equal(t, "dns:read", permissions["dns_record_get"])
	assert.Len(t, dnsTools, len(want)+1, "a bound tool is missing from this table")
}

// A caller holding the tool's scope gets the answer; a caller holding every
// other dns action is refused and the servicer is never called.
func TestDNSTools_AuthorizeByScope(t *testing.T) {
	for name, tool := range dnsTools {
		resource, action, ok := strings.Cut(tool.scope, ":")
		require.True(t, ok, "%s scope %q", name, tool.scope)

		t.Run(name+"/allowed", func(t *testing.T) {
			fake := &fakeMCPDNS{}
			authSvc := &mockAuthorizationService{checkFunc: func(_ context.Context, _, r, a string) (bool, error) {
				return r == resource && a == action, nil
			}}
			server := NewServer(newDNSTestProvider(fake), &Config{AuthorizationService: authSvc}, newTestLogger())

			resp := callDNSTool(ContextWithToken(context.Background(), "token"), server, name, dnsToolArgs[name])

			require.Nil(t, resp.Error, "%+v", resp.Error)
			assert.NotNil(t, resp.Result)
			assert.NotEmpty(t, fake.called)
		})

		t.Run(name+"/denied", func(t *testing.T) {
			fake := &fakeMCPDNS{}
			authSvc := &mockAuthorizationService{checkFunc: func(_ context.Context, _, r, a string) (bool, error) {
				return r == resource && a != action, nil
			}}
			server := NewServer(newDNSTestProvider(fake), &Config{AuthorizationService: authSvc}, newTestLogger())

			resp := callDNSTool(ContextWithToken(context.Background(), "token"), server, name, dnsToolArgs[name])

			require.NotNil(t, resp.Error)
			assert.Equal(t, mcpwire.PermissionDenied, resp.Error.Code)
			assert.Empty(t, fake.called, "the handler ran for a refused caller")
		})
	}
}

// A token carried in the arguments authorizes the call and is not decoded
// as a request field.
func TestDNSTools_AcceptTheTokenInTheArguments(t *testing.T) {
	for _, key := range tokenArgumentKeys {
		t.Run(key, func(t *testing.T) {
			fake := &fakeMCPDNS{}
			authSvc := &mockAuthorizationService{checkFunc: func(_ context.Context, subject, _, _ string) (bool, error) {
				return subject == "arg-token", nil
			}}
			server := NewServer(newDNSTestProvider(fake), &Config{AuthorizationService: authSvc}, newTestLogger())

			resp := callDNSTool(context.Background(), server, "dns_zone_get",
				map[string]interface{}{"name": "example.internal.", key: "arg-token"})

			require.Nil(t, resp.Error, "%+v", resp.Error)
			assert.Equal(t, "GetZone", fake.called)
		})
	}
}

func TestDNSTools_RefuseWhenTheDNSServiceIsNotWired(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), logging.DefaultLogger())

	for name := range dnsTools {
		_, err := registry.ExecuteTool(context.Background(), name, dnsToolArgs[name])

		require.ErrorIs(t, err, ErrDNSServiceUnavailable, name)
		assert.Equal(t, mcpwire.CodeForClass(codes.Unavailable), toolErrorCode(err), name)
	}
}

func TestDNSTools_RejectArgumentsTheRequestDoesNotHave(t *testing.T) {
	fake := &fakeMCPDNS{}
	registry := newDNSTestRegistry(fake)

	for name := range dnsTools {
		_, err := registry.ExecuteTool(context.Background(), name, map[string]interface{}{"zone": "example.internal."})

		var invalid ErrInvalidArgument
		assert.True(t, errors.As(err, &invalid), "%s: error = %v", name, err)
		assert.Equal(t, mcpwire.CodeForClass(codes.InvalidArgument), toolErrorCode(err), name)
	}
	assert.Empty(t, fake.called, "a malformed call reached the servicer")
}

// The servicer's status passes through unchanged, so MCP reports the class
// gRPC reports.
func TestDNSTools_PassTheServicerStatusThrough(t *testing.T) {
	registry := newDNSTestRegistry(&fakeMCPDNS{})

	_, err := registry.ExecuteTool(context.Background(), "dns_zone_get", map[string]interface{}{"name": missingZone})

	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, mcpwire.CodeForClass(codes.NotFound), toolErrorCode(err))
}

func TestDNSTools_ReturnTheResponseInProtoNames(t *testing.T) {
	registry := newDNSTestRegistry(&fakeMCPDNS{})

	result, err := registry.ExecuteTool(context.Background(), "dns_zone_get", dnsToolArgs["dns_zone_get"])

	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"zone": map[string]interface{}{"name": "example.internal.", "ttl": float64(3600)},
	}, result)
}

// Sign zone, DNSSEC status and register reach the RPC their gRPC twins call
// (#704): before them, MCP had no DNSSEC or register verb.
func TestDNSTools_DNSSECAndRegisterReachTheirRPC(t *testing.T) {
	cases := map[string]string{
		"dns_zone_sign":          "SignZone",
		"dns_zone_dnssec_status": "GetDNSSECStatus",
		"dns_register":           "Register",
	}
	for name, rpc := range cases {
		t.Run(name, func(t *testing.T) {
			fake := &fakeMCPDNS{}
			registry := newDNSTestRegistry(fake)

			result, err := registry.ExecuteTool(context.Background(), name, dnsToolArgs[name])

			require.NoError(t, err)
			assert.NotEmpty(t, result)
			assert.Equal(t, rpc, fake.called)
		})
	}
}

func TestDNSTools_SignZoneReportsTheServicerClass(t *testing.T) {
	registry := newDNSTestRegistry(&fakeMCPDNS{})

	_, err := registry.ExecuteTool(context.Background(), "dns_zone_sign", map[string]interface{}{"zone_name": missingZone})
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, mcpwire.CodeForClass(codes.NotFound), toolErrorCode(err))
}

func TestDNSRecordGet_ReturnsTheRecordOfThatTypeAndName(t *testing.T) {
	fake := &fakeMCPDNS{}
	registry := newDNSTestRegistry(fake)

	result, err := registry.ExecuteTool(context.Background(), "dns_record_get", dnsToolArgs["dns_record_get"])

	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"type": "RECORD_TYPE_A",
		"a":    map[string]interface{}{"name": "www", "value": "10.0.0.1", "ttl": float64(300)},
	}, result)
	assert.Equal(t, "example.internal.", fake.listed.GetZoneName())
	assert.Equal(t, platformv1.RecordType_RECORD_TYPE_A, fake.listed.GetType())
}

func TestDNSRecordGet_RefusesWhatItCannotAnswer(t *testing.T) {
	listFailure := status.Error(codes.NotFound, "zone not found")
	tests := []struct {
		name    string
		args    map[string]interface{}
		listErr error
		want    error
		class   codes.Code
	}{
		{"no type", map[string]interface{}{"zone_name": "example.internal.", "name": "www"}, nil, ErrDNSRecordTypeRequired, codes.InvalidArgument},
		{"no name", map[string]interface{}{"zone_name": "example.internal.", "type": "RECORD_TYPE_A"}, nil, ErrDNSRecordNameRequired, codes.InvalidArgument},
		{"empty name", map[string]interface{}{"zone_name": "example.internal.", "type": "RECORD_TYPE_A", "name": ""}, nil, ErrDNSRecordNameRequired, codes.InvalidArgument},
		{"name not a string", map[string]interface{}{"zone_name": "example.internal.", "type": "RECORD_TYPE_A", "name": 7}, nil, ErrDNSRecordNameRequired, codes.InvalidArgument},
		{"zone fails", dnsToolArgs["dns_record_get"], listFailure, listFailure, codes.NotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := newDNSTestRegistry(&fakeMCPDNS{listErr: tt.listErr})

			_, err := registry.ExecuteTool(context.Background(), "dns_record_get", tt.args)

			require.ErrorIs(t, err, tt.want)
			assert.Equal(t, mcpwire.CodeForClass(tt.class), toolErrorCode(err))
		})
	}
}

// A name the zone holds only in another type is not found: the AAAA "www"
// does not answer an A lookup for a name with no A record, and vice versa.
func TestDNSRecordGet_NotFoundIsTypedAndNotFoundClass(t *testing.T) {
	registry := newDNSTestRegistry(&fakeMCPDNS{})

	_, err := registry.ExecuteTool(context.Background(), "dns_record_get",
		map[string]interface{}{"zone_name": "example.internal.", "type": "RECORD_TYPE_AAAA", "name": "api"})

	var notFound ErrDNSRecordNotFound
	require.True(t, errors.As(err, &notFound), "error = %v", err)
	assert.Equal(t, "api", notFound.Name)
	assert.Equal(t, platformv1.RecordType_RECORD_TYPE_AAAA, notFound.Type)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, mcpwire.CodeForClass(codes.NotFound), toolErrorCode(err))
}
