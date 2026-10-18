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

package daemon

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const parityZone = "example.internal."

// dnsRPC calls one DNSService RPC with the tool arguments decoded into its
// request, as a gRPC client sending the same message would.
type dnsRPC func(t *testing.T, server *DNSServiceServer, args map[string]interface{}) (proto.Message, error)

func dnsRPCOf[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](call func(*DNSServiceServer, context.Context, PReq) (Resp, error)) dnsRPC {
	return func(t *testing.T, server *DNSServiceServer, args map[string]interface{}) (proto.Message, error) {
		request := PReq(new(Req))
		data, err := json.Marshal(args)
		require.NoError(t, err)
		require.NoError(t, protojson.Unmarshal(data, request))
		return call(server, context.Background(), request)
	}
}

// seedParityZone creates parityZone holding the A record www through the
// gRPC servicer.
func seedParityZone(t *testing.T, server *DNSServiceServer) {
	t.Helper()
	_, err := server.CreateZone(context.Background(), &platformv1.CreateZoneRequest{Name: parityZone, Ttl: 3600, Internal: true})
	require.NoError(t, err)
	_, err = server.AddRecord(context.Background(), &platformv1.AddRecordRequest{
		ZoneName: parityZone,
		Record: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "10.0.0.1", Ttl: 300}},
		},
	})
	require.NoError(t, err)
}

// newMCPDNSRegistry is the MCP tool registry the daemon builds over service.
func newMCPDNSRegistry(service dns.DNSService) *mcp.ToolRegistry {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{DNSService: service, Logger: testLogger()})
	return mcp.NewToolRegistry(provider, logging.DefaultLogger())
}

// protoNamesJSON is a response as the MCP tools render it.
func protoNamesJSON(t *testing.T, message proto.Message) map[string]interface{} {
	t.Helper()
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(message)
	require.NoError(t, err)
	result := map[string]interface{}{}
	require.NoError(t, json.Unmarshal(data, &result))
	return result
}

var aRecordWWW = map[string]interface{}{"type": "RECORD_TYPE_A", "a": map[string]interface{}{"name": "www", "value": "10.0.0.1", "ttl": 300}}

// Each MCP DNS tool gives the answer and the error class its gRPC RPC gives
// for the same request over the same DNS service.
func TestDNSMCPTools_MatchGRPC(t *testing.T) {
	tests := []struct {
		group string
		name  string
		tool  string
		rpc   dnsRPC
		args  map[string]interface{}
		class codes.Code
	}{
		{"zones", "create", "dns_zone_create", dnsRPCOf((*DNSServiceServer).CreateZone), map[string]interface{}{"name": "new.internal.", "ttl": 600}, codes.OK},
		{"zones", "create without a name", "dns_zone_create", dnsRPCOf((*DNSServiceServer).CreateZone), map[string]interface{}{"ttl": 600}, codes.InvalidArgument},
		{"zones", "get", "dns_zone_get", dnsRPCOf((*DNSServiceServer).GetZone), map[string]interface{}{"name": parityZone}, codes.OK},
		{"zones", "get unknown", "dns_zone_get", dnsRPCOf((*DNSServiceServer).GetZone), map[string]interface{}{"name": "missing.internal."}, codes.NotFound},
		{"zones", "get without a name", "dns_zone_get", dnsRPCOf((*DNSServiceServer).GetZone), map[string]interface{}{}, codes.InvalidArgument},
		{"zones", "list", "dns_zone_list", dnsRPCOf((*DNSServiceServer).ListZones), map[string]interface{}{}, codes.OK},
		{"zones", "update", "dns_zone_update", dnsRPCOf((*DNSServiceServer).UpdateZone), map[string]interface{}{"name": parityZone, "ttl": 60}, codes.OK},
		{"zones", "update unknown", "dns_zone_update", dnsRPCOf((*DNSServiceServer).UpdateZone), map[string]interface{}{"name": "missing.internal.", "ttl": 60}, codes.NotFound},
		{"zones", "delete", "dns_zone_delete", dnsRPCOf((*DNSServiceServer).DeleteZone), map[string]interface{}{"name": parityZone}, codes.OK},
		{"zones", "delete unknown", "dns_zone_delete", dnsRPCOf((*DNSServiceServer).DeleteZone), map[string]interface{}{"name": "missing.internal."}, codes.NotFound},

		{"records", "create", "dns_record_create", dnsRPCOf((*DNSServiceServer).AddRecord),
			map[string]interface{}{"zone_name": parityZone, "record": map[string]interface{}{"type": "RECORD_TYPE_A", "a": map[string]interface{}{"name": "api", "value": "10.0.0.2"}}}, codes.OK},
		{"records", "create in unknown zone", "dns_record_create", dnsRPCOf((*DNSServiceServer).AddRecord),
			map[string]interface{}{"zone_name": "missing.internal.", "record": aRecordWWW}, codes.NotFound},
		{"records", "create without a record", "dns_record_create", dnsRPCOf((*DNSServiceServer).AddRecord), map[string]interface{}{"zone_name": parityZone}, codes.InvalidArgument},
		{"records", "list", "dns_record_list", dnsRPCOf((*DNSServiceServer).ListRecords), map[string]interface{}{"zone_name": parityZone}, codes.OK},
		{"records", "list unknown zone", "dns_record_list", dnsRPCOf((*DNSServiceServer).ListRecords), map[string]interface{}{"zone_name": "missing.internal."}, codes.NotFound},
		{"records", "update", "dns_record_update", dnsRPCOf((*DNSServiceServer).UpdateRecord),
			map[string]interface{}{"zone_name": parityZone, "old_record": aRecordWWW, "new_record": map[string]interface{}{"type": "RECORD_TYPE_A", "a": map[string]interface{}{"name": "www", "value": "10.0.0.9"}}}, codes.OK},
		{"records", "update in unknown zone", "dns_record_update", dnsRPCOf((*DNSServiceServer).UpdateRecord),
			map[string]interface{}{"zone_name": "missing.internal.", "old_record": aRecordWWW, "new_record": aRecordWWW}, codes.NotFound},
		{"records", "delete", "dns_record_delete", dnsRPCOf((*DNSServiceServer).DeleteRecord), map[string]interface{}{"zone_name": parityZone, "type": "RECORD_TYPE_A", "name": "www"}, codes.OK},
		{"records", "delete in unknown zone", "dns_record_delete", dnsRPCOf((*DNSServiceServer).DeleteRecord),
			map[string]interface{}{"zone_name": "missing.internal.", "type": "RECORD_TYPE_A", "name": "www"}, codes.NotFound},
		{"records", "delete without a zone", "dns_record_delete", dnsRPCOf((*DNSServiceServer).DeleteRecord), map[string]interface{}{"type": "RECORD_TYPE_A", "name": "www"}, codes.InvalidArgument},

		{"lookups", "resolve", "dns_lookup", dnsRPCOf((*DNSServiceServer).Resolve), map[string]interface{}{"fqdn": "www." + parityZone, "type": "RECORD_TYPE_A"}, codes.OK},
		{"lookups", "resolve outside the managed zones", "dns_lookup", dnsRPCOf((*DNSServiceServer).Resolve), map[string]interface{}{"fqdn": "www.nowhere.example.", "type": "RECORD_TYPE_A"}, codes.OK},
		{"lookups", "resolve without a name", "dns_lookup", dnsRPCOf((*DNSServiceServer).Resolve), map[string]interface{}{"type": "RECORD_TYPE_A"}, codes.InvalidArgument},

		{"dnssec", "sign", "dns_zone_sign", dnsRPCOf((*DNSServiceServer).SignZone), map[string]interface{}{"zone_name": parityZone}, codes.OK},
		{"dnssec", "sign unknown", "dns_zone_sign", dnsRPCOf((*DNSServiceServer).SignZone), map[string]interface{}{"zone_name": "missing.internal."}, codes.NotFound},
		{"dnssec", "sign without a zone", "dns_zone_sign", dnsRPCOf((*DNSServiceServer).SignZone), map[string]interface{}{}, codes.InvalidArgument},
		{"dnssec", "status", "dns_zone_dnssec_status", dnsRPCOf((*DNSServiceServer).GetDNSSECStatus), map[string]interface{}{"zone_name": parityZone}, codes.OK},
		{"dnssec", "status unknown", "dns_zone_dnssec_status", dnsRPCOf((*DNSServiceServer).GetDNSSECStatus), map[string]interface{}{"zone_name": "missing.internal."}, codes.NotFound},

		{"register", "register", "dns_register", dnsRPCOf((*DNSServiceServer).Register), map[string]interface{}{"fqdn": "host1." + parityZone, "ip": "10.0.0.7"}, codes.OK},
		{"register", "register without an address", "dns_register", dnsRPCOf((*DNSServiceServer).Register), map[string]interface{}{"fqdn": "host1." + parityZone}, codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.group+"/"+tt.name, func(t *testing.T) {
			// Each transport gets its own identically seeded service, so a
			// write by one cannot shape the other's answer.
			grpcServer := NewDNSServiceServer(newMockDNSService(), testLogger())
			seedParityZone(t, grpcServer)
			mcpService := newMockDNSService()
			seedParityZone(t, NewDNSServiceServer(mcpService, testLogger()))

			want, grpcErr := tt.rpc(t, grpcServer, tt.args)
			got, mcpErr := newMCPDNSRegistry(mcpService).ExecuteTool(context.Background(), tt.tool, tt.args)

			require.Equal(t, tt.class, status.Code(grpcErr), "gRPC: %v", grpcErr)
			require.Equal(t, tt.class, status.Code(mcpErr), "MCP: %v", mcpErr)
			if tt.class == codes.OK {
				assert.Equal(t, protoNamesJSON(t, want), got)
			}
		})
	}
}

// dns_record_get has no RPC; it answers the record ListRecords holds, and
// an unknown zone is NotFound as ListRecords makes it.
func TestDNSMCPRecordGet_AnswersFromListRecords(t *testing.T) {
	service := newMockDNSService()
	server := NewDNSServiceServer(service, testLogger())
	seedParityZone(t, server)
	registry := newMCPDNSRegistry(service)

	listed, err := server.ListRecords(context.Background(), &platformv1.ListRecordsRequest{ZoneName: parityZone, Type: platformv1.RecordType_RECORD_TYPE_A})
	require.NoError(t, err)
	require.Len(t, listed.GetRecords(), 1)

	got, err := registry.ExecuteTool(context.Background(), "dns_record_get",
		map[string]interface{}{"zone_name": parityZone, "type": "RECORD_TYPE_A", "name": "www"})
	require.NoError(t, err)
	assert.Equal(t, protoNamesJSON(t, listed.GetRecords()[0]), got)

	_, err = registry.ExecuteTool(context.Background(), "dns_record_get",
		map[string]interface{}{"zone_name": "missing.internal.", "type": "RECORD_TYPE_A", "name": "www"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// newTenantDNSService is a real DNS service acting for tenant over storage.
func newTenantDNSService(t *testing.T, storage *quicbaas.MockStorage, tenant string) *dns.Service {
	t.Helper()
	service, err := dns.NewService(&dns.Params{
		TenantID:  tenant,
		Config:    &dns.Config{Logger: logging.DefaultLogger()},
		Datastore: dns.NewDatastore(storage, logging.DefaultLogger()),
	})
	require.NoError(t, err)
	return service
}

// DNSService carries no caller tenant: the DNS service acts for the tenant
// the daemon configured. A service acting for tenant A cannot see tenant B's
// zone over gRPC, and the MCP tools, calling the same servicer, cannot
// either.
func TestDNSMCPTools_RefuseAnotherTenantsZoneAsGRPCDoes(t *testing.T) {
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	tenantA := newTenantDNSService(t, storage, "tenant-a")
	tenantB := newTenantDNSService(t, storage, "tenant-b")
	seedParityZone(t, NewDNSServiceServer(tenantB, testLogger()))

	grpcA := NewDNSServiceServer(tenantA, testLogger())
	mcpA := newMCPDNSRegistry(tenantA)

	calls := []struct {
		tool string
		rpc  dnsRPC
		args map[string]interface{}
	}{
		{"dns_zone_get", dnsRPCOf((*DNSServiceServer).GetZone), map[string]interface{}{"name": parityZone}},
		{"dns_zone_delete", dnsRPCOf((*DNSServiceServer).DeleteZone), map[string]interface{}{"name": parityZone}},
		{"dns_record_list", dnsRPCOf((*DNSServiceServer).ListRecords), map[string]interface{}{"zone_name": parityZone}},
		{"dns_record_create", dnsRPCOf((*DNSServiceServer).AddRecord), map[string]interface{}{"zone_name": parityZone, "record": aRecordWWW}},
	}
	for _, call := range calls {
		t.Run(call.tool, func(t *testing.T) {
			_, grpcErr := call.rpc(t, grpcA, call.args)
			_, mcpErr := mcpA.ExecuteTool(context.Background(), call.tool, call.args)

			assert.Equal(t, codes.NotFound, status.Code(grpcErr), "gRPC: %v", grpcErr)
			assert.Equal(t, codes.NotFound, status.Code(mcpErr), "MCP: %v", mcpErr)
		})
	}

	listed, err := mcpA.ExecuteTool(context.Background(), "dns_zone_list", map[string]interface{}{})
	require.NoError(t, err)
	assert.NotContains(t, listed, "zones", "tenant A listed tenant B's zone")

	zone, err := tenantB.Zone(context.Background(), parityZone)
	require.NoError(t, err, "tenant B's zone was removed by tenant A")
	assert.Len(t, zone.RecordSet.ARecords, 1, "tenant A changed tenant B's zone")
}
