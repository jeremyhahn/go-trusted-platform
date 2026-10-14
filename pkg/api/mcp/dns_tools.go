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
	"fmt"
	"maps"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// DNS Error Types
// =============================================================================

// DNSError represents a DNS operation error.
type DNSError struct {
	Code    string
	Message string
}

func (e *DNSError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GRPCStatus classifies the error by its Code (codeClass), so the MCP
// server answers it with the matching JSON-RPC code.
func (e *DNSError) GRPCStatus() *status.Status {
	return codeStatus(e.Code, e.Error())
}

// DNS error sentinel values.
var (
	// ErrDNSServiceUnavailable indicates the DNS service is not available.
	ErrDNSServiceUnavailable = &DNSError{
		Code:    "DNS_SERVICE_UNAVAILABLE",
		Message: "dns service is not available",
	}

	// ErrDNSRecordTypeRequired indicates a record type is required.
	ErrDNSRecordTypeRequired = &DNSError{
		Code:    "DNS_RECORD_TYPE_REQUIRED",
		Message: "record type is required",
	}

	// ErrDNSRecordNameRequired indicates a record name is required.
	ErrDNSRecordNameRequired = &DNSError{
		Code:    "DNS_RECORD_NAME_REQUIRED",
		Message: "record name is required",
	}
)

// ErrDNSRecordNotFound is returned by dns_record_get when the zone holds no
// record of the requested type and name; REST answers the same lookup 404.
type ErrDNSRecordNotFound struct {
	Zone string
	Type platformv1.RecordType
	Name string
}

func (e ErrDNSRecordNotFound) Error() string {
	return fmt.Sprintf("record %s %s not found in zone %s", e.Type, e.Name, e.Zone)
}

// GRPCStatus classifies the error as NotFound.
func (e ErrDNSRecordNotFound) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, e.Error())
}

// =============================================================================
// DNS Tool Binding
// =============================================================================

// DNSServiceProvider is implemented by a ServiceProvider that serves the
// gRPC DNSService. The dns_zone_*, dns_record_* and dns_lookup tools call
// that servicer, so they answer, validate and fail exactly as gRPC does.
type DNSServiceProvider interface {
	DNSServiceServer() platformv1.DNSServiceServer
}

// dnsToolCall runs one DNS tool against the gRPC DNSService servicer.
type dnsToolCall func(server platformv1.DNSServiceServer, ctx context.Context, args map[string]interface{}) (interface{}, error)

// dnsToolBinding is how a DNS tool reaches the servicer: the schema it
// advertises and the call that serves it.
type dnsToolBinding struct {
	schema func() map[string]interface{}
	call   dnsToolCall
}

// dnsTool is one DNS tool and the permission it requires.
type dnsTool struct {
	// method is the gRPC method the tool serves; empty for dns_record_get,
	// which has no gRPC twin.
	method string
	// scope is the permission the tool requires: the scope of its gRPC
	// method in pkg/api/grpc/method_permissions.go.
	scope       string
	description string
	binding     dnsToolBinding
}

// dnsTools are the DNS tools bound to the gRPC DNSService. Arguments are the
// gRPC request in protojson form and answers are the gRPC response, so a
// client moves between the two transports without translation.
var dnsTools = map[string]dnsTool{
	"dns_zone_create": {
		method:      platformv1.DNSService_CreateZone_FullMethodName,
		scope:       "dns:write",
		description: "Create a DNS zone with optional SOA and NS records",
		binding:     dnsToolMethod(platformv1.DNSServiceServer.CreateZone, "name"),
	},
	"dns_zone_get": {
		method:      platformv1.DNSService_GetZone_FullMethodName,
		scope:       "dns:read",
		description: "Get a DNS zone",
		binding:     dnsToolMethod(platformv1.DNSServiceServer.GetZone, "name"),
	},
	"dns_zone_list": {
		method:      platformv1.DNSService_ListZones_FullMethodName,
		scope:       "dns:read",
		description: "List DNS zones",
		binding:     dnsToolMethod(platformv1.DNSServiceServer.ListZones),
	},
	"dns_zone_update": {
		method:      platformv1.DNSService_UpdateZone_FullMethodName,
		scope:       "dns:write",
		description: "Update a DNS zone's TTL or description",
		binding:     dnsToolMethod(platformv1.DNSServiceServer.UpdateZone, "name"),
	},
	"dns_zone_delete": {
		method:      platformv1.DNSService_DeleteZone_FullMethodName,
		scope:       "dns:delete",
		description: "Delete a DNS zone and all its records",
		binding:     dnsToolMethod(platformv1.DNSServiceServer.DeleteZone, "name"),
	},
	"dns_record_create": {
		method:      platformv1.DNSService_AddRecord_FullMethodName,
		scope:       "dns:write",
		description: "Add a DNS record to a zone",
		binding:     dnsToolMethod(platformv1.DNSServiceServer.AddRecord, "zone_name", "record"),
	},
	"dns_record_get": {
		// No gRPC twin: REST GET /api/v1/dns/zones/{zone}/records/{type}/{name}
		// is the only other transport, and it is gated by role, not scope.
		// dns:read is the scope of ListRecords, which serves it here, and of
		// the older dns_get_record.
		scope:       "dns:read",
		description: "Get the DNS record of one type and name in a zone",
		binding:     dnsToolBinding{schema: dnsRecordGetSchema, call: dnsRecordGet},
	},
	"dns_record_list": {
		method:      platformv1.DNSService_ListRecords_FullMethodName,
		scope:       "dns:read",
		description: "List the DNS records in a zone, optionally of one type",
		binding:     dnsToolMethod(platformv1.DNSServiceServer.ListRecords, "zone_name"),
	},
	"dns_record_update": {
		method:      platformv1.DNSService_UpdateRecord_FullMethodName,
		scope:       "dns:write",
		description: "Replace a DNS record in a zone",
		binding:     dnsToolMethod(platformv1.DNSServiceServer.UpdateRecord, "zone_name", "old_record", "new_record"),
	},
	"dns_record_delete": {
		method:      platformv1.DNSService_DeleteRecord_FullMethodName,
		scope:       "dns:delete",
		description: "Delete the DNS records of one type and name from a zone",
		binding:     dnsToolMethod(platformv1.DNSServiceServer.DeleteRecord, "zone_name", "name"),
	},
	"dns_lookup": {
		method:      platformv1.DNSService_Resolve_FullMethodName,
		scope:       "dns:read",
		description: "Resolve a name from the managed DNS zones",
		binding:     dnsToolMethod(platformv1.DNSServiceServer.Resolve, "fqdn"),
	},
}

// dnsToolMethod binds a DNS tool to one gRPC DNSService method: the
// arguments decode into the method's request and its response is the answer.
func dnsToolMethod[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](
	call func(platformv1.DNSServiceServer, context.Context, PReq) (Resp, error),
	required ...string,
) dnsToolBinding {
	descriptor := PReq(new(Req)).ProtoReflect().Descriptor()
	return dnsToolBinding{
		schema: func() map[string]interface{} {
			return appToolSchema(descriptor, required...)
		},
		call: func(server platformv1.DNSServiceServer, ctx context.Context, args map[string]interface{}) (interface{}, error) {
			request := PReq(new(Req))
			if err := decodeAppToolArgs(args, request); err != nil {
				return nil, err
			}
			response, err := call(server, ctx, request)
			if err != nil {
				return nil, err
			}
			return encodeAppToolResult(response)
		},
	}
}

// dnsRecordGetSchema is the ListRecords request plus the record name.
func dnsRecordGetSchema() map[string]interface{} {
	schema := appToolSchema((&platformv1.ListRecordsRequest{}).ProtoReflect().Descriptor(), "zone_name", "type", "name")
	if properties, ok := schema["properties"].(map[string]interface{}); ok {
		properties["name"] = map[string]interface{}{"type": "string"}
	}
	return schema
}

// dnsRecordGet answers dns_record_get from ListRecords: of the zone's records
// of the requested type, the one named exactly as requested is the answer,
// as REST GET /api/v1/dns/zones/{zone}/records/{type}/{name} answers.
func dnsRecordGet(server platformv1.DNSServiceServer, ctx context.Context, args map[string]interface{}) (interface{}, error) {
	listArgs := maps.Clone(args)
	delete(listArgs, "name")
	request := &platformv1.ListRecordsRequest{}
	if err := decodeAppToolArgs(listArgs, request); err != nil {
		return nil, err
	}
	if request.GetType() == platformv1.RecordType_RECORD_TYPE_UNSPECIFIED {
		return nil, ErrDNSRecordTypeRequired
	}
	name, ok := args["name"].(string)
	if !ok || name == "" {
		return nil, ErrDNSRecordNameRequired
	}

	response, err := server.ListRecords(ctx, request)
	if err != nil {
		return nil, err
	}
	for _, record := range response.GetRecords() {
		if record.GetType() == request.GetType() && dnsRecordName(record) == name {
			return encodeAppToolResult(record)
		}
	}
	return nil, ErrDNSRecordNotFound{Zone: request.GetZoneName(), Type: request.GetType(), Name: name}
}

// dnsRecordName is the name of the record set in a Record's oneof; every
// record message carries one.
func dnsRecordName(record *platformv1.Record) string {
	message := record.ProtoReflect()
	field := message.WhichOneof(message.Descriptor().Oneofs().ByName("record"))
	if field == nil {
		return ""
	}
	inner := message.Get(field).Message()
	nameField := inner.Descriptor().Fields().ByName("name")
	if nameField == nil {
		return ""
	}
	return inner.Get(nameField).String()
}

// =============================================================================
// DNS Tool Registration
// =============================================================================

// registerDNSExtendedTools registers the DNS tools bound to the gRPC
// DNSService, and dns_reverse_lookup, which no backend serves: there is no
// reverse lookup on any transport and no PTR record type, so it stays
// unclassified and is refused.
func (r *ToolRegistry) registerDNSExtendedTools() {
	for _, name := range slices.Sorted(maps.Keys(dnsTools)) {
		tool := dnsTools[name]
		r.addTool(mcpwire.ToolDefinition{
			Name:        name,
			Description: tool.description,
			InputSchema: tool.binding.schema(),
		})
	}

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_reverse_lookup",
		Description: "Perform a reverse DNS lookup (PTR) for an IP address",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ip": map[string]interface{}{
					"type":        "string",
					"description": "IP address to look up",
				},
			},
			"required": []string{"ip"},
		},
	})
}

// dnsServiceServer is the gRPC DNSService servicer the DNS tools call, or
// nil while the service provider serves none.
func (r *ToolRegistry) dnsServiceServer() platformv1.DNSServiceServer {
	if provider, ok := r.service.(DNSServiceProvider); ok {
		return provider.DNSServiceServer()
	}
	return nil
}

// dispatchDNSTool runs a DNS tool bound to the gRPC DNSService; handled is
// false for any other tool name.
func (r *ToolRegistry) dispatchDNSTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	tool, ok := dnsTools[name]
	if !ok {
		return nil, false, nil
	}
	server := r.dnsServiceServer()
	if server == nil {
		return nil, true, ErrDNSServiceUnavailable
	}
	result, err := tool.binding.call(server, ctx, args)
	return result, true, err
}
