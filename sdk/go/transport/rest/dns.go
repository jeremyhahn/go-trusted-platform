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
	"encoding/json"
	"net/http"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// DNS zones and records (#452, #445). The webservice DNS router
// (pkg/webservice/v1/rest/dns/router.go) keys a zone by the name in the path,
// every record operation by the zone in the path, and a single record by its
// type and name, as docs/dns/api.md specifies. The record type in a path or
// query travels as its mnemonic, "A" rather than "RECORD_TYPE_A".
//
// The server decodes the proto requests and answers the proto replies with
// protojson. Every DNS request body is sent as protojson too: the default
// encoding/json rendering spells a record's oneof and its type enum in a way
// protojson cannot read. Replies need no translation.
func init() {
	methods := platformv1.File_platform_dns_proto.Services().ByName("DNSService").Methods()
	for i := range methods.Len() {
		method := methods.Get(i)
		fullName := "/" + platformv1.DNSService_ServiceDesc.ServiceName + "/" + string(method.Name())
		restRequestEncoders[fullName] = dnsBodyEncoder(fullName, method.Input().FullName())
	}

	templatedRouteTable[platformv1.DNSService_GetZone_FullMethodName] =
		itemRoute("/api/v1/dns/zones/{zone}", http.MethodGet, "{zone}", "name")
	templatedRouteTable[platformv1.DNSService_UpdateZone_FullMethodName] =
		itemRoute("/api/v1/dns/zones/{zone}", http.MethodPut, "{zone}", "name")
	templatedRouteTable[platformv1.DNSService_DeleteZone_FullMethodName] =
		itemRoute("/api/v1/dns/zones/{zone}", http.MethodDelete, "{zone}", "name")
	templatedRouteTable[platformv1.DNSService_AddRecord_FullMethodName] =
		itemRoute("/api/v1/dns/zones/{zone}/records", http.MethodPost, "{zone}", "zone_name")
	templatedRouteTable[platformv1.DNSService_UpdateRecord_FullMethodName] =
		itemRoute("/api/v1/dns/zones/{zone}/records", http.MethodPut, "{zone}", "zone_name")
	templatedRouteTable[platformv1.DNSService_ListRecords_FullMethodName] = templatedRoute{
		path:        "/api/v1/dns/zones/{zone}/records",
		method:      http.MethodGet,
		pathParams:  []pathParam{{placeholder: "{zone}", field: "zone_name"}},
		queryParams: []queryParam{{name: "type", field: "type", encode: dnsRecordTypeField}},
	}
	templatedRouteTable[platformv1.DNSService_DeleteRecord_FullMethodName] = templatedRoute{
		path:   "/api/v1/dns/zones/{zone}/records/{type}/{name}",
		method: http.MethodDelete,
		pathParams: []pathParam{
			{placeholder: "{zone}", field: "zone_name"},
			{placeholder: "{type}", field: "type", encode: dnsRecordTypeField},
			{placeholder: "{name}", field: "name"},
		},
	}
	templatedRouteTable[platformv1.DNSService_SignZone_FullMethodName] =
		itemRoute("/api/v1/dns/zones/{zone}/sign", http.MethodPost, "{zone}", "zone_name")
	templatedRouteTable[platformv1.DNSService_GetDNSSECStatus_FullMethodName] =
		itemRoute("/api/v1/dns/zones/{zone}/dnssec", http.MethodGet, "{zone}", "zone_name")
	templatedRouteTable[platformv1.DNSService_Resolve_FullMethodName] = templatedRoute{
		path:   "/api/v1/dns/resolve",
		method: http.MethodGet,
		queryParams: []queryParam{
			{name: "fqdn", field: "fqdn"},
			{name: "type", field: "type", encode: dnsRecordTypeField},
		},
	}
}

// dnsRecordTypePrefix is the prefix every RecordType value name carries and
// the mnemonic does not.
const dnsRecordTypePrefix = "RECORD_TYPE_"

// dnsBodyJSON writes DNS request bodies in the proto JSON mapping the
// server's protorest decoder reads.
var dnsBodyJSON = protojson.MarshalOptions{}

// dnsBodyEncoder sends a DNS request (the clone with its path and query
// fields cleared, for a templated route) as its protojson body.
func dnsBodyEncoder(method string, input protoreflect.FullName) restRequestEncoder {
	return func(body interface{}) (interface{}, error) {
		msg, ok := body.(proto.Message)
		if !ok || msg == nil || msg.ProtoReflect().Descriptor().FullName() != input {
			return nil, ErrUnexpectedRequestType{Method: method}
		}
		raw, err := dnsBodyJSON.Marshal(msg)
		if err != nil {
			return nil, ErrMarshalFailed{Err: err}
		}
		return json.RawMessage(raw), nil
	}
}

// dnsRecordTypeField renders a RecordType request field for the URL as its
// mnemonic, "" for RECORD_TYPE_UNSPECIFIED.
func dnsRecordTypeField(v protoreflect.Value) string {
	recordType := platformv1.RecordType(v.Enum())
	if recordType == platformv1.RecordType_RECORD_TYPE_UNSPECIFIED {
		return ""
	}
	return strings.TrimPrefix(recordType.String(), dnsRecordTypePrefix)
}
