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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// dnsToolMap maps each DNSService method to the platformd tool of the newer
// DNS family, which decodes its arguments into the RPC request and answers
// the RPC response, both in proto JSON form (pkg/api/mcp/dns_tools.go). The
// older family (dns_add_record, ...) takes FQDN-shaped arguments no request
// message carries, so the SDK never calls it.
var dnsToolMap = map[string]string{
	platformv1.DNSService_CreateZone_FullMethodName:      "dns_zone_create",
	platformv1.DNSService_GetZone_FullMethodName:         "dns_zone_get",
	platformv1.DNSService_ListZones_FullMethodName:       "dns_zone_list",
	platformv1.DNSService_UpdateZone_FullMethodName:      "dns_zone_update",
	platformv1.DNSService_DeleteZone_FullMethodName:      "dns_zone_delete",
	platformv1.DNSService_AddRecord_FullMethodName:       "dns_record_create",
	platformv1.DNSService_ListRecords_FullMethodName:     "dns_record_list",
	platformv1.DNSService_UpdateRecord_FullMethodName:    "dns_record_update",
	platformv1.DNSService_DeleteRecord_FullMethodName:    "dns_record_delete",
	platformv1.DNSService_Resolve_FullMethodName:         "dns_lookup",
	platformv1.DNSService_SignZone_FullMethodName:        "dns_zone_sign",
	platformv1.DNSService_GetDNSSECStatus_FullMethodName: "dns_zone_dnssec_status",
	platformv1.DNSService_Register_FullMethodName:        "dns_register",
}

func init() {
	for method, tool := range dnsToolMap {
		grpcMethodToMCPToolMap[method] = tool
		mcpArgBuilders[method] = protoJSONArgs(method)
		mcpReplyDecoders[method] = protoJSONReply(method)
	}
}
