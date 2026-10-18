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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Every DNSService method reaches a tool of the newer family, which speaks
// its request and response in proto JSON form.
func TestDNSTools_CoverEveryMethod(t *testing.T) {
	desc := platformv1.DNSService_ServiceDesc
	for _, m := range desc.Methods {
		method := "/" + desc.ServiceName + "/" + m.MethodName
		assert.Equal(t, dnsToolMap[method], MethodTools()[method], "%s", method)
		assert.Contains(t, mcpArgBuilders, method)
		assert.Contains(t, mcpReplyDecoders, method)
	}
	assert.Len(t, dnsToolMap, len(desc.Methods))
}

// The request goes out as proto JSON (enums by name) and the reply comes
// back the same way, so the newer tools' arguments and results round-trip.
func TestDNSTools_CarryTheProtoJSONForm(t *testing.T) {
	tests := []struct {
		method string
		tool   string
		req    proto.Message
		result map[string]interface{}
		reply  proto.Message
		args   map[string]interface{}
		want   proto.Message
	}{
		{platformv1.DNSService_AddRecord_FullMethodName, "dns_record_create",
			&platformv1.AddRecordRequest{ZoneName: "example.internal.", Record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_A,
				Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "10.0.0.2"}}}},
			map[string]interface{}{"status": map[string]interface{}{"success": true}},
			&platformv1.AddRecordResponse{},
			map[string]interface{}{"zone_name": "example.internal.", "record": map[string]interface{}{
				"type": "RECORD_TYPE_A", "a": map[string]interface{}{"name": "www", "value": "10.0.0.2"}}},
			&platformv1.AddRecordResponse{Status: &platformv1.Status{Success: true}}},
		{platformv1.DNSService_SignZone_FullMethodName, "dns_zone_sign",
			&platformv1.SignZoneRequest{ZoneName: "example.internal."},
			map[string]interface{}{"zone": map[string]interface{}{"name": "example.internal."}},
			&platformv1.SignZoneResponse{},
			map[string]interface{}{"zone_name": "example.internal."},
			&platformv1.SignZoneResponse{Zone: &platformv1.Zone{Name: "example.internal."}}},
		{platformv1.DNSService_GetDNSSECStatus_FullMethodName, "dns_zone_dnssec_status",
			&platformv1.GetDNSSECStatusRequest{ZoneName: "example.internal."},
			map[string]interface{}{"status": map[string]interface{}{"enabled": true, "zone_signed": true}},
			&platformv1.GetDNSSECStatusResponse{},
			map[string]interface{}{"zone_name": "example.internal."},
			&platformv1.GetDNSSECStatusResponse{Status: &platformv1.DNSSECStatus{Enabled: true, ZoneSigned: true}}},
		{platformv1.DNSService_Register_FullMethodName, "dns_register",
			&platformv1.RegisterRequest{Fqdn: "host1.example.internal.", Ip: "10.0.0.7"},
			map[string]interface{}{"zone": map[string]interface{}{"name": "example.internal."}},
			&platformv1.RegisterResponse{},
			map[string]interface{}{"fqdn": "host1.example.internal.", "ip": "10.0.0.7"},
			&platformv1.RegisterResponse{Zone: &platformv1.Zone{Name: "example.internal."}}},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			calls, err := invokePhase35(t, map[string]interface{}{tt.tool: tt.result}, tt.method, tt.req, tt.reply)
			require.NoError(t, err)
			require.Len(t, calls, 1)
			assert.Equal(t, tt.tool, calls[0].Name)
			assert.Equal(t, tt.args, calls[0].Arguments)
			assert.True(t, proto.Equal(tt.want, tt.reply), "reply = %v, want %v", tt.reply, tt.want)
		})
	}
}

// A result the response message cannot hold is refused, not half-decoded.
func TestDNSTools_RefuseAReplyTheResponseCannotHold(t *testing.T) {
	_, err := invokePhase35(t,
		map[string]interface{}{"dns_zone_dnssec_status": map[string]interface{}{"status": map[string]interface{}{"enabled": "yes"}}},
		platformv1.DNSService_GetDNSSECStatus_FullMethodName,
		&platformv1.GetDNSSECStatusRequest{ZoneName: "example.internal."}, &platformv1.GetDNSSECStatusResponse{})
	requireCode(t, err, codes.Internal)
}
