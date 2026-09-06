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
package mcp

import (
	"context"
	"errors"
	"testing"

	mcpapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// sampleView is a reporting.View as the server tool marshals it: snake_case
// names, RFC 3339 timestamps.
func sampleView(id string) map[string]interface{} {
	return map[string]interface{}{
		"device_id": id, "serial": "SN-" + id, "model": "X10SDV",
		"verified": true, "ak_certificate_verified": true, "signature_valid": true,
		"nonce_valid": true, "pcrs_valid": true, "cryptographic_failure": false,
		"pcr_baseline_source": "signed", "pcr_baseline_recorded_at": "2026-09-01T10:00:00Z",
		"pcr_baseline_captured": true, "status": "verified",
		"attested_at": "2026-09-05T12:00:00Z", "collected_at": "2026-09-05T12:00:01Z",
		"fresh": true, "age_seconds": float64(42), "as_of": "2026-09-05T12:00:43Z",
	}
}

// TestAttestationReportsMCP_ToolMappingParity checks every mapped tool is one
// the server registers and has a decoder, so the client cannot call a tool
// that does not exist or decode a shape it does not understand.
func TestAttestationReportsMCP_ToolMappingParity(t *testing.T) {
	registry := mcpapi.NewToolRegistry(nil, logging.DefaultLogger())
	registered := map[string]bool{}
	for _, td := range registry.ListTools() {
		registered[td.Name] = true
	}
	methods := []string{
		platformv1.AttestationService_GetDeviceReport_FullMethodName,
		platformv1.AttestationService_ListDeviceReports_FullMethodName,
		platformv1.AttestationService_RefreshDeviceReport_FullMethodName,
		platformv1.AttestationService_DescribeCallerPolicy_FullMethodName,
	}
	for _, method := range methods {
		tool, ok := grpcMethodToMCPToolMap[method]
		if !ok {
			t.Errorf("%s is not mapped to an MCP tool", method)
			continue
		}
		if !registered[tool] {
			t.Errorf("adapter maps %s -> %q but the server does not register that tool", method, tool)
		}
		if _, has := mcpReplyDecoders[method]; !has {
			t.Errorf("%s missing reply decoder", method)
		}
	}
}

func TestAttestationReportsMCP_Get_ArgsAndDecode(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"attestation_device_report": sampleView("9"),
	}, &calls)

	resp := &platformv1.GetDeviceReportResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_GetDeviceReport_FullMethodName,
		&platformv1.GetDeviceReportRequest{DeviceId: "9"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "attestation_device_report" || calls[0].Arguments["device_id"] != "9" {
		t.Fatalf("calls = %+v, want attestation_device_report with device_id 9", calls)
	}
	r := resp.GetReport()
	if r.GetDeviceId() != "9" || !r.GetVerified() || !r.GetFresh() || r.GetAgeSeconds() != 42 {
		t.Errorf("report = %+v, want device 9 verified, fresh, age 42", r)
	}
	if r.GetAttestedAt().AsTime().Year() != 2026 || r.GetPcrBaselineSource() != "signed" {
		t.Errorf("attested_at = %v baseline = %q, want RFC 3339 decoded and signed", r.GetAttestedAt(), r.GetPcrBaselineSource())
	}
}

func TestAttestationReportsMCP_List_Decode(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"attestation_device_reports": map[string]interface{}{
			"reports": []interface{}{sampleView("1"), sampleView("2")},
			"count":   float64(2),
		},
	}, &calls)

	resp := &platformv1.ListDeviceReportsResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_ListDeviceReports_FullMethodName,
		&platformv1.ListDeviceReportsRequest{}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(resp.GetReports()) != 2 || resp.GetTotal() != 2 || resp.GetReports()[1].GetDeviceId() != "2" {
		t.Errorf("resp = %+v, want two reports with total 2", resp)
	}
}

func TestAttestationReportsMCP_Refresh_Decode(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"attestation_device_refresh": map[string]interface{}{"device_id": "9", "enqueued": true, "note": "collection enqueued"},
	}, &calls)

	resp := &platformv1.RefreshDeviceReportResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_RefreshDeviceReport_FullMethodName,
		&platformv1.RefreshDeviceReportRequest{DeviceId: "9"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["device_id"] != "9" || !resp.GetEnqueued() || resp.GetDeviceId() != "9" {
		t.Errorf("calls = %+v resp = %+v, want device 9 enqueued", calls, resp)
	}
}

func TestAttestationReportsMCP_Callers_Decode(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"attestation_caller_policy": map[string]interface{}{
			"strategy": "identity-list", "identities": []interface{}{"cp.example.internal"},
			"identities_source": "config", "list_valid": true, "anchors_configured": true,
			"anchor_source": "trust.internal", "attested_peers_available": false, "admits_nobody": false,
		},
	}, &calls)

	resp := &platformv1.DescribeCallerPolicyResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_DescribeCallerPolicy_FullMethodName,
		&platformv1.DescribeCallerPolicyRequest{}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	p := resp.GetPolicy()
	if p.GetStrategy() != "identity-list" || len(p.GetIdentities()) != 1 || !p.GetListValid() {
		t.Errorf("policy = %+v, want identity-list with one identity and a valid list", p)
	}
}

func TestAttestationReportsMCP_Decoders_RejectWrongReplyAndBadShape(t *testing.T) {
	decoders := map[string]struct {
		decode mcpReplyDecoder
		reply  interface{}
	}{
		"get":     {decodeDeviceReportResult, &platformv1.GetDeviceReportResponse{}},
		"list":    {decodeDeviceReportsResult, &platformv1.ListDeviceReportsResponse{}},
		"refresh": {decodeDeviceRefreshResult, &platformv1.RefreshDeviceReportResponse{}},
		"callers": {decodeCallerPolicyResult, &platformv1.DescribeCallerPolicyResponse{}},
	}
	for name, d := range decoders {
		t.Run(name, func(t *testing.T) {
			var wrong ErrUnexpectedReplyType
			if err := d.decode(map[string]interface{}{}, &platformv1.GetNonceResponse{}); !errors.As(err, &wrong) {
				t.Errorf("wrong reply type: err = %v, want ErrUnexpectedReplyType", err)
			}
			var bad ErrUnmarshalFailed
			// A JSON array is not an object, so protojson refuses it for every message.
			if err := d.decode([]interface{}{"not", "an", "object"}, d.reply); !errors.As(err, &bad) {
				t.Errorf("bad shape: err = %v, want ErrUnmarshalFailed", err)
			}
		})
	}
}

// TestAttestationReportsMCP_TimeSyncedSurvivesTheWire is the MCP half of
// #509: the tool result is generic JSON re-encoded and read with protojson,
// so a `time_synced` the device never reported must arrive ABSENT rather than
// false. Recording it as false would put a fabricated claim about a machine's
// clock beside its attestation verdict.
func TestAttestationReportsMCP_TimeSyncedSurvivesTheWire(t *testing.T) {
	for name, tc := range map[string]struct {
		set     bool
		value   bool
		present bool
	}{
		"synced":   {set: true, value: true, present: true},
		"unsynced": {set: true, value: false, present: true},
		"unknown":  {set: false},
	} {
		t.Run(name, func(t *testing.T) {
			view := sampleView("9")
			if tc.set {
				view["time_synced"] = tc.value
			}
			var calls []toolCall
			a := provisioningTestServer(t, map[string]interface{}{
				"attestation_device_report": view,
			}, &calls)

			resp := &platformv1.GetDeviceReportResponse{}
			err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_GetDeviceReport_FullMethodName,
				&platformv1.GetDeviceReportRequest{DeviceId: "9"}, resp)
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			got := resp.GetReport().TimeSynced
			if !tc.present {
				if got != nil {
					t.Fatalf("time_synced = %v, want absent", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("time_synced was dropped by the MCP decoder")
			}
			if *got != tc.value {
				t.Errorf("time_synced = %v, want %v", *got, tc.value)
			}
		})
	}
}
