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
	"context"
	"errors"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const sampleViewJSON = `{"device_id":"9","serial":"SN-9","model":"X10SDV","verified":true,
"ak_certificate_verified":true,"signature_valid":true,"nonce_valid":true,"pcrs_valid":true,
"cryptographic_failure":false,"pcr_baseline_source":"tofu","pcr_baseline_recorded_at":"2026-09-01T10:00:00Z",
"pcr_baseline_captured":true,"status":"verified","message":"","attested_at":"2026-09-05T12:00:00Z",
"collected_at":"2026-09-05T12:00:01Z","fresh":true,"age_seconds":42,"as_of":"2026-09-05T12:00:43Z"}`

type capturedRequest struct {
	method string
	path   string
}

func attestationServer(t *testing.T, statusCode int, body string, captured *capturedRequest) *Adapter {
	t.Helper()
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
	})
	return a
}

func TestAttestationReports_Get_RouteAndDecode(t *testing.T) {
	var captured capturedRequest
	a := attestationServer(t, http.StatusOK, envelope(sampleViewJSON), &captured)

	resp := &platformv1.GetDeviceReportResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_GetDeviceReport_FullMethodName,
		&platformv1.GetDeviceReportRequest{DeviceId: "9"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if captured.method != http.MethodGet || captured.path != "/api/v1/attestation/reports/9" {
		t.Errorf("request = %s %s, want GET /api/v1/attestation/reports/9", captured.method, captured.path)
	}
	r := resp.GetReport()
	if r.GetDeviceId() != "9" || !r.GetVerified() || !r.GetFresh() || r.GetAgeSeconds() != 42 {
		t.Errorf("report = %+v, want device 9 verified, fresh, age 42", r)
	}
	if r.GetPcrBaselineSource() != "tofu" || r.GetPcrBaselineRecordedAt().AsTime().Year() != 2026 {
		t.Errorf("baseline = %q at %v, want tofu recorded in 2026", r.GetPcrBaselineSource(), r.GetPcrBaselineRecordedAt())
	}
	if r.GetAsOf().AsTime().Unix()-r.GetCollectedAt().AsTime().Unix() != 42 {
		t.Errorf("as_of - collected_at = %d, want the RFC 3339 timestamps decoded (42s apart)",
			r.GetAsOf().AsTime().Unix()-r.GetCollectedAt().AsTime().Unix())
	}
}

// TestAttestationReports_Get_NeverCollectedIsNotFound pins the state the
// CLI branches on: a 404 arrives as codes.NotFound, never as an empty report.
func TestAttestationReports_Get_NeverCollectedIsNotFound(t *testing.T) {
	var captured capturedRequest
	a := attestationServer(t, http.StatusNotFound,
		`{"code":404,"error":"attestation: no report has been collected for device 9","success":false}`, &captured)

	resp := &platformv1.GetDeviceReportResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_GetDeviceReport_FullMethodName,
		&platformv1.GetDeviceReportRequest{DeviceId: "9"}, resp)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want codes.NotFound", err)
	}
	if resp.GetReport() != nil {
		t.Error("never collected must not populate a report")
	}
}

func TestAttestationReports_List_RouteAndDecode(t *testing.T) {
	var captured capturedRequest
	a := attestationServer(t, http.StatusOK, envelope(`{"reports":[`+sampleViewJSON+`],"count":1}`), &captured)

	resp := &platformv1.ListDeviceReportsResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_ListDeviceReports_FullMethodName,
		&platformv1.ListDeviceReportsRequest{}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if captured.method != http.MethodGet || captured.path != "/api/v1/attestation/reports" {
		t.Errorf("request = %s %s, want GET /api/v1/attestation/reports", captured.method, captured.path)
	}
	if len(resp.GetReports()) != 1 || resp.GetTotal() != 1 || resp.GetReports()[0].GetDeviceId() != "9" {
		t.Errorf("resp = %+v, want one report for device 9 with total 1", resp)
	}
}

func TestAttestationReports_Refresh_RouteAndDecode(t *testing.T) {
	var captured capturedRequest
	a := attestationServer(t, http.StatusAccepted,
		`{"code":202,"error":"","success":true,"payload":{"device_id":"9","enqueued":true,"note":"collection enqueued"}}`, &captured)

	resp := &platformv1.RefreshDeviceReportResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_RefreshDeviceReport_FullMethodName,
		&platformv1.RefreshDeviceReportRequest{DeviceId: "9"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if captured.method != http.MethodPost || captured.path != "/api/v1/attestation/reports/9/refresh" {
		t.Errorf("request = %s %s, want POST /api/v1/attestation/reports/9/refresh", captured.method, captured.path)
	}
	if !resp.GetEnqueued() || resp.GetDeviceId() != "9" || resp.GetNote() == "" {
		t.Errorf("resp = %+v, want enqueued for device 9 with a note", resp)
	}
}

func TestAttestationReports_Callers_RouteAndDecode(t *testing.T) {
	var captured capturedRequest
	a := attestationServer(t, http.StatusOK, envelope(`{"strategy":"identity-list","identities":["cp.example.internal"],
"identities_source":"config","list_valid":true,"anchors_configured":true,"anchor_source":"trust.internal",
"attested_peers_available":false,"admits_nobody":false}`), &captured)

	resp := &platformv1.DescribeCallerPolicyResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_DescribeCallerPolicy_FullMethodName,
		&platformv1.DescribeCallerPolicyRequest{}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if captured.method != http.MethodGet || captured.path != "/api/v1/attestation/callers" {
		t.Errorf("request = %s %s, want GET /api/v1/attestation/callers", captured.method, captured.path)
	}
	p := resp.GetPolicy()
	if p.GetStrategy() != "identity-list" || len(p.GetIdentities()) != 1 || !p.GetListValid() || !p.GetAnchorsConfigured() {
		t.Errorf("policy = %+v, want identity-list, one identity, valid list, anchors configured", p)
	}
}

func TestAttestationReports_Decoders_RejectWrongReplyAndBadJSON(t *testing.T) {
	decoders := map[string]struct {
		decode restResponseDecoder
		reply  interface{}
	}{
		"get":     {decodeDeviceReport, &platformv1.GetDeviceReportResponse{}},
		"list":    {decodeDeviceReports, &platformv1.ListDeviceReportsResponse{}},
		"callers": {decodeCallerPolicy, &platformv1.DescribeCallerPolicyResponse{}},
	}
	for name, d := range decoders {
		t.Run(name, func(t *testing.T) {
			var wrong ErrUnexpectedReplyType
			if err := d.decode([]byte(`{}`), &platformv1.GetNonceResponse{}); !errors.As(err, &wrong) {
				t.Errorf("wrong reply type: err = %v, want ErrUnexpectedReplyType", err)
			}
			var bad ErrUnmarshalFailed
			if err := d.decode([]byte(`not json`), d.reply); !errors.As(err, &bad) {
				t.Errorf("bad json: err = %v, want ErrUnmarshalFailed", err)
			}
		})
	}
}
