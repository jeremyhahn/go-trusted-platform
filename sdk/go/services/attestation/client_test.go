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

package attestation

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeAttestationServiceClient stubs the device-report RPCs; the embedded
// interface panics on any other method, which pins the client methods under
// test to exactly the RPCs they are expected to call.
type fakeAttestationServiceClient struct {
	platformv1.AttestationServiceClient

	listResp *platformv1.ListDeviceReportsResponse
	listErr  error

	getReq  *platformv1.GetDeviceReportRequest
	getResp *platformv1.GetDeviceReportResponse
	getErr  error

	refreshReq  *platformv1.RefreshDeviceReportRequest
	refreshResp *platformv1.RefreshDeviceReportResponse
	refreshErr  error

	describeResp *platformv1.DescribeCallerPolicyResponse
	describeErr  error
}

func (f *fakeAttestationServiceClient) ListDeviceReports(context.Context, *platformv1.ListDeviceReportsRequest, ...grpc.CallOption) (*platformv1.ListDeviceReportsResponse, error) {
	return f.listResp, f.listErr
}

func (f *fakeAttestationServiceClient) GetDeviceReport(_ context.Context, in *platformv1.GetDeviceReportRequest, _ ...grpc.CallOption) (*platformv1.GetDeviceReportResponse, error) {
	f.getReq = in
	return f.getResp, f.getErr
}

func (f *fakeAttestationServiceClient) RefreshDeviceReport(_ context.Context, in *platformv1.RefreshDeviceReportRequest, _ ...grpc.CallOption) (*platformv1.RefreshDeviceReportResponse, error) {
	f.refreshReq = in
	return f.refreshResp, f.refreshErr
}

func (f *fakeAttestationServiceClient) DescribeCallerPolicy(context.Context, *platformv1.DescribeCallerPolicyRequest, ...grpc.CallOption) (*platformv1.DescribeCallerPolicyResponse, error) {
	return f.describeResp, f.describeErr
}

func sampleReport(id string) *platformv1.DeviceAttestationReport {
	return &platformv1.DeviceAttestationReport{
		DeviceId: id, Serial: "SN-" + id, Verified: true, Fresh: true, AgeSeconds: 42,
		AsOf: timestamppb.Now(), CollectedAt: timestamppb.Now(),
	}
}

func TestClient_ListDeviceReports(t *testing.T) {
	fake := &fakeAttestationServiceClient{
		listResp: &platformv1.ListDeviceReportsResponse{
			Reports: []*platformv1.DeviceAttestationReport{sampleReport("1"), sampleReport("2")},
			Total:   2,
		},
	}
	reports, err := NewClientFromGRPC(fake).ListDeviceReports(context.Background())
	if err != nil {
		t.Fatalf("ListDeviceReports: %v", err)
	}
	if len(reports) != 2 || reports[0].GetDeviceId() != "1" || reports[1].GetDeviceId() != "2" {
		t.Errorf("reports = %+v, want devices 1 and 2", reports)
	}
}

func TestClient_ListDeviceReports_Error(t *testing.T) {
	fake := &fakeAttestationServiceClient{listErr: status.Error(codes.Unavailable, "reporting not configured")}
	_, err := NewClientFromGRPC(fake).ListDeviceReports(context.Background())
	var typed *ErrListDeviceReportsFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *ErrListDeviceReportsFailed", err)
	}
	if status.Code(errors.Unwrap(err)) != codes.Unavailable {
		t.Errorf("cause = %v, want the transport status preserved", errors.Unwrap(err))
	}
}

func TestClient_GetDeviceReport(t *testing.T) {
	fake := &fakeAttestationServiceClient{
		getResp: &platformv1.GetDeviceReportResponse{Report: sampleReport("7")},
	}
	report, err := NewClientFromGRPC(fake).GetDeviceReport(context.Background(), "7")
	if err != nil {
		t.Fatalf("GetDeviceReport: %v", err)
	}
	if fake.getReq.GetDeviceId() != "7" {
		t.Errorf("request device_id = %q, want 7", fake.getReq.GetDeviceId())
	}
	if !report.GetVerified() || report.GetAgeSeconds() != 42 {
		t.Errorf("report = %+v, want verified with age 42", report)
	}
}

func TestClient_GetDeviceReport_EmptyIDRejectedBeforeTheCall(t *testing.T) {
	fake := &fakeAttestationServiceClient{}
	_, err := NewClientFromGRPC(fake).GetDeviceReport(context.Background(), "")
	var typed *ErrDeviceIDRequired
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *ErrDeviceIDRequired", err)
	}
	if fake.getReq != nil {
		t.Error("an empty device id must never reach the transport")
	}
}

// TestClient_GetDeviceReport_NeverCollected pins the state distinction: a
// NotFound from the server is *ErrNoDeviceReport, never a report and never
// the generic failure.
func TestClient_GetDeviceReport_NeverCollected(t *testing.T) {
	cases := map[string]error{
		"grpc NotFound":       status.Error(codes.NotFound, "no report has been collected for device 9"),
		"mcp collapsed error": status.Error(codes.Internal, "attestation: no report has been collected for device 9"),
	}
	for name, cause := range cases {
		t.Run(name, func(t *testing.T) {
			fake := &fakeAttestationServiceClient{getErr: cause}
			report, err := NewClientFromGRPC(fake).GetDeviceReport(context.Background(), "9")
			var never *ErrNoDeviceReport
			if !errors.As(err, &never) {
				t.Fatalf("err = %v, want *ErrNoDeviceReport", err)
			}
			if never.DeviceID != "9" || report != nil {
				t.Errorf("never = %+v report = %v, want device 9 and no report", never, report)
			}
			var failed *ErrGetDeviceReportFailed
			if errors.As(err, &failed) {
				t.Error("never collected must not also read as a failed read")
			}
		})
	}
}

func TestClient_GetDeviceReport_OtherErrorsAreFailures(t *testing.T) {
	fake := &fakeAttestationServiceClient{getErr: status.Error(codes.PermissionDenied, "admin role required")}
	_, err := NewClientFromGRPC(fake).GetDeviceReport(context.Background(), "9")
	var typed *ErrGetDeviceReportFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *ErrGetDeviceReportFailed", err)
	}
	var never *ErrNoDeviceReport
	if errors.As(err, &never) {
		t.Error("a permission failure must not read as never collected")
	}
}

func TestIsNeverCollected_NonStatusError(t *testing.T) {
	if isNeverCollected(errors.New("no report has been collected for device 1")) {
		t.Error("a plain error is not a transport status and must not classify")
	}
}

func TestClient_RefreshDeviceReport(t *testing.T) {
	fake := &fakeAttestationServiceClient{
		refreshResp: &platformv1.RefreshDeviceReportResponse{DeviceId: "3", Enqueued: true, Note: "collection enqueued"},
	}
	resp, err := NewClientFromGRPC(fake).RefreshDeviceReport(context.Background(), "3")
	if err != nil {
		t.Fatalf("RefreshDeviceReport: %v", err)
	}
	if fake.refreshReq.GetDeviceId() != "3" || !resp.GetEnqueued() {
		t.Errorf("req = %+v resp = %+v, want device 3 enqueued", fake.refreshReq, resp)
	}
}

func TestClient_RefreshDeviceReport_Errors(t *testing.T) {
	fake := &fakeAttestationServiceClient{}
	_, err := NewClientFromGRPC(fake).RefreshDeviceReport(context.Background(), "")
	var required *ErrDeviceIDRequired
	if !errors.As(err, &required) || fake.refreshReq != nil {
		t.Fatalf("err = %v (req %v), want *ErrDeviceIDRequired before any call", err, fake.refreshReq)
	}

	fake = &fakeAttestationServiceClient{refreshErr: status.Error(codes.Unavailable, "collector stopped")}
	_, err = NewClientFromGRPC(fake).RefreshDeviceReport(context.Background(), "3")
	var failed *ErrRefreshDeviceReportFailed
	if !errors.As(err, &failed) || failed.DeviceID != "3" {
		t.Fatalf("err = %v, want *ErrRefreshDeviceReportFailed for device 3", err)
	}
}

func TestClient_DescribeCallerPolicy(t *testing.T) {
	fake := &fakeAttestationServiceClient{
		describeResp: &platformv1.DescribeCallerPolicyResponse{
			Policy: &platformv1.CallerPolicyDescription{Strategy: "identity-list", Identities: []string{"cp.example.internal"}, ListValid: true},
		},
	}
	policy, err := NewClientFromGRPC(fake).DescribeCallerPolicy(context.Background())
	if err != nil {
		t.Fatalf("DescribeCallerPolicy: %v", err)
	}
	if policy.GetStrategy() != "identity-list" || len(policy.GetIdentities()) != 1 {
		t.Errorf("policy = %+v, want identity-list with one identity", policy)
	}
}

func TestClient_DescribeCallerPolicy_Error(t *testing.T) {
	fake := &fakeAttestationServiceClient{describeErr: status.Error(codes.Unavailable, "not configured")}
	_, err := NewClientFromGRPC(fake).DescribeCallerPolicy(context.Background())
	var typed *ErrDescribeCallerPolicyFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *ErrDescribeCallerPolicyFailed", err)
	}
}
