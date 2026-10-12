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

package device

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeDeviceServiceClient stubs the assignment RPCs; the embedded
// interface panics on any other method, which pins the client methods
// under test to exactly the RPCs they are expected to call.
type fakeDeviceServiceClient struct {
	platformv1.DeviceServiceClient

	assignReq    *platformv1.AssignProfileToDeviceRequest
	assignResp   *platformv1.AssignProfileToDeviceResponse
	assignErr    error
	unassignReq  *platformv1.UnassignProfileFromDeviceRequest
	unassignResp *platformv1.UnassignProfileFromDeviceResponse
	unassignErr  error
	recordReq    *platformv1.RecordAttestationCertificateRequest
	recordResp   *platformv1.RecordAttestationCertificateResponse
	recordErr    error
}

func (f *fakeDeviceServiceClient) RecordAttestationCertificate(ctx context.Context, in *platformv1.RecordAttestationCertificateRequest, opts ...grpc.CallOption) (*platformv1.RecordAttestationCertificateResponse, error) {
	f.recordReq = in
	return f.recordResp, f.recordErr
}

func (f *fakeDeviceServiceClient) AssignProfileToDevice(ctx context.Context, in *platformv1.AssignProfileToDeviceRequest, opts ...grpc.CallOption) (*platformv1.AssignProfileToDeviceResponse, error) {
	f.assignReq = in
	return f.assignResp, f.assignErr
}

func (f *fakeDeviceServiceClient) UnassignProfileFromDevice(ctx context.Context, in *platformv1.UnassignProfileFromDeviceRequest, opts ...grpc.CallOption) (*platformv1.UnassignProfileFromDeviceResponse, error) {
	f.unassignReq = in
	return f.unassignResp, f.unassignErr
}

// TestClient_AssignProfile verifies the request mapping and the returned
// profile on the happy path.
func TestClient_AssignProfile(t *testing.T) {
	fake := &fakeDeviceServiceClient{
		assignResp: &platformv1.AssignProfileToDeviceResponse{
			Profile: &platformv1.DeviceProfile{Id: 123, Assigned: true, EkSerial: "EK-1"},
		},
	}
	client := NewClientFromGRPC(fake)

	profile, err := client.AssignProfile(context.Background(), 123, "EK-1", "00:25:90:ff:aa:02", "PEM")
	if err != nil {
		t.Fatalf("AssignProfile: %v", err)
	}
	if profile.GetId() != 123 || !profile.GetAssigned() {
		t.Errorf("profile = %+v, want assigned 123", profile)
	}

	req := fake.assignReq
	if req.GetProfileId() != 123 || req.GetEkSerial() != "EK-1" ||
		req.GetMacAddress() != "00:25:90:ff:aa:02" || req.GetEkCert() != "PEM" {
		t.Errorf("request = %+v, fields not mapped", req)
	}
}

// TestClient_AssignProfile_Error verifies transport errors wrap into the
// typed ErrAssignProfileFailed.
func TestClient_RecordAttestationCertificate_SendsBothOptions(t *testing.T) {
	fake := &fakeDeviceServiceClient{recordResp: &platformv1.RecordAttestationCertificateResponse{Cleared: true, Refusal: "not restricted"}}
	client := NewClientFromGRPC(fake)

	resp, err := client.RecordAttestationCertificate(context.Background(), 42, RecordAttestCertOptions{ClearOnRefusal: true})
	if err != nil {
		t.Fatalf("RecordAttestationCertificate: %v", err)
	}
	if fake.recordReq.GetDeviceId() != "42" || fake.recordReq.GetReissue() || !fake.recordReq.GetClearOnRefusal() {
		t.Errorf("request = %+v, want device 42, clear only", fake.recordReq)
	}
	if !resp.GetCleared() || resp.GetRefusal() != "not restricted" {
		t.Errorf("response = %+v, want the clear reported", resp)
	}

	if _, err := client.RecordAttestationCertificate(context.Background(), 42, RecordAttestCertOptions{}); err != nil {
		t.Fatalf("RecordAttestationCertificate: %v", err)
	}
	if fake.recordReq.GetReissue() || fake.recordReq.GetClearOnRefusal() {
		t.Errorf("zero options sent %+v, want neither flag", fake.recordReq)
	}
}

func TestClient_RecordAttestationCertificate_Error(t *testing.T) {
	cause := errors.New("refused")
	fake := &fakeDeviceServiceClient{recordErr: cause}
	client := NewClientFromGRPC(fake)

	_, err := client.RecordAttestationCertificate(context.Background(), 7, RecordAttestCertOptions{Reissue: true})
	var typed *ErrRecordAttestCertFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want ErrRecordAttestCertFailed", err)
	}
	if typed.ID != 7 || !errors.Is(err, cause) {
		t.Errorf("typed = %+v, cause lost", typed)
	}
}

func TestClient_AssignProfile_Error(t *testing.T) {
	cause := errors.New("boom")
	fake := &fakeDeviceServiceClient{assignErr: cause}
	client := NewClientFromGRPC(fake)

	_, err := client.AssignProfile(context.Background(), 5, "EK-1", "", "")
	var typed *ErrAssignProfileFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want ErrAssignProfileFailed", err)
	}
	if typed.ProfileID != 5 || !errors.Is(err, cause) {
		t.Errorf("typed = %+v, cause lost", typed)
	}
}

// TestClient_UnassignProfile verifies the request mapping and the
// returned profile on the happy path.
func TestClient_UnassignProfile(t *testing.T) {
	fake := &fakeDeviceServiceClient{
		unassignResp: &platformv1.UnassignProfileFromDeviceResponse{
			Profile: &platformv1.DeviceProfile{Id: 200, Assigned: false},
		},
	}
	client := NewClientFromGRPC(fake)

	profile, err := client.UnassignProfile(context.Background(), 200)
	if err != nil {
		t.Fatalf("UnassignProfile: %v", err)
	}
	if profile.GetId() != 200 || profile.GetAssigned() {
		t.Errorf("profile = %+v, want unassigned 200", profile)
	}
	if fake.unassignReq.GetProfileId() != 200 {
		t.Errorf("request ProfileId = %d, want 200", fake.unassignReq.GetProfileId())
	}
}

// TestClient_UnassignProfile_Error verifies transport errors wrap into
// the typed ErrUnassignProfileFailed.
func TestClient_UnassignProfile_Error(t *testing.T) {
	cause := errors.New("boom")
	fake := &fakeDeviceServiceClient{unassignErr: cause}
	client := NewClientFromGRPC(fake)

	_, err := client.UnassignProfile(context.Background(), 7)
	var typed *ErrUnassignProfileFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want ErrUnassignProfileFailed", err)
	}
	if typed.ProfileID != 7 || !errors.Is(err, cause) {
		t.Errorf("typed = %+v, cause lost", typed)
	}
}
