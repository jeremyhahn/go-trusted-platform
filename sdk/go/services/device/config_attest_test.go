// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

type fakeConfigAttestClient struct {
	platformv1.DeviceServiceClient

	configReq  *platformv1.FindConfigForDeviceRequest
	configResp *platformv1.FindConfigForDeviceResponse
	attestReq  *platformv1.AttestDeviceRequest
	attestResp *platformv1.AttestDeviceResponse
	err        error
}

func (f *fakeConfigAttestClient) FindConfigForDevice(_ context.Context, in *platformv1.FindConfigForDeviceRequest, _ ...grpc.CallOption) (*platformv1.FindConfigForDeviceResponse, error) {
	f.configReq = in
	return f.configResp, f.err
}

func (f *fakeConfigAttestClient) AttestDevice(_ context.Context, in *platformv1.AttestDeviceRequest, _ ...grpc.CallOption) (*platformv1.AttestDeviceResponse, error) {
	f.attestReq = in
	return f.attestResp, f.err
}

func TestClient_FindConfigForDevice(t *testing.T) {
	fake := &fakeConfigAttestClient{configResp: &platformv1.FindConfigForDeviceResponse{
		Profile: &platformv1.DeviceProfile{Id: 9, Name: "by-ek"},
	}}

	profile, err := NewClientFromGRPC(fake).FindConfigForDevice(context.Background(), "EK-9", "52:54:00:00:00:09")
	if err != nil {
		t.Fatalf("FindConfigForDevice: %v", err)
	}
	if fake.configReq.GetEkSerial() != "EK-9" || fake.configReq.GetMacAddress() != "52:54:00:00:00:09" {
		t.Errorf("request = %+v, want the EK serial and MAC passed through", fake.configReq)
	}
	if profile.GetId() != 9 {
		t.Errorf("profile id = %d, want 9", profile.GetId())
	}
}

func TestClient_AttestDevice(t *testing.T) {
	fake := &fakeConfigAttestClient{attestResp: &platformv1.AttestDeviceResponse{DeviceId: 42, Verified: true}}
	evidence := []byte{0x01, 0x02, 0x03}

	resp, err := NewClientFromGRPC(fake).AttestDevice(context.Background(), 42, evidence)
	if err != nil {
		t.Fatalf("AttestDevice: %v", err)
	}
	if fake.attestReq.GetDeviceId() != "42" || !bytes.Equal(fake.attestReq.GetEvidence(), evidence) {
		t.Errorf("request = %+v, want device 42 with the evidence", fake.attestReq)
	}
	if !resp.GetVerified() {
		t.Error("the verified result was not reported")
	}
}

func TestClient_ConfigAttestErrors(t *testing.T) {
	cause := errors.New("no matching config")
	client := NewClientFromGRPC(&fakeConfigAttestClient{err: cause})

	_, err := client.FindConfigForDevice(context.Background(), "EK-NONE", "")
	var config *ErrFindConfigForDeviceFailed
	if !errors.As(err, &config) || !errors.Is(err, cause) {
		t.Fatalf("FindConfigForDevice err = %v, want ErrFindConfigForDeviceFailed wrapping the cause", err)
	}

	_, err = client.AttestDevice(context.Background(), 7, nil)
	var attest *ErrAttestDeviceFailed
	if !errors.As(err, &attest) || attest.ID != 7 || !errors.Is(err, cause) {
		t.Fatalf("AttestDevice err = %v, want ErrAttestDeviceFailed for 7 wrapping the cause", err)
	}
	if !strings.Contains(err.Error(), "7") {
		t.Errorf("message %q does not name the device", err.Error())
	}
}
