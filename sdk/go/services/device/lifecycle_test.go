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
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

type fakeLifecycleClient struct {
	platformv1.DeviceServiceClient

	disableReq *platformv1.DisableDeviceRequest
	enableReq  *platformv1.EnableDeviceRequest
	resp       *platformv1.DeviceLifecycleResponse
	err        error
}

func (f *fakeLifecycleClient) DisableDevice(_ context.Context, in *platformv1.DisableDeviceRequest, _ ...grpc.CallOption) (*platformv1.DeviceLifecycleResponse, error) {
	f.disableReq = in
	return f.resp, f.err
}

func (f *fakeLifecycleClient) EnableDevice(_ context.Context, in *platformv1.EnableDeviceRequest, _ ...grpc.CallOption) (*platformv1.DeviceLifecycleResponse, error) {
	f.enableReq = in
	return f.resp, f.err
}

func TestClient_Disable(t *testing.T) {
	fake := &fakeLifecycleClient{resp: &platformv1.DeviceLifecycleResponse{DeviceId: 42, State: "suspended"}}

	resp, err := NewClientFromGRPC(fake).Disable(context.Background(), 42, "rma pending")
	if err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if fake.disableReq.GetDeviceId() != "42" || fake.disableReq.GetReason() != "rma pending" {
		t.Errorf("request = %+v, want device 42 with the reason", fake.disableReq)
	}
	if resp.GetState() != "suspended" {
		t.Errorf("state = %q, want suspended", resp.GetState())
	}
}

func TestClient_Enable(t *testing.T) {
	fake := &fakeLifecycleClient{resp: &platformv1.DeviceLifecycleResponse{DeviceId: 42, State: "quarantined", ReattestationRequested: true}}

	resp, err := NewClientFromGRPC(fake).Enable(context.Background(), 42)
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if fake.enableReq.GetDeviceId() != "42" {
		t.Errorf("request = %+v, want device 42", fake.enableReq)
	}
	if !resp.GetReattestationRequested() {
		t.Error("the re-attestation request was not reported")
	}
}

func TestClient_LifecycleErrors(t *testing.T) {
	cause := errors.New("device is not suspended")
	client := NewClientFromGRPC(&fakeLifecycleClient{err: cause})

	_, err := client.Disable(context.Background(), 7, "")
	var disable *ErrDisableFailed
	if !errors.As(err, &disable) || disable.ID != 7 || !errors.Is(err, cause) {
		t.Fatalf("Disable err = %v, want ErrDisableFailed for 7 wrapping the cause", err)
	}
	if !strings.Contains(err.Error(), "7") {
		t.Errorf("message %q does not name the device", err.Error())
	}

	_, err = client.Enable(context.Background(), 7)
	var enable *ErrEnableFailed
	if !errors.As(err, &enable) || enable.ID != 7 || !errors.Is(err, cause) {
		t.Fatalf("Enable err = %v, want ErrEnableFailed for 7 wrapping the cause", err)
	}
	if !strings.Contains(err.Error(), "7") {
		t.Errorf("message %q does not name the device", err.Error())
	}
}
