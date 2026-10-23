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

package embedded

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

type lifecycleServer struct {
	platformv1.UnimplementedDeviceServiceServer
	disabled *platformv1.DisableDeviceRequest
	enabled  *platformv1.EnableDeviceRequest
}

func (s *lifecycleServer) DisableDevice(_ context.Context, req *platformv1.DisableDeviceRequest) (*platformv1.DeviceLifecycleResponse, error) {
	s.disabled = req
	return &platformv1.DeviceLifecycleResponse{DeviceId: 42, State: "suspended"}, nil
}

func (s *lifecycleServer) EnableDevice(_ context.Context, req *platformv1.EnableDeviceRequest) (*platformv1.DeviceLifecycleResponse, error) {
	s.enabled = req
	return &platformv1.DeviceLifecycleResponse{DeviceId: 42, State: "quarantined"}, nil
}

func TestDispatch_DeviceLifecycle(t *testing.T) {
	server := &lifecycleServer{}
	handlers := buildHandlerMap(&ServiceRegistry{Device: server})

	disable, ok := handlers[platformv1.DeviceService_DisableDevice_FullMethodName]
	if !ok {
		t.Fatal("expected DisableDevice handler to be registered")
	}
	disableReq := &platformv1.DisableDeviceRequest{DeviceId: "42", Reason: "rma pending"}
	resp, err := disable(context.Background(), disableReq)
	if err != nil {
		t.Fatalf("DisableDevice: %v", err)
	}
	if server.disabled != disableReq {
		t.Errorf("DisableDevice received %v, want the dispatched request", server.disabled)
	}
	if got, isLifecycle := resp.(*platformv1.DeviceLifecycleResponse); !isLifecycle || got.GetState() != "suspended" {
		t.Errorf("response = %v, want the server's reply", resp)
	}

	enable, ok := handlers[platformv1.DeviceService_EnableDevice_FullMethodName]
	if !ok {
		t.Fatal("expected EnableDevice handler to be registered")
	}
	enableReq := &platformv1.EnableDeviceRequest{DeviceId: "42"}
	if _, err := enable(context.Background(), enableReq); err != nil {
		t.Fatalf("EnableDevice: %v", err)
	}
	if server.enabled != enableReq {
		t.Errorf("EnableDevice received %v, want the dispatched request", server.enabled)
	}
}

func TestDispatch_DeviceLifecycle_Unimplemented(t *testing.T) {
	handlers := buildHandlerMap(&ServiceRegistry{Device: &platformv1.UnimplementedDeviceServiceServer{}})

	_, err := handlers[platformv1.DeviceService_DisableDevice_FullMethodName](context.Background(), &platformv1.DisableDeviceRequest{DeviceId: "42"})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("DisableDevice err = %v, want the server's Unimplemented", err)
	}
	_, err = handlers[platformv1.DeviceService_EnableDevice_FullMethodName](context.Background(), &platformv1.EnableDeviceRequest{DeviceId: "42"})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("EnableDevice err = %v, want the server's Unimplemented", err)
	}
}
