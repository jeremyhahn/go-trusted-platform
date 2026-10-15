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

package compute

import (
	"context"
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeVMVerbClient answers the reboot, suspend and resume RPCs with a
// status carrying message, or with err, and records each request.
type fakeVMVerbClient struct {
	platformv1.ComputeServiceClient

	message string
	err     error

	reboot  *platformv1.RebootVMRequest
	suspend *platformv1.SuspendVMRequest
	resume  *platformv1.ResumeVMRequest
}

func (f *fakeVMVerbClient) status() *platformv1.Status {
	return &platformv1.Status{Success: true, Message: f.message}
}

func (f *fakeVMVerbClient) RebootVM(_ context.Context, in *platformv1.RebootVMRequest, _ ...grpc.CallOption) (*platformv1.RebootVMResponse, error) {
	f.reboot = in
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.RebootVMResponse{Status: f.status()}, nil
}

func (f *fakeVMVerbClient) SuspendVM(_ context.Context, in *platformv1.SuspendVMRequest, _ ...grpc.CallOption) (*platformv1.SuspendVMResponse, error) {
	f.suspend = in
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.SuspendVMResponse{Status: f.status()}, nil
}

func (f *fakeVMVerbClient) ResumeVM(_ context.Context, in *platformv1.ResumeVMRequest, _ ...grpc.CallOption) (*platformv1.ResumeVMResponse, error) {
	f.resume = in
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.ResumeVMResponse{Status: f.status()}, nil
}

func TestVMVerbDomain_ReturnsTheServerStatus(t *testing.T) {
	fake := &fakeVMVerbClient{message: "done"}
	client := NewClientFromGRPC(fake)
	ctx := context.Background()

	calls := map[string]func() (*VMStatus, error){
		"reboot":  func() (*VMStatus, error) { return client.RebootVMDomain(ctx, "vm-1", true) },
		"suspend": func() (*VMStatus, error) { return client.SuspendVMDomain(ctx, "vm-2") },
		"resume":  func() (*VMStatus, error) { return client.ResumeVMDomain(ctx, "vm-3") },
	}
	for name, call := range calls {
		got, err := call()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == nil || !got.Success || got.Message != "done" {
			t.Errorf("%s status = %+v, want success with message done", name, got)
		}
	}
	if fake.reboot.GetId() != "vm-1" || !fake.reboot.GetForce() {
		t.Errorf("reboot request = %v, want id vm-1 with force", fake.reboot)
	}
	if fake.suspend.GetId() != "vm-2" || fake.resume.GetId() != "vm-3" {
		t.Errorf("sent ids suspend=%q resume=%q, want vm-2 and vm-3", fake.suspend.GetId(), fake.resume.GetId())
	}
}

func TestVMVerbDomain_RPCErrorIsTyped(t *testing.T) {
	rpcErr := status.Error(codes.NotFound, "vm not found")
	client := NewClientFromGRPC(&fakeVMVerbClient{err: rpcErr})
	ctx := context.Background()

	tests := []struct {
		name  string
		call  func() (*VMStatus, error)
		typed func(error) bool
	}{
		{"reboot", func() (*VMStatus, error) { return client.RebootVMDomain(ctx, "vm-1", false) },
			func(err error) bool { var e *ErrRebootVMFailed; return errors.As(err, &e) && e.ID == "vm-1" }},
		{"suspend", func() (*VMStatus, error) { return client.SuspendVMDomain(ctx, "vm-1") },
			func(err error) bool { var e *ErrSuspendVMFailed; return errors.As(err, &e) && e.ID == "vm-1" }},
		{"resume", func() (*VMStatus, error) { return client.ResumeVMDomain(ctx, "vm-1") },
			func(err error) bool { var e *ErrResumeVMFailed; return errors.As(err, &e) && e.ID == "vm-1" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.call()
			if got != nil {
				t.Errorf("status = %+v, want nil on error", got)
			}
			if !tt.typed(err) {
				t.Fatalf("err = %T %v, want the typed %s error for vm-1", err, err, tt.name)
			}
			if !errors.Is(err, rpcErr) {
				t.Errorf("err does not unwrap to the RPC error: %v", err)
			}
		})
	}
}
