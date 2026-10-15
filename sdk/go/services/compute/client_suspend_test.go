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

// fakeSuspendClient records the suspend and resume RPCs the client sends.
type fakeSuspendClient struct {
	platformv1.ComputeServiceClient

	suspendID string
	resumeID  string
	err       error
}

func (f *fakeSuspendClient) SuspendVM(ctx context.Context, in *platformv1.SuspendVMRequest, opts ...grpc.CallOption) (*platformv1.SuspendVMResponse, error) {
	f.suspendID = in.GetId()
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.SuspendVMResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (f *fakeSuspendClient) ResumeVM(ctx context.Context, in *platformv1.ResumeVMRequest, opts ...grpc.CallOption) (*platformv1.ResumeVMResponse, error) {
	f.resumeID = in.GetId()
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.ResumeVMResponse{Status: &platformv1.Status{Success: true}}, nil
}

func TestSuspendResumeVM_SendsID(t *testing.T) {
	fake := &fakeSuspendClient{}
	client := NewClientFromGRPC(fake)

	if err := client.SuspendVM(context.Background(), "vm-1"); err != nil {
		t.Fatalf("SuspendVM: %v", err)
	}
	if err := client.ResumeVM(context.Background(), "vm-2"); err != nil {
		t.Fatalf("ResumeVM: %v", err)
	}
	if fake.suspendID != "vm-1" || fake.resumeID != "vm-2" {
		t.Errorf("sent ids suspend=%q resume=%q, want vm-1 and vm-2", fake.suspendID, fake.resumeID)
	}
}

func TestSuspendResumeVM_RPCErrorIsTyped(t *testing.T) {
	rpcErr := status.Error(codes.FailedPrecondition, "instance is not running")
	client := NewClientFromGRPC(&fakeSuspendClient{err: rpcErr})

	err := client.SuspendVM(context.Background(), "vm-1")
	var suspendErr *ErrSuspendVMFailed
	if !errors.As(err, &suspendErr) || suspendErr.ID != "vm-1" {
		t.Fatalf("SuspendVM error = %v, want *ErrSuspendVMFailed for vm-1", err)
	}
	if status.Code(errors.Unwrap(err)) != codes.FailedPrecondition {
		t.Errorf("SuspendVM cause code = %v, want FailedPrecondition", status.Code(errors.Unwrap(err)))
	}

	err = client.ResumeVM(context.Background(), "vm-1")
	var resumeErr *ErrResumeVMFailed
	if !errors.As(err, &resumeErr) || resumeErr.ID != "vm-1" {
		t.Fatalf("ResumeVM error = %v, want *ErrResumeVMFailed for vm-1", err)
	}
	if !errors.Is(err, rpcErr) {
		t.Errorf("ResumeVM error does not unwrap to the RPC error: %v", err)
	}
}
