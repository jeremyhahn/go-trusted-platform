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
	"google.golang.org/protobuf/proto"
)

// fakeMigrationClient records the destination-side migration requests the
// client sends.
type fakeMigrationClient struct {
	platformv1.ComputeServiceClient

	gotPrepare  *platformv1.PrepareMigrationRequest
	gotFinalize *platformv1.FinalizeMigrationRequest
	err         error
}

func (f *fakeMigrationClient) PrepareMigration(ctx context.Context, in *platformv1.PrepareMigrationRequest, opts ...grpc.CallOption) (*platformv1.PrepareMigrationResponse, error) {
	f.gotPrepare = in
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.PrepareMigrationResponse{ReceiverId: "recv-1", Port: 49152, TlsHostname: "dest.example"}, nil
}

func (f *fakeMigrationClient) FinalizeMigration(ctx context.Context, in *platformv1.FinalizeMigrationRequest, opts ...grpc.CallOption) (*platformv1.FinalizeMigrationResponse, error) {
	f.gotFinalize = in
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.FinalizeMigrationResponse{Status: &platformv1.Status{Success: true}}, nil
}

func TestPrepareMigration_SendsTheRequestAndReturnsTheReceiver(t *testing.T) {
	fake := &fakeMigrationClient{}
	req := &platformv1.PrepareMigrationRequest{
		VmId: "vm-1", VmName: "web", Mode: "live",
		Spec: &platformv1.VMMigrationSpec{MemoryMb: 2048, Cpus: 2, TpmEnabled: true},
	}

	resp, err := NewClientFromGRPC(fake).PrepareMigration(context.Background(), req)
	if err != nil {
		t.Fatalf("PrepareMigration: %v", err)
	}
	if !proto.Equal(fake.gotPrepare, req) {
		t.Errorf("sent %v, want %v", fake.gotPrepare, req)
	}
	if resp.GetReceiverId() != "recv-1" || resp.GetPort() != 49152 || resp.GetTlsHostname() != "dest.example" {
		t.Errorf("response = %v, want recv-1 on dest.example:49152", resp)
	}
}

func TestPrepareMigration_RPCErrorIsTyped(t *testing.T) {
	rpcErr := status.Error(codes.FailedPrecondition, "orchestrator cannot receive")
	client := NewClientFromGRPC(&fakeMigrationClient{err: rpcErr})

	_, err := client.PrepareMigration(context.Background(), &platformv1.PrepareMigrationRequest{VmName: "web"})
	var prepErr *ErrPrepareMigrationFailed
	if !errors.As(err, &prepErr) || prepErr.VMName != "web" {
		t.Fatalf("PrepareMigration error = %v, want *ErrPrepareMigrationFailed for web", err)
	}
	if status.Code(errors.Unwrap(err)) != codes.FailedPrecondition {
		t.Errorf("PrepareMigration cause code = %v, want FailedPrecondition", status.Code(errors.Unwrap(err)))
	}
}

func TestFinalizeMigration_SendsTheReceiverAndCommit(t *testing.T) {
	fake := &fakeMigrationClient{}

	if err := NewClientFromGRPC(fake).FinalizeMigration(context.Background(), "recv-1", true); err != nil {
		t.Fatalf("FinalizeMigration: %v", err)
	}
	if fake.gotFinalize.GetReceiverId() != "recv-1" || !fake.gotFinalize.GetCommit() {
		t.Errorf("sent receiver=%q commit=%v, want recv-1 and true", fake.gotFinalize.GetReceiverId(), fake.gotFinalize.GetCommit())
	}
}

func TestFinalizeMigration_RPCErrorIsTyped(t *testing.T) {
	rpcErr := status.Error(codes.NotFound, "migration receiver not found")
	client := NewClientFromGRPC(&fakeMigrationClient{err: rpcErr})

	err := client.FinalizeMigration(context.Background(), "nope", false)
	var finErr *ErrFinalizeMigrationFailed
	if !errors.As(err, &finErr) || finErr.ReceiverID != "nope" {
		t.Fatalf("FinalizeMigration error = %v, want *ErrFinalizeMigrationFailed for nope", err)
	}
	if status.Code(errors.Unwrap(err)) != codes.NotFound {
		t.Errorf("FinalizeMigration cause code = %v, want NotFound", status.Code(errors.Unwrap(err)))
	}
}
