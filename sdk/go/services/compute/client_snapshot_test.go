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

// fakeSnapshotClient records the GetSnapshot request the client sends.
type fakeSnapshotClient struct {
	platformv1.ComputeServiceClient

	got *platformv1.GetSnapshotRequest
	err error
}

func (f *fakeSnapshotClient) GetSnapshot(ctx context.Context, in *platformv1.GetSnapshotRequest, opts ...grpc.CallOption) (*platformv1.GetSnapshotResponse, error) {
	f.got = in
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetSnapshotResponse{Snapshot: &platformv1.Snapshot{Id: in.GetSnapshotId(), VmId: in.GetVmId()}}, nil
}

func TestGetSnapshot_SendsIDsAndReturnsTheSnapshot(t *testing.T) {
	fake := &fakeSnapshotClient{}
	client := NewClientFromGRPC(fake)

	snapshot, err := client.GetSnapshot(context.Background(), "vm-1", "nightly")
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if fake.got.GetVmId() != "vm-1" || fake.got.GetSnapshotId() != "nightly" {
		t.Errorf("sent vm=%q snapshot=%q, want vm-1 and nightly", fake.got.GetVmId(), fake.got.GetSnapshotId())
	}
	if snapshot.GetId() != "nightly" || snapshot.GetVmId() != "vm-1" {
		t.Errorf("snapshot = %q of %q, want nightly of vm-1", snapshot.GetId(), snapshot.GetVmId())
	}
}

func TestGetSnapshot_RPCErrorIsTyped(t *testing.T) {
	rpcErr := status.Error(codes.NotFound, "snapshot not found")
	client := NewClientFromGRPC(&fakeSnapshotClient{err: rpcErr})

	_, err := client.GetSnapshot(context.Background(), "vm-1", "nightly")
	var getErr *ErrGetSnapshotFailed
	if !errors.As(err, &getErr) || getErr.VMID != "vm-1" || getErr.SnapshotID != "nightly" {
		t.Fatalf("GetSnapshot error = %v, want *ErrGetSnapshotFailed for vm-1/nightly", err)
	}
	if status.Code(errors.Unwrap(err)) != codes.NotFound {
		t.Errorf("GetSnapshot cause code = %v, want NotFound", status.Code(errors.Unwrap(err)))
	}
}
