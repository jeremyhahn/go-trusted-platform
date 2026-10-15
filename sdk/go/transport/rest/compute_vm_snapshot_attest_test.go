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

package rest

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestVMSnapshotAttestRoutes_IDsTravelInThePath pins the snapshot and
// attestation routes to the REST servers' paths and verbs: the VM id (and
// the snapshot id) ride the path and never the body.
func TestVMSnapshotAttestRoutes_IDsTravelInThePath(t *testing.T) {
	tests := []struct {
		grpcMethod string
		req        proto.Message
		resp       proto.Message
		httpMethod string
		path       string
		body       map[string]interface{}
	}{
		{platformv1.ComputeService_CreateSnapshot_FullMethodName,
			&platformv1.CreateSnapshotRequest{VmId: "vm-1", Config: &platformv1.SnapshotConfig{Name: "nightly", DiskSnapshot: true}},
			&platformv1.CreateSnapshotResponse{},
			http.MethodPost, "/api/v1/compute/vms/vm-1/snapshots",
			map[string]interface{}{"config": map[string]interface{}{"name": "nightly", "disk_snapshot": true}}},
		{platformv1.ComputeService_ListSnapshots_FullMethodName,
			&platformv1.ListSnapshotsRequest{VmId: "vm-1"}, &platformv1.ListSnapshotsResponse{},
			http.MethodGet, "/api/v1/compute/vms/vm-1/snapshots", nil},
		{platformv1.ComputeService_DeleteSnapshot_FullMethodName,
			&platformv1.DeleteSnapshotRequest{VmId: "vm-1", SnapshotId: "snap-1"}, &platformv1.DeleteSnapshotResponse{},
			http.MethodDelete, "/api/v1/compute/vms/vm-1/snapshots/snap-1", nil},
		{platformv1.ComputeService_RestoreSnapshot_FullMethodName,
			&platformv1.RestoreSnapshotRequest{VmId: "vm-1", SnapshotId: "snap-1"}, &platformv1.RestoreSnapshotResponse{},
			http.MethodPost, "/api/v1/compute/vms/vm-1/snapshots/snap-1/restore", map[string]interface{}{}},
		{platformv1.ComputeService_AttestVM_FullMethodName,
			&platformv1.AttestVMRequest{VmId: "vm-1", Nonce: []byte("nonce"), PcrIndices: []uint32{0, 7}},
			&platformv1.AttestVMResponse{},
			http.MethodPost, "/api/v1/compute/vms/vm-1/attest",
			map[string]interface{}{"nonce": "bm9uY2U=", "pcr_indices": []interface{}{float64(0), float64(7)}}},
		{platformv1.ComputeService_VerifyVMAttestation_FullMethodName,
			&platformv1.VerifyVMAttestationRequest{VmId: "vm-1", Quote: []byte("q"), Signature: []byte("s")},
			&platformv1.VerifyVMAttestationResponse{},
			http.MethodPost, "/api/v1/compute/vms/vm-1/attest/verify",
			map[string]interface{}{"quote": "cQ==", "signature": "cw=="}},
	}
	for _, tt := range tests {
		t.Run(tt.grpcMethod, func(t *testing.T) {
			a, seen := vmLifecycleServer(t, http.StatusOK, `{"success":true,"payload":{"status":{"success":true}}}`)
			if err := a.Connection().Invoke(context.Background(), tt.grpcMethod, tt.req, tt.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if seen.method != tt.httpMethod || seen.path != tt.path {
				t.Errorf("request = %s %s, want %s %s", seen.method, seen.path, tt.httpMethod, tt.path)
			}
			if seen.query != "" {
				t.Errorf("query = %q, want none", seen.query)
			}
			if tt.body != nil && !reflect.DeepEqual(seen.body, tt.body) {
				t.Errorf("body = %v, want %v", seen.body, tt.body)
			}
			for _, field := range []string{"vm_id", "snapshot_id"} {
				if _, has := seen.body[field]; has {
					t.Errorf("body still carries %s: %v", field, seen.body)
				}
			}
		})
	}
}

// TestVMSnapshotAttestRoutes_EmptyIDRejectedBeforeTheWire: a missing VM or
// snapshot id is InvalidArgument at the client, never a shorter path that
// would route to another handler.
func TestVMSnapshotAttestRoutes_EmptyIDRejectedBeforeTheWire(t *testing.T) {
	tests := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
	}{
		{"snapshot list without VM id", platformv1.ComputeService_ListSnapshots_FullMethodName,
			&platformv1.ListSnapshotsRequest{}, &platformv1.ListSnapshotsResponse{}},
		{"snapshot delete without snapshot id", platformv1.ComputeService_DeleteSnapshot_FullMethodName,
			&platformv1.DeleteSnapshotRequest{VmId: "vm-1"}, &platformv1.DeleteSnapshotResponse{}},
		{"attest without VM id", platformv1.ComputeService_AttestVM_FullMethodName,
			&platformv1.AttestVMRequest{Nonce: []byte("n")}, &platformv1.AttestVMResponse{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, seen := vmLifecycleServer(t, http.StatusOK, `{"success":true,"payload":{}}`)
			err := a.Connection().Invoke(context.Background(), tt.grpcMethod, tt.req, tt.resp)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if seen.path != "" {
				t.Errorf("server saw %s; the request must not leave the client", seen.path)
			}
		})
	}
}
