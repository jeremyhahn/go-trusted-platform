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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestMigrationRoutes_ReachTheDocumentedPaths pins the destination half of
// a migration to the routes both REST servers mount: PrepareMigration posts
// its whole request, FinalizeMigration names the receiver in the path and
// keeps only commit in the body.
func TestMigrationRoutes_ReachTheDocumentedPaths(t *testing.T) {
	t.Run("PrepareMigration", func(t *testing.T) {
		a, seen := vmLifecycleServer(t, http.StatusOK,
			`{"success":true,"payload":{"status":{"success":true},"receiver_id":"recv-1","port":49152}}`)
		req := &platformv1.PrepareMigrationRequest{
			VmId: "vm-1", VmName: "web", Mode: "live",
			Spec: &platformv1.VMMigrationSpec{MemoryMb: 2048, Cpus: 2},
		}
		resp := &platformv1.PrepareMigrationResponse{}

		if err := a.Connection().Invoke(context.Background(), platformv1.ComputeService_PrepareMigration_FullMethodName, req, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if seen.method != http.MethodPost || seen.path != "/api/v1/compute/migrations/prepare" {
			t.Errorf("request = %s %s, want POST /api/v1/compute/migrations/prepare", seen.method, seen.path)
		}
		wantBody := map[string]interface{}{
			"vm_id": "vm-1", "vm_name": "web", "mode": "live",
			"spec": map[string]interface{}{"memory_mb": float64(2048), "cpus": float64(2)},
		}
		if !reflect.DeepEqual(seen.body, wantBody) {
			t.Errorf("body = %v, want %v", seen.body, wantBody)
		}
		if resp.GetReceiverId() != "recv-1" || resp.GetPort() != 49152 {
			t.Errorf("response = %v, want receiver recv-1 on port 49152", resp)
		}
	})

	t.Run("FinalizeMigration", func(t *testing.T) {
		a, seen := vmLifecycleServer(t, http.StatusOK, `{"success":true,"payload":{"status":{"success":true}}}`)
		req := &platformv1.FinalizeMigrationRequest{ReceiverId: "recv-1", Commit: true}

		if err := a.Connection().Invoke(context.Background(), platformv1.ComputeService_FinalizeMigration_FullMethodName, req, &platformv1.FinalizeMigrationResponse{}); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if seen.method != http.MethodPost || seen.path != "/api/v1/compute/migrations/recv-1/finalize" {
			t.Errorf("request = %s %s, want POST /api/v1/compute/migrations/recv-1/finalize", seen.method, seen.path)
		}
		wantBody := map[string]interface{}{"commit": true}
		if !reflect.DeepEqual(seen.body, wantBody) {
			t.Errorf("body = %v, want %v", seen.body, wantBody)
		}
	})
}

// TestMigrationRoutes_EmptyReceiverRejectedBeforeTheWire proves a finalize
// without a receiver id never becomes a request to /migrations//finalize.
func TestMigrationRoutes_EmptyReceiverRejectedBeforeTheWire(t *testing.T) {
	a, seen := vmLifecycleServer(t, http.StatusOK, `{"success":true,"payload":{}}`)

	err := a.Connection().Invoke(context.Background(), platformv1.ComputeService_FinalizeMigration_FullMethodName,
		&platformv1.FinalizeMigrationRequest{Commit: true}, &platformv1.FinalizeMigrationResponse{})

	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
	if seen.path != "" {
		t.Errorf("server saw %s; the request must not leave the client", seen.path)
	}
}
