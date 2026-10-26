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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newMigrationParityProvider is the daemon MCP provider over an orchestrator
// that can receive a migration.
func newMigrationParityProvider(recv *migrationReceiverOrchestrator) *MCPServiceProvider {
	return NewMCPServiceProvider(&MCPServiceProviderConfig{ComputeOrchestrator: recv})
}

// newParityReceiver answers every prepare with the same receiver, so two
// receivers give byte-identical replies.
func newParityReceiver() *migrationReceiverOrchestrator {
	return &migrationReceiverOrchestrator{
		grpcMockOrchestrator: newGRPCMockOrchestrator(),
		handle:               &compute.ReceiverHandle{ReceiverID: "recv-1", Port: 49200, TLSHostname: "dest.example"},
	}
}

// migrationParityCall is one destination-side migration verb as the MCP tool
// sees it and as gRPC does.
type migrationParityCall struct {
	tool string
	args map[string]interface{}
	grpc func(*ComputeGRPCService) (proto.Message, error)
}

var migrationParityCalls = []migrationParityCall{
	{
		tool: "vm_migration_prepare",
		args: map[string]interface{}{
			"vm_id": "vm-1", "vm_name": "guest", "mode": "live",
			"spec": map[string]interface{}{"memory_mb": float64(2048), "cpus": float64(2), "tpm_enabled": true},
		},
		grpc: func(s *ComputeGRPCService) (proto.Message, error) {
			return s.PrepareMigration(context.Background(), &platformv1.PrepareMigrationRequest{
				VmId: "vm-1", VmName: "guest", Mode: "live",
				Spec: &platformv1.VMMigrationSpec{MemoryMb: 2048, Cpus: 2, TpmEnabled: true},
			})
		},
	},
	{
		tool: "vm_migration_finalize",
		args: map[string]interface{}{"receiver_id": "recv-1", "commit": true},
		grpc: func(s *ComputeGRPCService) (proto.Message, error) {
			return s.FinalizeMigration(context.Background(), &platformv1.FinalizeMigrationRequest{ReceiverId: "recv-1", Commit: true})
		},
	},
}

// TestMigrationParity_Replies: each tool answers what its gRPC twin answers
// and hands the orchestrator the same request.
func TestMigrationParity_Replies(t *testing.T) {
	for _, call := range migrationParityCalls {
		t.Run(call.tool, func(t *testing.T) {
			mcpRecv, grpcRecv := newParityReceiver(), newParityReceiver()

			mcpResult, err := runVMTool(newMigrationParityProvider(mcpRecv), call.tool, call.args)
			require.NoError(t, err)
			grpcResp, err := call.grpc(newMigrationReceiverService(grpcRecv))
			require.NoError(t, err)

			want, err := protoResultJSON.Marshal(grpcResp)
			require.NoError(t, err)
			got, err := json.Marshal(mcpResult)
			require.NoError(t, err)
			assert.JSONEq(t, string(want), string(got))
			assert.Equal(t, grpcRecv.recordedSpec(), mcpRecv.recordedSpec())
			assert.Equal(t, grpcRecv.recordedReceiverID(), mcpRecv.recordedReceiverID())
			assert.Equal(t, grpcRecv.recordedCommit(), mcpRecv.recordedCommit())
		})
	}
}

// TestMigrationParity_ErrorClasses: a refused or failed migration call fails
// over MCP with the class gRPC answers.
func TestMigrationParity_ErrorClasses(t *testing.T) {
	tests := []struct {
		name string
		recv func() *migrationReceiverOrchestrator
		call migrationParityCall
		want codes.Code
	}{
		{
			name: "prepare without a spec",
			recv: newParityReceiver,
			call: migrationParityCall{
				tool: "vm_migration_prepare",
				args: map[string]interface{}{"vm_name": "guest"},
				grpc: func(s *ComputeGRPCService) (proto.Message, error) {
					return s.PrepareMigration(context.Background(), &platformv1.PrepareMigrationRequest{VmName: "guest"})
				},
			},
			want: codes.InvalidArgument,
		},
		{
			name: "finalize of an unknown receiver",
			recv: func() *migrationReceiverOrchestrator {
				recv := newParityReceiver()
				recv.finalizeErr = compute.ErrReceiverNotFound
				return recv
			},
			call: migrationParityCalls[1],
			want: codes.NotFound,
		},
		{
			name: "orchestrator that cannot receive",
			recv: nil,
			call: migrationParityCalls[0],
			want: codes.FailedPrecondition,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var provider *MCPServiceProvider
			var svc *ComputeGRPCService
			if tt.recv == nil {
				provider, svc, _ = newComputeParityPair()
			} else {
				provider, svc = newMigrationParityProvider(tt.recv()), newMigrationReceiverService(tt.recv())
			}

			_, mcpErr := runVMTool(provider, tt.call.tool, tt.call.args)
			_, grpcErr := tt.call.grpc(svc)
			assertSameClass(t, tt.want, mcpErr, grpcErr)
		})
	}
}
