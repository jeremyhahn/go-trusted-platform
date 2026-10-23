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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// newQUICMigrationHandler serves the destination half of a migration over
// QUIC against an orchestrator that can receive one.
func newQUICMigrationHandler(recv *migrationReceiverOrchestrator) *QUICServiceHandler {
	h := &QUICServiceHandler{logger: logging.DefaultLogger()}
	h.SetComputeGRPCService(newMigrationReceiverService(recv))
	return h
}

func TestQUICVMMigration_PrepareReturnsTheReceiver(t *testing.T) {
	recv := &migrationReceiverOrchestrator{
		grpcMockOrchestrator: newGRPCMockOrchestrator(),
		handle:               &compute.ReceiverHandle{ReceiverID: "recv-1", Port: 49200, TLSHostname: "dest.example"},
	}
	h := newQUICMigrationHandler(recv)

	resp := sendVMLifecycle(t, h, quicwire.OpVMPrepareMigration, encodeVMLifecycle(t, &platformv1.PrepareMigrationRequest{
		VmName: "guest", Mode: "live",
		Spec: &platformv1.VMMigrationSpec{MemoryMb: 2048, Cpus: 2},
	}))

	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var got platformv1.PrepareMigrationResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
	assert.Equal(t, "recv-1", got.GetReceiverId())
	assert.Equal(t, int32(49200), got.GetPort())
	assert.Equal(t, "dest.example", got.GetTlsHostname())
	assert.Equal(t, "guest", recv.gotSpec.VMName)
}

func TestQUICVMMigration_FinalizeCommitsTheReceiver(t *testing.T) {
	recv := &migrationReceiverOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator()}
	h := newQUICMigrationHandler(recv)

	resp := sendVMLifecycle(t, h, quicwire.OpVMFinalizeMigration,
		encodeVMLifecycle(t, &platformv1.FinalizeMigrationRequest{ReceiverId: "recv-1", Commit: true}))

	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	assert.Equal(t, "recv-1", recv.lastReceiverID)
	assert.True(t, recv.lastCommit)
}

// TestQUICVMMigration_ErrorClasses proves the daemon's gRPC status reaches
// the QUIC caller as the matching wire status, not a blanket internal error.
func TestQUICVMMigration_ErrorClasses(t *testing.T) {
	tests := []struct {
		name   string
		recv   *migrationReceiverOrchestrator
		opcode byte
		req    any
		want   byte
	}{
		{
			name:   "prepare without a spec is invalid",
			recv:   &migrationReceiverOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator()},
			opcode: quicwire.OpVMPrepareMigration,
			req:    &platformv1.PrepareMigrationRequest{VmName: "guest"},
			want:   quicwire.StatusInvalidArgument,
		},
		{
			name:   "finalize without a receiver id is invalid",
			recv:   &migrationReceiverOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator()},
			opcode: quicwire.OpVMFinalizeMigration,
			req:    &platformv1.FinalizeMigrationRequest{Commit: true},
			want:   quicwire.StatusInvalidArgument,
		},
		{
			name: "finalize of an unknown receiver is not found",
			recv: &migrationReceiverOrchestrator{
				grpcMockOrchestrator: newGRPCMockOrchestrator(),
				finalizeErr:          compute.ErrReceiverNotFound,
			},
			opcode: quicwire.OpVMFinalizeMigration,
			req:    &platformv1.FinalizeMigrationRequest{ReceiverId: "nope"},
			want:   quicwire.StatusNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sendVMLifecycle(t, newQUICMigrationHandler(tt.recv), tt.opcode, encodeVMLifecycle(t, tt.req))

			assert.Equal(t, tt.want, resp.Status, string(resp.Payload))
		})
	}
}

// TestQUICVMMigration_UnsupportedOrchestratorIsFailedPrecondition covers an
// orchestrator that cannot receive a migration: the caller is told the
// request cannot be served here (StatusInvalidRequest is FailedPrecondition).
func TestQUICVMMigration_UnsupportedOrchestratorIsFailedPrecondition(t *testing.T) {
	h, _ := newQUICVMSnapshotHandler()

	resp := sendVMLifecycle(t, h, quicwire.OpVMPrepareMigration, encodeVMLifecycle(t, &platformv1.PrepareMigrationRequest{
		VmName: "guest", Spec: &platformv1.VMMigrationSpec{MemoryMb: 512, Cpus: 1},
	}))

	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status, string(resp.Payload))
}
