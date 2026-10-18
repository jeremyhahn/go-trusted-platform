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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errSnapshotBackend stands in for a hypervisor failure the snapshot
// error mapping does not classify.
var errSnapshotBackend = errors.New("qemu monitor closed")

// quicVMSnapshotOps are the snapshot sub-opcodes, each with a valid
// request for vmID and the orchestrator field that makes it fail.
var quicVMSnapshotOps = []struct {
	name     string
	opcode   byte
	request  func(vmID string) any
	failWith func(orch *vmCapableMockOrchestrator, err error)
}{
	{
		name:   "create",
		opcode: quicwire.OpVMSnapshotCreate,
		request: func(vmID string) any {
			return &platformv1.CreateSnapshotRequest{VmId: vmID, Config: &platformv1.SnapshotConfig{Name: "nightly", MemorySnapshot: true, DiskSnapshot: true}}
		},
		failWith: func(orch *vmCapableMockOrchestrator, err error) { orch.createSnapshotErr = err },
	},
	{
		name:     "restore",
		opcode:   quicwire.OpVMSnapshotRestore,
		request:  func(vmID string) any { return &platformv1.RestoreSnapshotRequest{VmId: vmID, SnapshotId: "nightly"} },
		failWith: func(orch *vmCapableMockOrchestrator, err error) { orch.restoreErr = err },
	},
	{
		name:     "delete",
		opcode:   quicwire.OpVMSnapshotDelete,
		request:  func(vmID string) any { return &platformv1.DeleteSnapshotRequest{VmId: vmID, SnapshotId: "nightly"} },
		failWith: func(orch *vmCapableMockOrchestrator, err error) { orch.deleteErr = err },
	},
	{
		name:     "list",
		opcode:   quicwire.OpVMSnapshotList,
		request:  func(vmID string) any { return &platformv1.ListSnapshotsRequest{VmId: vmID} },
		failWith: func(orch *vmCapableMockOrchestrator, err error) { orch.listErr = err },
	},
}

// newQUICVMSnapshotHandler returns a QUIC handler whose compute service
// runs on an orchestrator that supports snapshots and attestation.
func newQUICVMSnapshotHandler() (*QUICServiceHandler, *vmCapableMockOrchestrator) {
	svc, orch := newVMCapableComputeService()
	h := &QUICServiceHandler{logger: logging.DefaultLogger()}
	h.SetComputeGRPCService(svc)
	return h, orch
}

func TestQUICVMSnapshot_CreateReturnsTheSnapshot(t *testing.T) {
	h, orch := newQUICVMSnapshotHandler()
	request := &platformv1.CreateSnapshotRequest{
		VmId:   "vm-1",
		Config: &platformv1.SnapshotConfig{Name: "nightly", Description: "before upgrade", MemorySnapshot: true, DiskSnapshot: true},
	}

	resp := sendVMLifecycle(t, h, quicwire.OpVMSnapshotCreate, encodeVMLifecycle(t, request))

	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var got platformv1.CreateSnapshotResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
	assert.Equal(t, "nightly", got.GetSnapshot().GetId())
	assert.Equal(t, "vm-1", got.GetSnapshot().GetVmId())
	assert.Equal(t, "before upgrade", got.GetSnapshot().GetConfig().GetDescription())
	require.Len(t, orch.snapshots, 1)
	assert.Equal(t, "vm-1", orch.snapshots[0].VMID)
}

func TestQUICVMSnapshot_ListReturnsTheSnapshots(t *testing.T) {
	h, orch := newQUICVMSnapshotHandler()
	orch.snapshots = []*compute.VMSnapshot{{Name: "first", VMID: "vm-1"}, {Name: "second", VMID: "vm-1"}}

	resp := sendVMLifecycle(t, h, quicwire.OpVMSnapshotList, encodeVMLifecycle(t, &platformv1.ListSnapshotsRequest{VmId: "vm-1"}))

	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var got platformv1.ListSnapshotsResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
	require.Len(t, got.GetSnapshots(), 2)
	assert.Equal(t, "second", got.GetSnapshots()[1].GetId())
}

func TestQUICVMSnapshot_RestoreAndDeleteSucceed(t *testing.T) {
	requests := map[byte]any{
		quicwire.OpVMSnapshotRestore: &platformv1.RestoreSnapshotRequest{VmId: "vm-1", SnapshotId: "nightly"},
		quicwire.OpVMSnapshotDelete:  &platformv1.DeleteSnapshotRequest{VmId: "vm-1", SnapshotId: "nightly"},
	}
	for opcode, request := range requests {
		h, _ := newQUICVMSnapshotHandler()

		resp := sendVMLifecycle(t, h, opcode, encodeVMLifecycle(t, request))

		assert.Equal(t, quicwire.StatusOK, resp.Status, "opcode 0x%02x: %s", opcode, resp.Payload)
	}
}

// TestQUICVMSnapshot_ErrorClasses checks each orchestrator refusal answers
// the QUIC status matching the gRPC code the shared service returns.
func TestQUICVMSnapshot_ErrorClasses(t *testing.T) {
	failures := []struct {
		name string
		err  error
		want byte
	}{
		{"unknown vm", compute.ErrInstanceNotFound, quicwire.StatusNotFound},
		{"unknown snapshot", compute.ErrSnapshotNotFound, quicwire.StatusNotFound},
		{"vm not running", compute.ErrInstanceNotRunning, quicwire.StatusFailedPrecondition},
		{"backend failure", errSnapshotBackend, quicwire.StatusInternalError},
	}
	for _, op := range quicVMSnapshotOps {
		for _, failure := range failures {
			t.Run(op.name+"/"+failure.name, func(t *testing.T) {
				h, orch := newQUICVMSnapshotHandler()
				op.failWith(orch, failure.err)

				resp := sendVMLifecycle(t, h, op.opcode, encodeVMLifecycle(t, op.request("vm-1")))

				assert.Equal(t, failure.want, resp.Status, string(resp.Payload))
			})
		}
	}
}

func TestQUICVMSnapshot_MissingVMIDIsInvalidArgument(t *testing.T) {
	for _, op := range quicVMSnapshotOps {
		t.Run(op.name, func(t *testing.T) {
			h, _ := newQUICVMSnapshotHandler()

			resp := sendVMLifecycle(t, h, op.opcode, encodeVMLifecycle(t, op.request("")))

			assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status, string(resp.Payload))
		})
	}
}

func TestQUICVMSnapshot_PartialSnapshotIsInvalidArgument(t *testing.T) {
	h, orch := newQUICVMSnapshotHandler()
	request := &platformv1.CreateSnapshotRequest{VmId: "vm-1", Config: &platformv1.SnapshotConfig{Name: "disk-only", DiskSnapshot: true}}

	resp := sendVMLifecycle(t, h, quicwire.OpVMSnapshotCreate, encodeVMLifecycle(t, request))

	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status, string(resp.Payload))
	assert.Empty(t, orch.snapshots, "a refused request must not reach the orchestrator")
}

func TestQUICVMSnapshot_MalformedPayloadIsInvalidRequest(t *testing.T) {
	for _, op := range quicVMSnapshotOps {
		t.Run(op.name, func(t *testing.T) {
			h, _ := newQUICVMSnapshotHandler()

			resp := sendVMLifecycle(t, h, op.opcode, []byte("invalid payload"))

			assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		})
	}
}

// TestQUICVMSnapshot_UnsupportedOrchestratorIsFailedPrecondition checks an
// orchestrator without snapshots answers FailedPrecondition, as on gRPC.
func TestQUICVMSnapshot_UnsupportedOrchestratorIsFailedPrecondition(t *testing.T) {
	for _, op := range quicVMSnapshotOps {
		t.Run(op.name, func(t *testing.T) {
			h, _ := newQUICVMLifecycleHandler(nil)

			resp := sendVMLifecycle(t, h, op.opcode, encodeVMLifecycle(t, op.request("vm-1")))

			assert.Equal(t, quicwire.StatusFailedPrecondition, resp.Status, string(resp.Payload))
		})
	}
}

func TestQUICVMSnapshot_NoComputeServiceIsUnavailable(t *testing.T) {
	for _, op := range quicVMSnapshotOps {
		t.Run(op.name, func(t *testing.T) {
			h := &QUICServiceHandler{logger: logging.DefaultLogger()}

			resp := sendVMLifecycle(t, h, op.opcode, encodeVMLifecycle(t, op.request("vm-1")))

			assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
		})
	}
}
