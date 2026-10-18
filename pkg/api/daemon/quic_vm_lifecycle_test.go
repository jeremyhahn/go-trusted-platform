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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lifecycleRecorder records the orchestrator calls the QUIC lifecycle
// sub-opcodes make and answers every call with err.
type lifecycleRecorder struct {
	*grpcMockOrchestrator

	calls []string
	err   error
}

var _ compute.VMSuspender = (*lifecycleRecorder)(nil)

func (r *lifecycleRecorder) Start(ctx context.Context, instanceID string) error {
	r.calls = append(r.calls, "start "+instanceID)
	return r.err
}

func (r *lifecycleRecorder) Stop(ctx context.Context, instanceID string) error {
	r.calls = append(r.calls, "stop "+instanceID)
	return r.err
}

func (r *lifecycleRecorder) Delete(ctx context.Context, instanceID string) error {
	r.calls = append(r.calls, "delete "+instanceID)
	return r.err
}

func (r *lifecycleRecorder) Suspend(ctx context.Context, instanceID string) error {
	r.calls = append(r.calls, "suspend "+instanceID)
	return r.err
}

func (r *lifecycleRecorder) Resume(ctx context.Context, instanceID string) error {
	r.calls = append(r.calls, "resume "+instanceID)
	return r.err
}

// vmStatusResponse is the pb response every lifecycle verb answers with.
type vmStatusResponse interface {
	GetStatus() *platformv1.Status
}

// quicVMLifecycleOps are the lifecycle sub-opcodes the daemon carries under
// OpVMExtendedCategory, each with its pb request and the calls it makes.
var quicVMLifecycleOps = []struct {
	name     string
	opcode   byte
	request  func(id string) any
	response func() vmStatusResponse
	calls    []string
}{
	{
		name:     "start",
		opcode:   quicwire.OpVMStart,
		request:  func(id string) any { return &platformv1.StartVMRequest{Id: id} },
		response: func() vmStatusResponse { return &platformv1.StartVMResponse{} },
		calls:    []string{"start vm-1"},
	},
	{
		name:     "stop",
		opcode:   quicwire.OpVMStop,
		request:  func(id string) any { return &platformv1.StopVMRequest{Id: id} },
		response: func() vmStatusResponse { return &platformv1.StopVMResponse{} },
		calls:    []string{"stop vm-1"},
	},
	{
		name:     "delete",
		opcode:   quicwire.OpVMDelete,
		request:  func(id string) any { return &platformv1.DeleteVMRequest{Id: id} },
		response: func() vmStatusResponse { return &platformv1.DeleteVMResponse{} },
		calls:    []string{"delete vm-1"},
	},
	{
		name:     "restart",
		opcode:   quicwire.OpVMRestart,
		request:  func(id string) any { return &platformv1.RebootVMRequest{Id: id} },
		response: func() vmStatusResponse { return &platformv1.RebootVMResponse{} },
		calls:    []string{"stop vm-1", "start vm-1"},
	},
	{
		name:     "suspend",
		opcode:   quicwire.OpVMSuspend,
		request:  func(id string) any { return &platformv1.SuspendVMRequest{Id: id} },
		response: func() vmStatusResponse { return &platformv1.SuspendVMResponse{} },
		calls:    []string{"suspend vm-1"},
	},
	{
		name:     "resume",
		opcode:   quicwire.OpVMResume,
		request:  func(id string) any { return &platformv1.ResumeVMRequest{Id: id} },
		response: func() vmStatusResponse { return &platformv1.ResumeVMResponse{} },
		calls:    []string{"resume vm-1"},
	},
}

// newQUICVMLifecycleHandler returns a QUIC handler whose compute service runs
// on a lifecycleRecorder answering err.
func newQUICVMLifecycleHandler(err error) (*QUICServiceHandler, *lifecycleRecorder) {
	recorder := &lifecycleRecorder{grpcMockOrchestrator: newGRPCMockOrchestrator(), err: err}
	h := &QUICServiceHandler{logger: logging.DefaultLogger()}
	h.SetComputeGRPCService(NewComputeGRPCService(logging.DefaultLogger(), recorder))
	return h, recorder
}

// sendVMLifecycle sends body under OpVMExtendedCategory with opcode as the
// sub-opcode, as the remote transports do.
func sendVMLifecycle(t *testing.T, h *QUICServiceHandler, opcode byte, body []byte) *quicwire.Response {
	t.Helper()
	resp := h.handleVMServiceOperation(context.Background(), &quicwire.Request{
		Opcode:  quicwire.OpVMExtendedCategory,
		Payload: append([]byte{opcode}, body...),
	})
	require.NotNil(t, resp)
	return resp
}

func encodeVMLifecycle(t *testing.T, request any) []byte {
	t.Helper()
	body, err := quicwire.EncodePayload(request)
	require.NoError(t, err)
	return body
}

func TestQUICVMLifecycle_ReachesComputeService(t *testing.T) {
	for _, op := range quicVMLifecycleOps {
		t.Run(op.name, func(t *testing.T) {
			h, recorder := newQUICVMLifecycleHandler(nil)

			resp := sendVMLifecycle(t, h, op.opcode, encodeVMLifecycle(t, op.request("vm-1")))

			require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
			decoded := op.response()
			require.NoError(t, quicwire.DecodePayload(resp.Payload, decoded))
			assert.True(t, decoded.GetStatus().GetSuccess())
			assert.Equal(t, op.calls, recorder.calls)
		})
	}
}

func TestQUICVMLifecycle_ErrorClasses(t *testing.T) {
	wrongState := &compute.SentinelCauseError{
		Sentinel: compute.ErrInstanceNotRunning,
		Cause:    &compute.MessageError{Msg: "instance is stopped"},
	}
	tests := []struct {
		name string
		err  error
		id   string
		want byte
	}{
		{name: "missing id", id: "", want: quicwire.StatusInvalidArgument},
		{name: "unknown VM", err: compute.ErrInstanceNotFound, id: "missing", want: quicwire.StatusNotFound},
		{name: "wrong state", err: wrongState, id: "vm-1", want: quicwire.StatusFailedPrecondition},
		{name: "not suspended", err: compute.ErrInstanceNotSuspended, id: "vm-1", want: quicwire.StatusFailedPrecondition},
	}

	for _, tt := range tests {
		for _, op := range quicVMLifecycleOps {
			t.Run(tt.name+"/"+op.name, func(t *testing.T) {
				h, _ := newQUICVMLifecycleHandler(tt.err)

				resp := sendVMLifecycle(t, h, op.opcode, encodeVMLifecycle(t, op.request(tt.id)))

				assert.Equal(t, tt.want, resp.Status, string(resp.Payload))
			})
		}
	}
}

func TestQUICVMLifecycle_MalformedPayloadIsInvalidRequest(t *testing.T) {
	for _, op := range quicVMLifecycleOps {
		t.Run(op.name, func(t *testing.T) {
			h, recorder := newQUICVMLifecycleHandler(nil)

			resp := sendVMLifecycle(t, h, op.opcode, []byte("invalid payload"))

			assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status, string(resp.Payload))
			assert.Contains(t, string(resp.Payload), "decoding failed")
			assert.Empty(t, recorder.calls)
		})
	}
}

func TestQUICVMLifecycle_NoComputeServiceIsUnavailable(t *testing.T) {
	for _, op := range quicVMLifecycleOps {
		t.Run(op.name, func(t *testing.T) {
			h := &QUICServiceHandler{logger: logging.DefaultLogger()}

			resp := sendVMLifecycle(t, h, op.opcode, encodeVMLifecycle(t, op.request("vm-1")))

			assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
		})
	}
}

func TestQUICVMCreate_ReturnsTheNewVM(t *testing.T) {
	h, _ := newQUICVMLifecycleHandler(nil)
	req := &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{Name: "web"}}

	resp := sendVMLifecycle(t, h, quicwire.OpVMCreate, encodeVMLifecycle(t, req))

	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var created platformv1.CreateVMResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &created))
	assert.True(t, created.GetStatus().GetSuccess())
	assert.Equal(t, "web-instance", created.GetVm().GetId())
}

func TestQUICVMCreate_MissingConfigIsInvalidArgument(t *testing.T) {
	h, _ := newQUICVMLifecycleHandler(nil)

	resp := sendVMLifecycle(t, h, quicwire.OpVMCreate, encodeVMLifecycle(t, &platformv1.CreateVMRequest{}))

	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status, string(resp.Payload))
}

func TestQUICVMGet_ReturnsTheVM(t *testing.T) {
	h, _ := newQUICVMLifecycleHandler(nil)
	create := &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{Name: "web"}}
	require.Equal(t, quicwire.StatusOK, sendVMLifecycle(t, h, quicwire.OpVMCreate, encodeVMLifecycle(t, create)).Status)

	resp := sendVMLifecycle(t, h, quicwire.OpVMGet, encodeVMLifecycle(t, &platformv1.GetVMRequest{Id: "web-instance"}))

	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var got platformv1.GetVMResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
	assert.Equal(t, "web-instance", got.GetVm().GetId())
}

func TestQUICVMGet_UnknownVMIsNotFound(t *testing.T) {
	h, _ := newQUICVMLifecycleHandler(nil)

	resp := sendVMLifecycle(t, h, quicwire.OpVMGet, encodeVMLifecycle(t, &platformv1.GetVMRequest{Id: "missing"}))

	assert.Equal(t, quicwire.StatusNotFound, resp.Status, string(resp.Payload))
}

func TestQUICVMList_ReturnsTheVMs(t *testing.T) {
	h, _ := newQUICVMLifecycleHandler(nil)
	for _, name := range []string{"web", "db"} {
		create := &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{Name: name}}
		require.Equal(t, quicwire.StatusOK, sendVMLifecycle(t, h, quicwire.OpVMCreate, encodeVMLifecycle(t, create)).Status)
	}

	resp := sendVMLifecycle(t, h, quicwire.OpVMList, encodeVMLifecycle(t, &platformv1.ListVMsRequest{}))

	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var listed platformv1.ListVMsResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &listed))
	ids := make([]string, 0, len(listed.GetVms()))
	for _, vm := range listed.GetVms() {
		ids = append(ids, vm.GetId())
	}
	assert.ElementsMatch(t, []string{"web-instance", "db-instance"}, ids)
}

func TestQUICVMList_OrchestratorFailureIsInternal(t *testing.T) {
	h, recorder := newQUICVMLifecycleHandler(nil)
	recorder.listFunc = func(context.Context, *compute.InstanceFilter) ([]*compute.Instance, error) {
		return nil, &compute.MessageError{Msg: "store offline"}
	}

	resp := sendVMLifecycle(t, h, quicwire.OpVMList, encodeVMLifecycle(t, &platformv1.ListVMsRequest{}))

	assert.Equal(t, quicwire.StatusInternalError, resp.Status, string(resp.Payload))
}

func TestQUICVMReads_MalformedPayloadIsInvalidRequest(t *testing.T) {
	for _, opcode := range []byte{quicwire.OpVMCreate, quicwire.OpVMGet, quicwire.OpVMList} {
		h, _ := newQUICVMLifecycleHandler(nil)

		resp := sendVMLifecycle(t, h, opcode, []byte("invalid payload"))

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status, "opcode 0x%02x", opcode)
	}
}
