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
