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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// suspendMockOrchestrator adds the suspend capability to grpcMockOrchestrator
// and records the instance each call names.
type suspendMockOrchestrator struct {
	*grpcMockOrchestrator

	err       error
	suspended string
	resumed   string
}

var _ compute.VMSuspender = (*suspendMockOrchestrator)(nil)

func (m *suspendMockOrchestrator) Suspend(ctx context.Context, instanceID string) error {
	m.suspended = instanceID
	return m.err
}

func (m *suspendMockOrchestrator) Resume(ctx context.Context, instanceID string) error {
	m.resumed = instanceID
	return m.err
}

func newSuspendComputeService(err error) (*ComputeGRPCService, *suspendMockOrchestrator) {
	orchestrator := &suspendMockOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator(), err: err}
	return NewComputeGRPCService(logging.DefaultLogger(), orchestrator), orchestrator
}

// suspendCalls drives SuspendVM and ResumeVM through one signature.
var suspendCalls = map[string]func(svc *ComputeGRPCService, id string) (*platformv1.Status, error){
	"SuspendVM": func(svc *ComputeGRPCService, id string) (*platformv1.Status, error) {
		resp, err := svc.SuspendVM(context.Background(), &platformv1.SuspendVMRequest{Id: id})
		return resp.GetStatus(), err
	},
	"ResumeVM": func(svc *ComputeGRPCService, id string) (*platformv1.Status, error) {
		resp, err := svc.ResumeVM(context.Background(), &platformv1.ResumeVMRequest{Id: id})
		return resp.GetStatus(), err
	},
}

func TestComputeGRPCService_SuspendResumeVM_Success(t *testing.T) {
	svc, orchestrator := newSuspendComputeService(nil)

	st, err := suspendCalls["SuspendVM"](svc, "vm-1")
	require.NoError(t, err)
	assert.True(t, st.GetSuccess())
	assert.Equal(t, "vm-1", orchestrator.suspended)

	st, err = suspendCalls["ResumeVM"](svc, "vm-2")
	require.NoError(t, err)
	assert.True(t, st.GetSuccess())
	assert.Equal(t, "vm-2", orchestrator.resumed)
}

func TestComputeGRPCService_SuspendResumeVM_Errors(t *testing.T) {
	wrongState := &compute.SentinelCauseError{
		Sentinel: compute.ErrInstanceNotRunning,
		Cause:    &compute.MessageError{Msg: "cannot suspend instance in state stopped"},
	}
	tests := []struct {
		name string
		svc  func() *ComputeGRPCService
		id   string
		want codes.Code
	}{
		{
			name: "no orchestrator",
			svc:  func() *ComputeGRPCService { return NewComputeGRPCService(logging.DefaultLogger(), nil) },
			id:   "vm-1",
			want: codes.FailedPrecondition,
		},
		{
			name: "orchestrator cannot suspend",
			svc: func() *ComputeGRPCService {
				return NewComputeGRPCService(logging.DefaultLogger(), newGRPCMockOrchestrator())
			},
			id:   "vm-1",
			want: codes.FailedPrecondition,
		},
		{
			name: "missing id",
			svc:  func() *ComputeGRPCService { svc, _ := newSuspendComputeService(nil); return svc },
			id:   "",
			want: codes.InvalidArgument,
		},
		{
			name: "unknown VM",
			svc: func() *ComputeGRPCService {
				svc, _ := newSuspendComputeService(compute.ErrInstanceNotFound)
				return svc
			},
			id:   "missing",
			want: codes.NotFound,
		},
		{
			name: "wrong state",
			svc:  func() *ComputeGRPCService { svc, _ := newSuspendComputeService(wrongState); return svc },
			id:   "vm-1",
			want: codes.FailedPrecondition,
		},
		{
			name: "QMP failure",
			svc: func() *ComputeGRPCService {
				svc, _ := newSuspendComputeService(&compute.WrappedError{Msg: "failed to suspend VM", Err: &compute.MessageError{Msg: "QMP stop failed"}})
				return svc
			},
			id:   "vm-1",
			want: codes.Internal,
		},
	}

	for _, tt := range tests {
		for method, call := range suspendCalls {
			t.Run(tt.name+"/"+method, func(t *testing.T) {
				st, err := call(tt.svc(), tt.id)
				assert.Nil(t, st)
				assertStatusCode(t, err, tt.want)
			})
		}
	}
}

// A suspended VM must be resumed or stopped, not started; Start's
// ErrInvalidState is a FailedPrecondition like the other wrong-state errors.
func TestComputeGRPCService_StartVM_InvalidStateIsFailedPrecondition(t *testing.T) {
	svc, orchestrator := newSuspendComputeService(nil)
	orchestrator.startFunc = func(ctx context.Context, instanceID string) error {
		return compute.ErrInvalidState
	}

	_, err := svc.StartVM(context.Background(), &platformv1.StartVMRequest{Id: "vm-1"})
	assertStatusCode(t, err, codes.FailedPrecondition)
}

func TestComputeGRPCService_SuspendedStateIsPaused(t *testing.T) {
	svc, _ := newSuspendComputeService(nil)
	assert.Equal(t, platformv1.VMState_VM_STATE_PAUSED, svc.instanceStateToVMState(compute.StateSuspended))
}
