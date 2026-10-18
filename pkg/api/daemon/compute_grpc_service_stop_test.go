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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// stopOptionsMockOrchestrator adds the VMStopper capability to
// grpcMockOrchestrator and records the options each stop carried.
type stopOptionsMockOrchestrator struct {
	*grpcMockOrchestrator

	opts []compute.StopOptions
}

var _ compute.VMStopper = (*stopOptionsMockOrchestrator)(nil)

func (m *stopOptionsMockOrchestrator) StopWithOptions(ctx context.Context, instanceID string, opts compute.StopOptions) error {
	m.opts = append(m.opts, opts)
	return nil
}

func newStopOptionsComputeService() (*ComputeGRPCService, *stopOptionsMockOrchestrator) {
	orchestrator := &stopOptionsMockOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator()}
	return NewComputeGRPCService(logging.DefaultLogger(), orchestrator), orchestrator
}

func TestComputeGRPCService_StopVM_OptionsReachOrchestrator(t *testing.T) {
	tests := []struct {
		name string
		req  *platformv1.StopVMRequest
		want compute.StopOptions
	}{
		{name: "default", req: &platformv1.StopVMRequest{Id: "vm-1"}, want: compute.StopOptions{}},
		{name: "force", req: &platformv1.StopVMRequest{Id: "vm-1", Force: true}, want: compute.StopOptions{Force: true}},
		{
			name: "timeout",
			req:  &platformv1.StopVMRequest{Id: "vm-1", TimeoutSeconds: 90},
			want: compute.StopOptions{Timeout: 90 * time.Second},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, orchestrator := newStopOptionsComputeService()

			resp, err := svc.StopVM(context.Background(), tt.req)
			require.NoError(t, err)
			assert.True(t, resp.GetStatus().GetSuccess())
			assert.Equal(t, []compute.StopOptions{tt.want}, orchestrator.opts)
		})
	}
}

func TestComputeGRPCService_StopVM_BadOptionsRefused(t *testing.T) {
	tests := []struct {
		name string
		req  *platformv1.StopVMRequest
	}{
		{name: "force with timeout", req: &platformv1.StopVMRequest{Id: "vm-1", Force: true, TimeoutSeconds: 10}},
		{name: "timeout over the maximum", req: &platformv1.StopVMRequest{Id: "vm-1", TimeoutSeconds: 3601}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, orchestrator := newStopOptionsComputeService()

			_, err := svc.StopVM(context.Background(), tt.req)
			assertStatusCode(t, err, codes.InvalidArgument)
			assert.Empty(t, orchestrator.opts, "a refused stop must not reach the orchestrator")
		})
	}
}

// An orchestrator that cannot honour stop options refuses them instead of
// taking a default stop the caller did not ask for.
func TestComputeGRPCService_StopVM_OptionsUnsupported(t *testing.T) {
	orchestrator := newGRPCMockOrchestrator()
	stopped := false
	orchestrator.stopFunc = func(ctx context.Context, instanceID string) error {
		stopped = true
		return nil
	}
	svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)

	_, err := svc.StopVM(context.Background(), &platformv1.StopVMRequest{Id: "vm-1", Force: true})
	assertStatusCode(t, err, codes.FailedPrecondition)
	assert.False(t, stopped)
}

func TestComputeGRPCService_RebootVM_ForceReachesOrchestrator(t *testing.T) {
	svc, orchestrator := newStopOptionsComputeService()
	started := ""
	orchestrator.startFunc = func(ctx context.Context, instanceID string) error {
		started = instanceID
		return nil
	}

	resp, err := svc.RebootVM(context.Background(), &platformv1.RebootVMRequest{Id: "vm-1", Force: true})
	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, []compute.StopOptions{{Force: true}}, orchestrator.opts)
	assert.Equal(t, "vm-1", started)
}

func TestComputeGRPCService_RebootVM_ForceUnsupported(t *testing.T) {
	orchestrator := newGRPCMockOrchestrator()
	started := false
	orchestrator.startFunc = func(ctx context.Context, instanceID string) error {
		started = true
		return nil
	}
	svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)

	_, err := svc.RebootVM(context.Background(), &platformv1.RebootVMRequest{Id: "vm-1", Force: true})
	assertStatusCode(t, err, codes.FailedPrecondition)
	assert.False(t, started, "a refused reboot must not start the instance")
}
