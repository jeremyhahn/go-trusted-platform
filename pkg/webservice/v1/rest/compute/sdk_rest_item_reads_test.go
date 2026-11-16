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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// itemReadsComputeServer records the GetVM, GetVMMetrics,
// GetContainerMetrics and ExecContainer requests that reach it. It knows
// one VM, "vm-1", and one container, "c1"; any other id is NotFound.
type itemReadsComputeServer struct {
	platformv1.UnimplementedComputeServiceServer

	mu               sync.Mutex
	getVM            *platformv1.GetVMRequest
	vmMetrics        *platformv1.GetVMMetricsRequest
	containerMetrics *platformv1.GetContainerMetricsRequest
	exec             *platformv1.ExecContainerRequest
}

func (s *itemReadsComputeServer) GetVM(_ context.Context, req *platformv1.GetVMRequest) (*platformv1.GetVMResponse, error) {
	s.mu.Lock()
	s.getVM = req
	s.mu.Unlock()
	if req.GetId() != "vm-1" {
		return nil, status.Error(codes.NotFound, "vm not found")
	}
	return &platformv1.GetVMResponse{Vm: &platformv1.VM{Id: "vm-1", Config: &platformv1.VMConfig{Name: "web"}}}, nil
}

func (s *itemReadsComputeServer) GetVMMetrics(_ context.Context, req *platformv1.GetVMMetricsRequest) (*platformv1.VMMetricsResponse, error) {
	s.mu.Lock()
	s.vmMetrics = req
	s.mu.Unlock()
	if req.GetId() != "vm-1" {
		return nil, status.Error(codes.NotFound, "vm not found")
	}
	return &platformv1.VMMetricsResponse{Metrics: &platformv1.VMMetrics{CpuUsagePercent: 12.5, MemoryUsedMb: 512}}, nil
}

func (s *itemReadsComputeServer) GetContainerMetrics(_ context.Context, req *platformv1.GetContainerMetricsRequest) (*platformv1.ContainerMetricsResponse, error) {
	s.mu.Lock()
	s.containerMetrics = req
	s.mu.Unlock()
	if req.GetId() != "c1" {
		return nil, status.Error(codes.NotFound, "container not found")
	}
	return &platformv1.ContainerMetricsResponse{Metrics: &platformv1.ContainerMetrics{CpuUsagePercent: 3.5, MemoryLimitMb: 256}}, nil
}

func (s *itemReadsComputeServer) ExecContainer(_ context.Context, req *platformv1.ExecContainerRequest) (*platformv1.ExecContainerResponse, error) {
	s.mu.Lock()
	s.exec = req
	s.mu.Unlock()
	if req.GetId() != "c1" {
		return nil, status.Error(codes.NotFound, "container not found")
	}
	return &platformv1.ExecContainerResponse{ExitCode: 3, Stdout: []byte("ok")}, nil
}

func TestSDKREST_GetVM(t *testing.T) {
	server := &itemReadsComputeServer{}
	client, _ := connectComputeSDK(t, server)

	resp, err := client.GetVM(context.Background(), &platformv1.GetVMRequest{Id: "vm-1"})
	require.NoError(t, err)
	assert.Equal(t, "vm-1", resp.GetVm().GetId())
	assert.Equal(t, "web", resp.GetVm().GetConfig().GetName())
	require.NotNil(t, server.getVM)
	assert.Equal(t, "vm-1", server.getVM.GetId())
}

func TestSDKREST_GetVMUnknownIsNotFound(t *testing.T) {
	client, _ := connectComputeSDK(t, &itemReadsComputeServer{})

	_, err := client.GetVM(context.Background(), &platformv1.GetVMRequest{Id: "gone"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSDKREST_GetVMMetrics(t *testing.T) {
	server := &itemReadsComputeServer{}
	client, _ := connectComputeSDK(t, server)

	resp, err := client.GetVMMetrics(context.Background(), &platformv1.GetVMMetricsRequest{Id: "vm-1"})
	require.NoError(t, err)
	assert.Equal(t, 12.5, resp.GetMetrics().GetCpuUsagePercent())
	assert.Equal(t, uint64(512), resp.GetMetrics().GetMemoryUsedMb())
	require.NotNil(t, server.vmMetrics)
	assert.Equal(t, "vm-1", server.vmMetrics.GetId())
}

func TestSDKREST_GetContainerMetrics(t *testing.T) {
	server := &itemReadsComputeServer{}
	client, _ := connectComputeSDK(t, server)

	resp, err := client.GetContainerMetrics(context.Background(), &platformv1.GetContainerMetricsRequest{Id: "c1"})
	require.NoError(t, err)
	assert.Equal(t, 3.5, resp.GetMetrics().GetCpuUsagePercent())
	assert.Equal(t, uint64(256), resp.GetMetrics().GetMemoryLimitMb())
	require.NotNil(t, server.containerMetrics)
	assert.Equal(t, "c1", server.containerMetrics.GetId())
}

func TestSDKREST_ExecContainer(t *testing.T) {
	server := &itemReadsComputeServer{}
	client, _ := connectComputeSDK(t, server)

	resp, err := client.ExecContainer(context.Background(), &platformv1.ExecContainerRequest{
		Id:         "c1",
		Command:    []string{"true"},
		Env:        []*platformv1.EnvVar{{Name: "A", Value: "b"}},
		WorkingDir: "/",
		Tty:        false,
	})
	require.NoError(t, err)
	assert.Equal(t, int32(3), resp.GetExitCode())
	assert.Equal(t, []byte("ok"), resp.GetStdout())
	require.NotNil(t, server.exec)
	assert.Equal(t, "c1", server.exec.GetId())
	assert.Equal(t, []string{"true"}, server.exec.GetCommand())
	require.Len(t, server.exec.GetEnv(), 1)
	assert.Equal(t, "A", server.exec.GetEnv()[0].GetName())
	assert.Equal(t, "b", server.exec.GetEnv()[0].GetValue())
	assert.Equal(t, "/", server.exec.GetWorkingDir())
	assert.False(t, server.exec.GetTty())
}

func TestSDKREST_ItemReads_EmptyIDRefusedBeforeSending(t *testing.T) {
	client, apiRequests := connectComputeSDK(t, &itemReadsComputeServer{})
	ctx := context.Background()

	calls := map[string]func() error{
		"GetVM": func() error {
			_, err := client.GetVM(ctx, &platformv1.GetVMRequest{})
			return err
		},
		"GetVMMetrics": func() error {
			_, err := client.GetVMMetrics(ctx, &platformv1.GetVMMetricsRequest{})
			return err
		},
		"GetContainerMetrics": func() error {
			_, err := client.GetContainerMetrics(ctx, &platformv1.GetContainerMetricsRequest{})
			return err
		},
		"ExecContainer": func() error {
			_, err := client.ExecContainer(ctx, &platformv1.ExecContainerRequest{Command: []string{"true"}})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
	assert.Zero(t, apiRequests.Load(), "an empty id must be refused before any request is sent")
}
