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

package daemon

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestExecOptionsFromProto(t *testing.T) {
	req := &platformv1.ExecContainerRequest{
		Id:         "cid",
		Command:    []string{"ls", "-l"},
		WorkingDir: "/srv",
		Tty:        true,
		Env: []*platformv1.EnvVar{
			{Name: "FOO", Value: "bar"},
			{Name: "", Value: "skip"}, // nameless env is dropped
			nil,                       // nil entry is dropped
		},
	}

	opts := execOptionsFromProto(req)
	assert.Equal(t, []string{"ls", "-l"}, opts.Command)
	assert.Equal(t, "/srv", opts.WorkingDir)
	assert.True(t, opts.TTY)
	assert.Equal(t, []string{"FOO=bar"}, opts.Env)
}

func TestExecResultToProto(t *testing.T) {
	success := execResultToProto(&container.ExecResult{ExitCode: 0, Stdout: []byte("o"), Stderr: []byte("e")})
	require.NotNil(t, success.GetStatus())
	assert.True(t, success.GetStatus().GetSuccess())
	assert.Equal(t, int32(0), success.GetExitCode())
	assert.Equal(t, []byte("o"), success.GetStdout())
	assert.Equal(t, []byte("e"), success.GetStderr())

	failure := execResultToProto(&container.ExecResult{ExitCode: 2})
	assert.False(t, failure.GetStatus().GetSuccess())
	assert.Equal(t, int32(2), failure.GetExitCode())
}

func TestContainerStatsToProto(t *testing.T) {
	stats := &container.ContainerStats{
		CPUUsagePercent:  25.0,
		MemoryUsedBytes:  128 * 1024 * 1024,
		MemoryLimitBytes: 512 * 1024 * 1024,
		DiskReadBytes:    100,
		DiskWriteBytes:   200,
		NetworkRxBytes:   300,
		NetworkTxBytes:   400,
		UptimeSeconds:    600,
	}

	pb := containerStatsToProto(stats)
	assert.Equal(t, 25.0, pb.GetCpuUsagePercent())
	assert.Equal(t, uint64(128), pb.GetMemoryUsedMb())
	assert.Equal(t, uint64(512), pb.GetMemoryLimitMb())
	assert.Equal(t, uint64(100), pb.GetDiskReadBytes())
	assert.Equal(t, uint64(400), pb.GetNetworkTxBytes())
	assert.Equal(t, uint32(600), pb.GetUptimeSeconds())
}

func TestAttachChunkToProto(t *testing.T) {
	pb := attachChunkToProto(container.AttachChunk{Stream: "console", Data: []byte("hi")})
	assert.Equal(t, []byte("hi"), pb.GetData())
	assert.Equal(t, "console", pb.GetStream())
	assert.NotNil(t, pb.GetTimestamp())
}

func TestContainerOpsErrToStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code codes.Code
	}{
		{"exec not supported", container.ErrExecNotSupported, codes.Unimplemented},
		{"metrics not supported", container.ErrMetricsNotSupported, codes.Unimplemented},
		{"attach not supported", container.ErrAttachNotSupported, codes.Unimplemented},
		{"command required", container.ErrExecCommandRequired, codes.InvalidArgument},
		{"not found", container.ErrContainerNotFound, codes.NotFound},
		{"invalid id", container.ErrInvalidContainerID, codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.code, status.Code(containerOpsErrToStatus(tc.err)))
		})
	}
}
