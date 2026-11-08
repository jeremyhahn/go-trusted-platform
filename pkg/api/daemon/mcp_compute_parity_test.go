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
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

// computeParityOrchestrator is one in-memory orchestrator both transports
// share, so the MCP VM and container tools can be held to the answer and the
// error class ComputeService gives for the same input (#304). It adds the VM
// metrics and disk capabilities and container exec and metrics to the
// snapshot and attestation fake.
type computeParityOrchestrator struct {
	*vmCapableMockOrchestrator

	vmMetrics    *compute.VMMetrics
	vmMetricsErr error
	diskErr      error

	execResult     *container.ExecResult
	execErr        error
	containerStats *container.ContainerStats
	statsErr       error

	// runStateFunc answers Suspend and Resume; nil succeeds.
	runStateFunc func(ctx context.Context, instanceID string) error
}

func (m *computeParityOrchestrator) Suspend(ctx context.Context, instanceID string) error {
	return m.runState(ctx, instanceID)
}

func (m *computeParityOrchestrator) Resume(ctx context.Context, instanceID string) error {
	return m.runState(ctx, instanceID)
}

func (m *computeParityOrchestrator) runState(ctx context.Context, instanceID string) error {
	if m.runStateFunc == nil {
		return nil
	}
	return m.runStateFunc(ctx, instanceID)
}

func (m *computeParityOrchestrator) GetVMMetrics(context.Context, string) (*compute.VMMetrics, error) {
	return m.vmMetrics, m.vmMetricsErr
}

func (m *computeParityOrchestrator) AttachDisk(context.Context, string, compute.DiskAttachRequest) (*compute.DiskInfo, error) {
	return nil, m.diskErr
}

func (m *computeParityOrchestrator) DetachDisk(context.Context, string, string) error {
	return m.diskErr
}

func (m *computeParityOrchestrator) ResizeDisk(context.Context, string, string, uint64) error {
	return m.diskErr
}

func (m *computeParityOrchestrator) Exec(context.Context, string, container.ExecOptions) (*container.ExecResult, error) {
	return m.execResult, m.execErr
}

func (m *computeParityOrchestrator) Metrics(context.Context, string) (*container.ContainerStats, error) {
	return m.containerStats, m.statsErr
}

var (
	_ compute.VMMetricsReader = (*computeParityOrchestrator)(nil)
	_ compute.VMDiskManager   = (*computeParityOrchestrator)(nil)
	_ compute.VMSuspender     = (*computeParityOrchestrator)(nil)
	_ containerExecutor       = (*computeParityOrchestrator)(nil)
	_ containerMetricsReader  = (*computeParityOrchestrator)(nil)
)

// newComputeParityPair builds the MCP provider and the gRPC ComputeService
// over the same orchestrator.
func newComputeParityPair() (*MCPServiceProvider, *ComputeGRPCService, *computeParityOrchestrator) {
	orch := &computeParityOrchestrator{vmCapableMockOrchestrator: newVMCapableMockOrchestrator()}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{ComputeOrchestrator: orch})
	return provider, NewComputeGRPCService(logging.DefaultLogger(), orch), orch
}

// computeErrClasses are orchestrator failures for an unknown or a malformed
// instance, with the class ComputeService answers each with.
var computeErrClasses = []struct {
	name string
	err  error
	want codes.Code
}{
	{"not found", compute.ErrInstanceNotFound, codes.NotFound},
	{"invalid input", compute.ErrInvalidInstanceID, codes.InvalidArgument},
}

func TestComputeParity_VMSnapshotList(t *testing.T) {
	provider, svc, orch := newComputeParityPair()
	orch.snapshots = []*compute.VMSnapshot{{
		Name: "snap-1", VMID: "vm-1", Description: "before upgrade", SizeBytes: 4096,
		CreatedAt: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC),
	}}

	mcpResult, err := provider.VMSnapshotList(context.Background(), "vm-1")
	require.NoError(t, err)
	grpcResp, err := svc.ListSnapshots(context.Background(), &platformv1.ListSnapshotsRequest{VmId: "vm-1"})
	require.NoError(t, err)

	var got platformv1.ListSnapshotsResponse
	decodeMCPProto(t, mcpResult, &got)
	assert.True(t, proto.Equal(grpcResp, &got), "MCP reply %v, gRPC reply %v", &got, grpcResp)
}

func TestComputeParity_VMSnapshotListErrors(t *testing.T) {
	for _, tc := range append(computeErrClasses, struct {
		name string
		err  error
		want codes.Code
	}{"unknown snapshot", compute.ErrSnapshotNotFound, codes.NotFound}) {
		t.Run(tc.name, func(t *testing.T) {
			provider, svc, orch := newComputeParityPair()
			orch.listErr = tc.err

			_, mcpErr := provider.VMSnapshotList(context.Background(), "vm-1")
			_, grpcErr := svc.ListSnapshots(context.Background(), &platformv1.ListSnapshotsRequest{VmId: "vm-1"})
			assertSameClass(t, tc.want, mcpErr, grpcErr)
		})
	}
}

func TestComputeParity_VMAttest(t *testing.T) {
	provider, svc, _ := newComputeParityPair()
	nonce := []byte("nonce")

	req := &platformv1.AttestVMRequest{VmId: "vm-1", Nonce: nonce, PcrIndices: []uint32{0, 7}}

	mcpResult, err := provider.VMAttest(context.Background(), req)
	require.NoError(t, err)
	grpcResp, err := svc.AttestVM(context.Background(), req)
	require.NoError(t, err)

	var got platformv1.AttestVMResponse
	decodeMCPProto(t, mcpResult, &got)
	assert.Equal(t, grpcResp.GetQuote(), got.GetQuote())
	assert.Equal(t, grpcResp.GetSignatureAlgorithm(), got.GetSignatureAlgorithm())
	require.Len(t, got.GetPcrValues(), len(grpcResp.GetPcrValues()))
	for i, pcr := range grpcResp.GetPcrValues() {
		assert.True(t, proto.Equal(pcr, got.GetPcrValues()[i]), "PCR %d: MCP %v, gRPC %v", i, got.GetPcrValues()[i], pcr)
	}
}

// TestComputeParity_VMAttestRefusesOutOfRangePCR: PCR 24 is outside a TPM
// 2.0 bank; both transports refuse it as invalid input before the backend
// quotes anything.
func TestComputeParity_VMAttestRefusesOutOfRangePCR(t *testing.T) {
	provider, svc, orch := newComputeParityPair()

	req := &platformv1.AttestVMRequest{VmId: "vm-1", Nonce: []byte("nonce"), PcrIndices: []uint32{24}}
	_, mcpErr := provider.VMAttest(context.Background(), req)
	_, grpcErr := svc.AttestVM(context.Background(), req)

	assertSameClass(t, codes.InvalidArgument, mcpErr, grpcErr)
	assert.Nil(t, orch.recordedAttestPCRs(), "the backend must not be asked to quote")
}

func TestComputeParity_VMAttestErrors(t *testing.T) {
	for _, tc := range computeErrClasses {
		t.Run(tc.name, func(t *testing.T) {
			provider, svc, orch := newComputeParityPair()
			orch.attestErr = tc.err

			req := &platformv1.AttestVMRequest{VmId: "vm-1", Nonce: []byte("nonce")}
			_, mcpErr := provider.VMAttest(context.Background(), req)
			_, grpcErr := svc.AttestVM(context.Background(), req)
			assertSameClass(t, tc.want, mcpErr, grpcErr)
		})
	}
}

func TestComputeParity_VMMetrics(t *testing.T) {
	provider, svc, orch := newComputeParityPair()
	orch.vmMetrics = &compute.VMMetrics{CPUUsagePercent: 12.5, MemoryUsedMB: 512, NetworkRxBytes: 99, UptimeSeconds: 60}

	mcpResult, err := provider.VMMetrics(context.Background(), "vm-1")
	require.NoError(t, err)
	grpcResp, err := svc.GetVMMetrics(context.Background(), &platformv1.GetVMMetricsRequest{Id: "vm-1"})
	require.NoError(t, err)

	got := mcpResult.(map[string]interface{})
	want := grpcResp.GetMetrics()
	assert.Equal(t, want.GetCpuUsagePercent(), got["cpu_usage_percent"])
	assert.Equal(t, want.GetMemoryUsedMb(), got["memory_used_mb"])
	assert.Equal(t, want.GetNetworkRxBytes(), got["network_rx_bytes"])
	assert.Equal(t, want.GetUptimeSeconds(), got["uptime_seconds"])
}

func TestComputeParity_VMOpsErrors(t *testing.T) {
	for _, tc := range computeErrClasses {
		t.Run("metrics "+tc.name, func(t *testing.T) {
			provider, svc, orch := newComputeParityPair()
			orch.vmMetricsErr = tc.err

			_, mcpErr := provider.VMMetrics(context.Background(), "vm-1")
			_, grpcErr := svc.GetVMMetrics(context.Background(), &platformv1.GetVMMetricsRequest{Id: "vm-1"})
			assertSameClass(t, tc.want, mcpErr, grpcErr)
		})
	}

	t.Run("resize unknown disk", func(t *testing.T) {
		provider, svc, orch := newComputeParityPair()
		orch.diskErr = compute.ErrDiskNotFound

		mcpErr := provider.VMDiskResize(context.Background(), "vm-1", "disk-9", 20)
		_, grpcErr := svc.ResizeDisk(context.Background(), &platformv1.ResizeDiskRequest{VmId: "vm-1", DiskId: "disk-9", NewSizeGb: 20})
		assertSameClass(t, codes.NotFound, mcpErr, grpcErr)
	})

	t.Run("resize invalid request", func(t *testing.T) {
		provider, svc, orch := newComputeParityPair()
		orch.diskErr = compute.ErrInvalidDiskRequest

		mcpErr := provider.VMDiskResize(context.Background(), "vm-1", "disk-1", 0)
		_, grpcErr := svc.ResizeDisk(context.Background(), &platformv1.ResizeDiskRequest{VmId: "vm-1", DiskId: "disk-1"})
		assertSameClass(t, codes.InvalidArgument, mcpErr, grpcErr)
	})
}

func TestComputeParity_ContainerExec(t *testing.T) {
	provider, svc, orch := newComputeParityPair()
	orch.execResult = &container.ExecResult{ExitCode: 3, Stdout: []byte("out"), Stderr: []byte("err")}

	mcpResult, err := provider.ContainerExec(context.Background(), "c-1", []string{"ls"}, nil, "", false)
	require.NoError(t, err)
	grpcResp, err := svc.ExecContainer(context.Background(), &platformv1.ExecContainerRequest{Id: "c-1", Command: []string{"ls"}})
	require.NoError(t, err)

	got := mcpResult.(map[string]interface{})
	assert.EqualValues(t, grpcResp.GetExitCode(), got["exit_code"])
	assert.Equal(t, string(grpcResp.GetStdout()), got["stdout"])
	assert.Equal(t, string(grpcResp.GetStderr()), got["stderr"])
}

func TestComputeParity_ContainerMetrics(t *testing.T) {
	provider, svc, orch := newComputeParityPair()
	orch.containerStats = &container.ContainerStats{CPUUsagePercent: 4.5, MemoryUsedBytes: 1 << 20, UptimeSeconds: 30}

	mcpResult, err := provider.ContainerMetrics(context.Background(), "c-1")
	require.NoError(t, err)
	grpcResp, err := svc.GetContainerMetrics(context.Background(), &platformv1.GetContainerMetricsRequest{Id: "c-1"})
	require.NoError(t, err)

	got := mcpResult.(map[string]interface{})
	want := grpcResp.GetMetrics()
	assert.Equal(t, want.GetCpuUsagePercent(), got["cpu_usage_percent"])
	// gRPC carries memory in MiB, MCP in bytes: the same quantity.
	assert.Equal(t, want.GetMemoryUsedMb(), got["memory_used_bytes"].(uint64)/(1024*1024))
	assert.EqualValues(t, want.GetUptimeSeconds(), got["uptime_seconds"])
}

func TestComputeParity_ContainerOpsErrors(t *testing.T) {
	classes := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"not found", container.ErrContainerNotFound, codes.NotFound},
		{"invalid input", container.ErrInvalidContainerID, codes.InvalidArgument},
	}
	for _, tc := range classes {
		t.Run("exec "+tc.name, func(t *testing.T) {
			provider, svc, orch := newComputeParityPair()
			orch.execErr = tc.err

			_, mcpErr := provider.ContainerExec(context.Background(), "c-1", []string{"ls"}, nil, "", false)
			_, grpcErr := svc.ExecContainer(context.Background(), &platformv1.ExecContainerRequest{Id: "c-1", Command: []string{"ls"}})
			assertSameClass(t, tc.want, mcpErr, grpcErr)
		})
		t.Run("metrics "+tc.name, func(t *testing.T) {
			provider, svc, orch := newComputeParityPair()
			orch.statsErr = tc.err

			_, mcpErr := provider.ContainerMetrics(context.Background(), "c-1")
			_, grpcErr := svc.GetContainerMetrics(context.Background(), &platformv1.GetContainerMetricsRequest{Id: "c-1"})
			assertSameClass(t, tc.want, mcpErr, grpcErr)
		})
	}

	t.Run("exec without a command", func(t *testing.T) {
		provider, svc, _ := newComputeParityPair()

		_, mcpErr := provider.ContainerExec(context.Background(), "c-1", nil, nil, "", false)
		_, grpcErr := svc.ExecContainer(context.Background(), &platformv1.ExecContainerRequest{Id: "c-1"})
		assertSameClass(t, codes.InvalidArgument, mcpErr, grpcErr)
	})
}

func TestComputeParity_ContainerGet(t *testing.T) {
	provider, svc, orch := newComputeParityPair()
	orch.instances["c-1"] = &compute.Instance{
		ID: "c-1", Name: "web", Type: compute.ComputeTypeContainer, State: compute.StateRunning,
	}

	mcpResult, err := provider.ContainerGet(context.Background(), "c-1")
	require.NoError(t, err)
	grpcResp, err := svc.GetContainer(context.Background(), &platformv1.GetContainerRequest{Id: "c-1"})
	require.NoError(t, err)

	got := mcpResult.(map[string]interface{})
	assert.Equal(t, grpcResp.GetContainer().GetId(), got["id"])
	assert.Equal(t, grpcResp.GetContainer().GetConfig().GetName(), got["name"])

	t.Run("unknown container", func(t *testing.T) {
		_, mcpErr := provider.ContainerGet(context.Background(), "c-missing")
		_, grpcErr := svc.GetContainer(context.Background(), &platformv1.GetContainerRequest{Id: "c-missing"})
		assertSameClass(t, codes.NotFound, mcpErr, grpcErr)
	})
}

// TestComputeParity_NoOrchestrator: with no compute orchestrator both
// transports answer FailedPrecondition.
func TestComputeParity_NoOrchestrator(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	svc := NewComputeGRPCService(logging.DefaultLogger(), nil)

	_, mcpErr := provider.VMSnapshotList(context.Background(), "vm-1")
	_, grpcErr := svc.ListSnapshots(context.Background(), &platformv1.ListSnapshotsRequest{VmId: "vm-1"})
	assertSameClass(t, codes.FailedPrecondition, mcpErr, grpcErr)

	_, mcpErr = provider.ContainerGet(context.Background(), "c-1")
	_, grpcErr = svc.GetContainer(context.Background(), &platformv1.GetContainerRequest{Id: "c-1"})
	assertSameClass(t, codes.FailedPrecondition, mcpErr, grpcErr)
}
