package daemon

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Compute gRPC Service - VM Operations with Mock Orchestrator
// =============================================================================

func boostComputeService() (*ComputeGRPCService, *mockOrchestrator) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	orch := &mockOrchestrator{}
	svc := NewComputeGRPCService(logger, orch)
	return svc, orch
}

func TestBoost_ComputeGRPCService_CreateVM_Success(t *testing.T) {
	svc, orch := boostComputeService()
	now := time.Now()
	orch.createFunc = func(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
		return &compute.Instance{
			ID:    "vm-1",
			Name:  profile.Name,
			State: compute.StateRunning,
			Config: &compute.InstanceConfig{
				Memory: 1024,
				CPUs:   1,
			},
			CreatedAt: now,
			UpdatedAt: now,
		}, nil
	}

	resp, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{
		// A plain orchestrator can create a default VM only.
		Config: &platformv1.VMConfig{
			Name: "test-vm",
			Tpm:  &platformv1.TPMConfig{Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Fatal("expected success status")
	}
	if resp.Vm == nil {
		t.Fatal("expected non-nil VM")
	}
}

func TestBoost_ComputeGRPCService_CreateVM_NilConfig(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{})
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestBoost_ComputeGRPCService_CreateVM_EmptyName(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{
		Config: &platformv1.VMConfig{Name: ""},
	})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestBoost_ComputeGRPCService_CreateVM_OrchestratorError(t *testing.T) {
	svc, orch := boostComputeService()
	orch.createFunc = func(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
		return nil, ErrServiceNotAvailable{Service: "compute"}
	}

	_, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{
		Config: &platformv1.VMConfig{Name: "test-vm"},
	})
	if err == nil {
		t.Fatal("expected error from orchestrator")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", status.Code(err))
	}
}

func TestBoost_ComputeGRPCService_StartVM_Success(t *testing.T) {
	svc, _ := boostComputeService()

	resp, err := svc.StartVM(context.Background(), &platformv1.StartVMRequest{Id: "vm-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Fatal("expected success")
	}
}

func TestBoost_ComputeGRPCService_StartVM_EmptyID(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.StartVM(context.Background(), &platformv1.StartVMRequest{Id: ""})
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestBoost_ComputeGRPCService_StartVM_Error(t *testing.T) {
	svc, orch := boostComputeService()
	orch.startFunc = func(ctx context.Context, id string) error {
		return ErrServiceNotAvailable{Service: "compute"}
	}

	_, err := svc.StartVM(context.Background(), &platformv1.StartVMRequest{Id: "vm-1"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBoost_ComputeGRPCService_StopVM_Success(t *testing.T) {
	svc, _ := boostComputeService()

	resp, err := svc.StopVM(context.Background(), &platformv1.StopVMRequest{Id: "vm-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Fatal("expected success")
	}
}

func TestBoost_ComputeGRPCService_StopVM_EmptyID(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.StopVM(context.Background(), &platformv1.StopVMRequest{Id: ""})
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestBoost_ComputeGRPCService_StopVM_Error(t *testing.T) {
	svc, orch := boostComputeService()
	orch.stopFunc = func(ctx context.Context, id string) error {
		return ErrServiceNotAvailable{Service: "compute"}
	}

	_, err := svc.StopVM(context.Background(), &platformv1.StopVMRequest{Id: "vm-1"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBoost_ComputeGRPCService_RebootVM_Success(t *testing.T) {
	svc, _ := boostComputeService()

	resp, err := svc.RebootVM(context.Background(), &platformv1.RebootVMRequest{Id: "vm-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Fatal("expected success")
	}
}

func TestBoost_ComputeGRPCService_RebootVM_EmptyID(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.RebootVM(context.Background(), &platformv1.RebootVMRequest{Id: ""})
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestBoost_ComputeGRPCService_RebootVM_StopFails(t *testing.T) {
	svc, orch := boostComputeService()
	orch.stopFunc = func(ctx context.Context, id string) error {
		return ErrServiceNotAvailable{Service: "compute"}
	}

	_, err := svc.RebootVM(context.Background(), &platformv1.RebootVMRequest{Id: "vm-1"})
	if err == nil {
		t.Fatal("expected error when stop fails")
	}
}

func TestBoost_ComputeGRPCService_RebootVM_StartFails(t *testing.T) {
	svc, orch := boostComputeService()
	orch.startFunc = func(ctx context.Context, id string) error {
		return ErrServiceNotAvailable{Service: "compute"}
	}

	_, err := svc.RebootVM(context.Background(), &platformv1.RebootVMRequest{Id: "vm-1"})
	if err == nil {
		t.Fatal("expected error when start fails after stop")
	}
}

func TestBoost_ComputeGRPCService_DeleteVM_Success(t *testing.T) {
	svc, _ := boostComputeService()

	resp, err := svc.DeleteVM(context.Background(), &platformv1.DeleteVMRequest{Id: "vm-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Fatal("expected success")
	}
}

func TestBoost_ComputeGRPCService_DeleteVM_EmptyID(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.DeleteVM(context.Background(), &platformv1.DeleteVMRequest{Id: ""})
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestBoost_ComputeGRPCService_DeleteVM_Error(t *testing.T) {
	svc, orch := boostComputeService()
	orch.deleteFunc = func(ctx context.Context, id string) error {
		return ErrServiceNotAvailable{Service: "compute"}
	}

	_, err := svc.DeleteVM(context.Background(), &platformv1.DeleteVMRequest{Id: "vm-1"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBoost_ComputeGRPCService_GetVM_Success(t *testing.T) {
	svc, orch := boostComputeService()
	orch.getFunc = func(ctx context.Context, id string) (*compute.Instance, error) {
		return &compute.Instance{
			ID:    id,
			Name:  "test-vm",
			State: compute.StateRunning,
		}, nil
	}

	resp, err := svc.GetVM(context.Background(), &platformv1.GetVMRequest{Id: "vm-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Vm == nil {
		t.Fatal("expected non-nil VM")
	}
	if resp.Vm.Id != "vm-1" {
		t.Fatalf("expected vm-1, got %s", resp.Vm.Id)
	}
}

func TestBoost_ComputeGRPCService_GetVM_EmptyID(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.GetVM(context.Background(), &platformv1.GetVMRequest{Id: ""})
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestBoost_ComputeGRPCService_GetVM_NotFound(t *testing.T) {
	svc, orch := boostComputeService()
	orch.getFunc = func(ctx context.Context, id string) (*compute.Instance, error) {
		return nil, ErrServiceNotFound{ServiceName: id}
	}

	_, err := svc.GetVM(context.Background(), &platformv1.GetVMRequest{Id: "vm-1"})
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", status.Code(err))
	}
}

func TestBoost_ComputeGRPCService_ListVMs_Success(t *testing.T) {
	svc, orch := boostComputeService()
	orch.listFunc = func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
		return []*compute.Instance{
			{ID: "vm-1", Name: "vm1", State: compute.StateRunning},
			{ID: "vm-2", Name: "vm2", State: compute.StateStopped},
		}, nil
	}

	resp, err := svc.ListVMs(context.Background(), &platformv1.ListVMsRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Vms) != 2 {
		t.Fatalf("expected 2 VMs, got %d", len(resp.Vms))
	}
}

func TestBoost_ComputeGRPCService_ListVMs_Error(t *testing.T) {
	svc, orch := boostComputeService()
	orch.listFunc = func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
		return nil, ErrServiceNotAvailable{Service: "compute"}
	}

	_, err := svc.ListVMs(context.Background(), &platformv1.ListVMsRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// =============================================================================
// Compute gRPC Service - Container Operations with Mock Orchestrator
// =============================================================================

func TestBoost_ComputeGRPCService_CreateContainer_Success(t *testing.T) {
	svc, orch := boostComputeService()
	orch.createFunc = func(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
		return &compute.Instance{
			ID:    "ctr-1",
			Name:  profile.Name,
			State: compute.StateRunning,
		}, nil
	}

	resp, err := svc.CreateContainer(context.Background(), &platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{
			Name:  "test-ctr",
			Image: "alpine:latest",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Fatal("expected success")
	}
	if resp.Container == nil {
		t.Fatal("expected non-nil container")
	}
}

func TestBoost_ComputeGRPCService_CreateContainer_NilConfig(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.CreateContainer(context.Background(), &platformv1.CreateContainerRequest{})
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestBoost_ComputeGRPCService_CreateContainer_EmptyImage(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.CreateContainer(context.Background(), &platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{Name: "no-image", Image: ""},
	})
	if err == nil {
		t.Fatal("expected error for empty image")
	}
}

func TestBoost_ComputeGRPCService_CreateContainer_Error(t *testing.T) {
	svc, orch := boostComputeService()
	orch.createFunc = func(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
		return nil, ErrServiceNotAvailable{Service: "compute"}
	}

	_, err := svc.CreateContainer(context.Background(), &platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{Name: "create-fails", Image: "alpine:latest"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBoost_ComputeGRPCService_StartContainer_Success(t *testing.T) {
	svc, _ := boostComputeService()

	resp, err := svc.StartContainer(context.Background(), &platformv1.StartContainerRequest{Id: "ctr-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Fatal("expected success")
	}
}

func TestBoost_ComputeGRPCService_StartContainer_EmptyID(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.StartContainer(context.Background(), &platformv1.StartContainerRequest{Id: ""})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBoost_ComputeGRPCService_StartContainer_Error(t *testing.T) {
	svc, orch := boostComputeService()
	orch.startFunc = func(ctx context.Context, id string) error {
		return ErrServiceNotAvailable{Service: "compute"}
	}

	_, err := svc.StartContainer(context.Background(), &platformv1.StartContainerRequest{Id: "ctr-1"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBoost_ComputeGRPCService_StopContainer_Success(t *testing.T) {
	svc, _ := boostComputeService()

	resp, err := svc.StopContainer(context.Background(), &platformv1.StopContainerRequest{Id: "ctr-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Fatal("expected success")
	}
}

func TestBoost_ComputeGRPCService_StopContainer_EmptyID(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.StopContainer(context.Background(), &platformv1.StopContainerRequest{Id: ""})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBoost_ComputeGRPCService_StopContainer_Error(t *testing.T) {
	svc, orch := boostComputeService()
	orch.stopFunc = func(ctx context.Context, id string) error {
		return ErrServiceNotAvailable{Service: "compute"}
	}

	_, err := svc.StopContainer(context.Background(), &platformv1.StopContainerRequest{Id: "ctr-1"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBoost_ComputeGRPCService_DeleteContainer_Success(t *testing.T) {
	svc, _ := boostComputeService()

	resp, err := svc.DeleteContainer(context.Background(), &platformv1.DeleteContainerRequest{Id: "ctr-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Fatal("expected success")
	}
}

func TestBoost_ComputeGRPCService_DeleteContainer_EmptyID(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.DeleteContainer(context.Background(), &platformv1.DeleteContainerRequest{Id: ""})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBoost_ComputeGRPCService_DeleteContainer_Error(t *testing.T) {
	svc, orch := boostComputeService()
	orch.deleteFunc = func(ctx context.Context, id string) error {
		return ErrServiceNotAvailable{Service: "compute"}
	}

	_, err := svc.DeleteContainer(context.Background(), &platformv1.DeleteContainerRequest{Id: "ctr-1"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBoost_ComputeGRPCService_GetContainer_Success(t *testing.T) {
	svc, orch := boostComputeService()
	orch.getFunc = func(ctx context.Context, id string) (*compute.Instance, error) {
		return &compute.Instance{
			ID:    id,
			Name:  "test-ctr",
			State: compute.StateRunning,
		}, nil
	}

	resp, err := svc.GetContainer(context.Background(), &platformv1.GetContainerRequest{Id: "ctr-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Container == nil {
		t.Fatal("expected non-nil container")
	}
}

func TestBoost_ComputeGRPCService_GetContainer_EmptyID(t *testing.T) {
	svc, _ := boostComputeService()

	_, err := svc.GetContainer(context.Background(), &platformv1.GetContainerRequest{Id: ""})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBoost_ComputeGRPCService_GetContainer_NotFound(t *testing.T) {
	svc, orch := boostComputeService()
	orch.getFunc = func(ctx context.Context, id string) (*compute.Instance, error) {
		return nil, ErrServiceNotFound{ServiceName: id}
	}

	_, err := svc.GetContainer(context.Background(), &platformv1.GetContainerRequest{Id: "ctr-1"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBoost_ComputeGRPCService_ListContainers_Success(t *testing.T) {
	svc, orch := boostComputeService()
	orch.listFunc = func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
		return []*compute.Instance{
			{ID: "ctr-1", Name: "ctr1", State: compute.StateRunning},
		}, nil
	}

	resp, err := svc.ListContainers(context.Background(), &platformv1.ListContainersRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(resp.Containers))
	}
}

func TestBoost_ComputeGRPCService_ListContainers_Error(t *testing.T) {
	svc, orch := boostComputeService()
	orch.listFunc = func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
		return nil, ErrServiceNotAvailable{Service: "compute"}
	}

	_, err := svc.ListContainers(context.Background(), &platformv1.ListContainersRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
}
