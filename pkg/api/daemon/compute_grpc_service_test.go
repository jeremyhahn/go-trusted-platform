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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Mock Orchestrator for gRPC service tests
// =============================================================================

// grpcMockOrchestrator implements compute.Orchestrator for testing.
// Named distinctly to avoid conflicts with mockOrchestrator in compute_adapter_test.go.
type grpcMockOrchestrator struct {
	mu            sync.RWMutex
	instances     map[string]*compute.Instance
	createFunc    func(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error)
	startFunc     func(ctx context.Context, instanceID string) error
	stopFunc      func(ctx context.Context, instanceID string) error
	deleteFunc    func(ctx context.Context, instanceID string) error
	getFunc       func(ctx context.Context, instanceID string) (*compute.Instance, error)
	listFunc      func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error)
	attachNetFunc func(ctx context.Context, instanceID, portName string) error
	detachNetFunc func(ctx context.Context, instanceID, portName string) error
	activateFunc  func(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error
	waitFunc      func(ctx context.Context, instanceID string) error
	getStateFunc  func(ctx context.Context, instanceID string) (compute.InstanceState, error)
	closeFunc     func() error
}

func newGRPCMockOrchestrator() *grpcMockOrchestrator {
	return &grpcMockOrchestrator{
		instances: make(map[string]*compute.Instance),
	}
}

func (m *grpcMockOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, profile)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	id := profile.Name + "-instance"
	instance := &compute.Instance{
		ID:        id,
		Name:      profile.Name,
		Type:      compute.ComputeTypeVM,
		State:     compute.StateStopped,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Config: &compute.InstanceConfig{
			Memory:     2048,
			CPUs:       2,
			SecureBoot: false,
			TPMEnabled: false,
		},
	}
	m.instances[id] = instance
	return instance, nil
}

func (m *grpcMockOrchestrator) Start(ctx context.Context, instanceID string) error {
	if m.startFunc != nil {
		return m.startFunc(ctx, instanceID)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	instance, ok := m.instances[instanceID]
	if !ok {
		return errors.New("instance not found")
	}
	instance.State = compute.StateRunning
	instance.UpdatedAt = time.Now()
	return nil
}

func (m *grpcMockOrchestrator) Stop(ctx context.Context, instanceID string) error {
	if m.stopFunc != nil {
		return m.stopFunc(ctx, instanceID)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	instance, ok := m.instances[instanceID]
	if !ok {
		return errors.New("instance not found")
	}
	instance.State = compute.StateStopped
	instance.UpdatedAt = time.Now()
	return nil
}

func (m *grpcMockOrchestrator) Delete(ctx context.Context, instanceID string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, instanceID)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.instances[instanceID]; !ok {
		return errors.New("instance not found")
	}
	delete(m.instances, instanceID)
	return nil
}

func (m *grpcMockOrchestrator) Get(ctx context.Context, instanceID string) (*compute.Instance, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, instanceID)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	instance, ok := m.instances[instanceID]
	if !ok {
		return nil, errors.New("instance not found")
	}
	return instance, nil
}

func (m *grpcMockOrchestrator) List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, filter)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*compute.Instance
	for _, instance := range m.instances {
		if filter == nil || filter.Matches(instance) {
			result = append(result, instance)
		}
	}
	return result, nil
}

func (m *grpcMockOrchestrator) AttachNetwork(ctx context.Context, instanceID, portName string) error {
	if m.attachNetFunc != nil {
		return m.attachNetFunc(ctx, instanceID, portName)
	}
	return nil
}

func (m *grpcMockOrchestrator) DetachNetwork(ctx context.Context, instanceID, portName string) error {
	if m.detachNetFunc != nil {
		return m.detachNetFunc(ctx, instanceID, portName)
	}
	return nil
}

func (m *grpcMockOrchestrator) ActivateInstance(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error {
	if m.activateFunc != nil {
		return m.activateFunc(ctx, instanceID, portPolicy)
	}
	return nil
}

func (m *grpcMockOrchestrator) Wait(ctx context.Context, instanceID string) error {
	if m.waitFunc != nil {
		return m.waitFunc(ctx, instanceID)
	}
	return nil
}

func (m *grpcMockOrchestrator) GetState(ctx context.Context, instanceID string) (compute.InstanceState, error) {
	if m.getStateFunc != nil {
		return m.getStateFunc(ctx, instanceID)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	instance, ok := m.instances[instanceID]
	if !ok {
		return compute.StateUnknown, errors.New("instance not found")
	}
	return instance.State, nil
}

func (m *grpcMockOrchestrator) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

// Verify interface compliance at compile time
var _ compute.Orchestrator = (*grpcMockOrchestrator)(nil)

// =============================================================================
// Helper Functions
// =============================================================================

func createTestComputeService(t *testing.T) *ComputeGRPCService {
	t.Helper()
	logger := logging.DefaultLogger()
	orchestrator := newGRPCMockOrchestrator()
	return NewComputeGRPCService(logger, orchestrator)
}

func createTestComputeServiceNoOrchestrator(t *testing.T) *ComputeGRPCService {
	t.Helper()
	logger := logging.DefaultLogger()
	return NewComputeGRPCService(logger, nil)
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewComputeGRPCService(t *testing.T) {
	t.Run("creates service with orchestrator", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()

		svc := NewComputeGRPCService(logger, orchestrator)

		assert.NotNil(t, svc)
		assert.Equal(t, logger, svc.logger)
		assert.Equal(t, orchestrator, svc.orchestrator)
	})

	t.Run("creates service without orchestrator", func(t *testing.T) {
		logger := logging.DefaultLogger()

		svc := NewComputeGRPCService(logger, nil)

		assert.NotNil(t, svc)
		assert.Equal(t, logger, svc.logger)
		assert.Nil(t, svc.orchestrator)
	})
}

func TestComputeGRPCService_SetOrchestrator(t *testing.T) {
	logger := logging.DefaultLogger()
	svc := NewComputeGRPCService(logger, nil)
	assert.Nil(t, svc.orchestrator)

	orchestrator := newGRPCMockOrchestrator()
	svc.SetOrchestrator(orchestrator)

	assert.Equal(t, orchestrator, svc.orchestrator)
}

// =============================================================================
// VM Operation Tests
// =============================================================================

func TestComputeGRPCService_CreateVM(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.CreateVM(ctx, &platformv1.CreateVMRequest{
			Config: &platformv1.VMConfig{Name: "test-vm"},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil config", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.CreateVM(ctx, &platformv1.CreateVMRequest{
			Config: nil,
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty VM name", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.CreateVM(ctx, &platformv1.CreateVMRequest{
			Config: &platformv1.VMConfig{Name: ""},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("creates VM successfully", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.CreateVM(ctx, &platformv1.CreateVMRequest{
			Config: &platformv1.VMConfig{
				Name: "test-vm",
				Memory: &platformv1.MemoryConfig{
					SizeMb: 4096,
				},
				Cpu: &platformv1.CPUConfig{
					Cores: 4,
				},
				SecureBoot: true,
				Tpm: &platformv1.TPMConfig{
					Enabled: true,
					Version: platformv1.TPMVersion_TPM_VERSION_2_0,
				},
			},
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
		assert.NotNil(t, resp.Vm)
		assert.NotEmpty(t, resp.Vm.Id)
	})

	t.Run("creates VM with default values", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.CreateVM(ctx, &platformv1.CreateVMRequest{
			Config: &platformv1.VMConfig{
				Name: "minimal-vm",
			},
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
	})

	t.Run("handles orchestrator create error", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()
		orchestrator.createFunc = func(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
			return nil, errors.New("create failed")
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.CreateVM(ctx, &platformv1.CreateVMRequest{
			Config: &platformv1.VMConfig{Name: "fail-vm"},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestComputeGRPCService_StartVM(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.StartVM(ctx, &platformv1.StartVMRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for empty VM ID", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.StartVM(ctx, &platformv1.StartVMRequest{Id: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("starts VM successfully", func(t *testing.T) {
		svc := createTestComputeService(t)

		// Create VM first
		createResp, err := svc.CreateVM(ctx, &platformv1.CreateVMRequest{
			Config: &platformv1.VMConfig{Name: "start-test"},
		})
		require.NoError(t, err)

		resp, err := svc.StartVM(ctx, &platformv1.StartVMRequest{
			Id: createResp.Vm.Id,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
	})

	t.Run("handles orchestrator start error", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()
		orchestrator.startFunc = func(ctx context.Context, instanceID string) error {
			return errors.New("start failed")
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.StartVM(ctx, &platformv1.StartVMRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestComputeGRPCService_StopVM(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.StopVM(ctx, &platformv1.StopVMRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for empty VM ID", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.StopVM(ctx, &platformv1.StopVMRequest{Id: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("stops VM successfully", func(t *testing.T) {
		svc := createTestComputeService(t)

		// Create and start VM first
		createResp, err := svc.CreateVM(ctx, &platformv1.CreateVMRequest{
			Config: &platformv1.VMConfig{Name: "stop-test"},
		})
		require.NoError(t, err)

		_, err = svc.StartVM(ctx, &platformv1.StartVMRequest{Id: createResp.Vm.Id})
		require.NoError(t, err)

		resp, err := svc.StopVM(ctx, &platformv1.StopVMRequest{
			Id: createResp.Vm.Id,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
	})

	t.Run("handles orchestrator stop error", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()
		orchestrator.stopFunc = func(ctx context.Context, instanceID string) error {
			return errors.New("stop failed")
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.StopVM(ctx, &platformv1.StopVMRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestComputeGRPCService_RebootVM(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.RebootVM(ctx, &platformv1.RebootVMRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for empty VM ID", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.RebootVM(ctx, &platformv1.RebootVMRequest{Id: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("reboots VM successfully", func(t *testing.T) {
		svc := createTestComputeService(t)

		// Create VM first
		createResp, err := svc.CreateVM(ctx, &platformv1.CreateVMRequest{
			Config: &platformv1.VMConfig{Name: "reboot-test"},
		})
		require.NoError(t, err)

		resp, err := svc.RebootVM(ctx, &platformv1.RebootVMRequest{
			Id: createResp.Vm.Id,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
	})

	t.Run("handles stop error during reboot", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()
		orchestrator.stopFunc = func(ctx context.Context, instanceID string) error {
			return errors.New("stop failed")
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.RebootVM(ctx, &platformv1.RebootVMRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("handles start error during reboot", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()
		stopCalled := false
		orchestrator.stopFunc = func(ctx context.Context, instanceID string) error {
			stopCalled = true
			return nil
		}
		orchestrator.startFunc = func(ctx context.Context, instanceID string) error {
			if stopCalled {
				return errors.New("start failed after stop")
			}
			return nil
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.RebootVM(ctx, &platformv1.RebootVMRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestComputeGRPCService_DeleteVM(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.DeleteVM(ctx, &platformv1.DeleteVMRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for empty VM ID", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.DeleteVM(ctx, &platformv1.DeleteVMRequest{Id: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("deletes VM successfully", func(t *testing.T) {
		svc := createTestComputeService(t)

		// Create VM first
		createResp, err := svc.CreateVM(ctx, &platformv1.CreateVMRequest{
			Config: &platformv1.VMConfig{Name: "delete-test"},
		})
		require.NoError(t, err)

		resp, err := svc.DeleteVM(ctx, &platformv1.DeleteVMRequest{
			Id: createResp.Vm.Id,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
	})

	t.Run("handles orchestrator delete error", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()
		orchestrator.deleteFunc = func(ctx context.Context, instanceID string) error {
			return errors.New("delete failed")
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.DeleteVM(ctx, &platformv1.DeleteVMRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestComputeGRPCService_GetVM(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.GetVM(ctx, &platformv1.GetVMRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for empty VM ID", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.GetVM(ctx, &platformv1.GetVMRequest{Id: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns VM by ID", func(t *testing.T) {
		svc := createTestComputeService(t)

		// Create VM first
		createResp, err := svc.CreateVM(ctx, &platformv1.CreateVMRequest{
			Config: &platformv1.VMConfig{Name: "get-test"},
		})
		require.NoError(t, err)

		resp, err := svc.GetVM(ctx, &platformv1.GetVMRequest{
			Id: createResp.Vm.Id,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotNil(t, resp.Vm)
		assert.Equal(t, createResp.Vm.Id, resp.Vm.Id)
	})

	t.Run("returns not found for non-existent VM", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.GetVM(ctx, &platformv1.GetVMRequest{Id: "non-existent"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

func TestComputeGRPCService_ListVMs(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.ListVMs(ctx, &platformv1.ListVMsRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns empty list when no VMs", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.ListVMs(ctx, &platformv1.ListVMsRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Empty(t, resp.Vms)
	})

	t.Run("returns list of VMs", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()

		// Pre-populate with VM instance
		orchestrator.instances["vm-1"] = &compute.Instance{
			ID:        "vm-1",
			Name:      "test-vm-1",
			Type:      compute.ComputeTypeVM,
			State:     compute.StateRunning,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.ListVMs(ctx, &platformv1.ListVMsRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Len(t, resp.Vms, 1)
	})

	t.Run("handles orchestrator list error", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()
		orchestrator.listFunc = func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
			return nil, errors.New("list failed")
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.ListVMs(ctx, &platformv1.ListVMsRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

// =============================================================================
// Container Operation Tests
// =============================================================================

func TestComputeGRPCService_CreateContainer(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.CreateContainer(ctx, &platformv1.CreateContainerRequest{
			Config: &platformv1.ContainerConfig{Image: "nginx:latest"},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil config", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.CreateContainer(ctx, &platformv1.CreateContainerRequest{
			Config: nil,
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty image", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.CreateContainer(ctx, &platformv1.CreateContainerRequest{
			Config: &platformv1.ContainerConfig{Image: ""},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("creates container successfully", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.CreateContainer(ctx, &platformv1.CreateContainerRequest{
			Config: &platformv1.ContainerConfig{
				Name:  "test-container",
				Image: "nginx:latest",
			},
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
		assert.NotNil(t, resp.Container)
	})

	t.Run("handles orchestrator create error", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()
		orchestrator.createFunc = func(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
			return nil, errors.New("create failed")
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.CreateContainer(ctx, &platformv1.CreateContainerRequest{
			Config: &platformv1.ContainerConfig{Image: "nginx:latest"},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestComputeGRPCService_StartContainer(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.StartContainer(ctx, &platformv1.StartContainerRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for empty container ID", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.StartContainer(ctx, &platformv1.StartContainerRequest{Id: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("starts container successfully", func(t *testing.T) {
		svc := createTestComputeService(t)

		// Create container first
		createResp, err := svc.CreateContainer(ctx, &platformv1.CreateContainerRequest{
			Config: &platformv1.ContainerConfig{
				Name:  "start-test",
				Image: "nginx:latest",
			},
		})
		require.NoError(t, err)

		resp, err := svc.StartContainer(ctx, &platformv1.StartContainerRequest{
			Id: createResp.Container.Id,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
	})

	t.Run("handles orchestrator start error", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()
		orchestrator.startFunc = func(ctx context.Context, instanceID string) error {
			return errors.New("start failed")
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.StartContainer(ctx, &platformv1.StartContainerRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestComputeGRPCService_StopContainer(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.StopContainer(ctx, &platformv1.StopContainerRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for empty container ID", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.StopContainer(ctx, &platformv1.StopContainerRequest{Id: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("stops container successfully", func(t *testing.T) {
		svc := createTestComputeService(t)

		// Create and start container first
		createResp, err := svc.CreateContainer(ctx, &platformv1.CreateContainerRequest{
			Config: &platformv1.ContainerConfig{
				Name:  "stop-test",
				Image: "nginx:latest",
			},
		})
		require.NoError(t, err)

		_, err = svc.StartContainer(ctx, &platformv1.StartContainerRequest{Id: createResp.Container.Id})
		require.NoError(t, err)

		resp, err := svc.StopContainer(ctx, &platformv1.StopContainerRequest{
			Id: createResp.Container.Id,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
	})

	t.Run("handles orchestrator stop error", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()
		orchestrator.stopFunc = func(ctx context.Context, instanceID string) error {
			return errors.New("stop failed")
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.StopContainer(ctx, &platformv1.StopContainerRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestComputeGRPCService_DeleteContainer(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.DeleteContainer(ctx, &platformv1.DeleteContainerRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for empty container ID", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.DeleteContainer(ctx, &platformv1.DeleteContainerRequest{Id: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("deletes container successfully", func(t *testing.T) {
		svc := createTestComputeService(t)

		// Create container first
		createResp, err := svc.CreateContainer(ctx, &platformv1.CreateContainerRequest{
			Config: &platformv1.ContainerConfig{
				Name:  "delete-test",
				Image: "nginx:latest",
			},
		})
		require.NoError(t, err)

		resp, err := svc.DeleteContainer(ctx, &platformv1.DeleteContainerRequest{
			Id: createResp.Container.Id,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
	})

	t.Run("handles orchestrator delete error", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()
		orchestrator.deleteFunc = func(ctx context.Context, instanceID string) error {
			return errors.New("delete failed")
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.DeleteContainer(ctx, &platformv1.DeleteContainerRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestComputeGRPCService_GetContainer(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.GetContainer(ctx, &platformv1.GetContainerRequest{Id: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for empty container ID", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.GetContainer(ctx, &platformv1.GetContainerRequest{Id: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns container by ID", func(t *testing.T) {
		svc := createTestComputeService(t)

		// Create container first
		createResp, err := svc.CreateContainer(ctx, &platformv1.CreateContainerRequest{
			Config: &platformv1.ContainerConfig{
				Name:  "get-test",
				Image: "nginx:latest",
			},
		})
		require.NoError(t, err)

		resp, err := svc.GetContainer(ctx, &platformv1.GetContainerRequest{
			Id: createResp.Container.Id,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotNil(t, resp.Container)
		assert.Equal(t, createResp.Container.Id, resp.Container.Id)
	})

	t.Run("returns not found for non-existent container", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.GetContainer(ctx, &platformv1.GetContainerRequest{Id: "non-existent"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

func TestComputeGRPCService_ListContainers(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.ListContainers(ctx, &platformv1.ListContainersRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns empty list when no containers", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.ListContainers(ctx, &platformv1.ListContainersRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Empty(t, resp.Containers)
	})

	t.Run("returns list of containers", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()

		// Pre-populate with container instance
		orchestrator.instances["container-1"] = &compute.Instance{
			ID:        "container-1",
			Name:      "test-container-1",
			Type:      compute.ComputeTypeContainer,
			State:     compute.StateRunning,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.ListContainers(ctx, &platformv1.ListContainersRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Len(t, resp.Containers, 1)
	})

	t.Run("handles orchestrator list error", func(t *testing.T) {
		logger := logging.DefaultLogger()
		orchestrator := newGRPCMockOrchestrator()
		orchestrator.listFunc = func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
			return nil, errors.New("list failed")
		}
		svc := NewComputeGRPCService(logger, orchestrator)

		resp, err := svc.ListContainers(ctx, &platformv1.ListContainersRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

// =============================================================================
// Unimplemented Operations Tests
// =============================================================================

func TestComputeGRPCService_UnimplementedOperations(t *testing.T) {
	svc := createTestComputeService(t)
	ctx := context.Background()

	t.Run("AttachVMConsole capability not supported", func(t *testing.T) {
		err := svc.AttachVMConsole(&platformv1.AttachVMConsoleRequest{}, nil)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("SendVMConsoleInput capability not supported", func(t *testing.T) {
		err := svc.SendVMConsoleInput(nil)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("GetVMLogs capability not supported", func(t *testing.T) {
		err := svc.GetVMLogs(&platformv1.GetVMLogsRequest{}, nil)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("GetVMMetrics capability not supported", func(t *testing.T) {
		resp, err := svc.GetVMMetrics(ctx, &platformv1.GetVMMetricsRequest{})
		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("AttachDisk capability not supported", func(t *testing.T) {
		resp, err := svc.AttachDisk(ctx, &platformv1.AttachDiskRequest{})
		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("DetachDisk capability not supported", func(t *testing.T) {
		resp, err := svc.DetachDisk(ctx, &platformv1.DetachDiskRequest{})
		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("ResizeDisk capability not supported", func(t *testing.T) {
		resp, err := svc.ResizeDisk(ctx, &platformv1.ResizeDiskRequest{})
		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	// VM snapshot and attestation RPCs are implemented; their capability
	// and error-path coverage lives in compute_grpc_service_vm_test.go.

	t.Run("MigrateVM capability not supported", func(t *testing.T) {
		resp, err := svc.MigrateVM(ctx, &platformv1.MigrateVMRequest{VmId: "vm-1", DestinationHost: "dest:10443"})
		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("AttachContainer returns unimplemented when orchestrator lacks capability", func(t *testing.T) {
		err := svc.AttachContainer(&platformv1.AttachContainerRequest{Id: "container-1"}, nil)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

	t.Run("ExecContainer returns unimplemented when orchestrator lacks capability", func(t *testing.T) {
		resp, err := svc.ExecContainer(ctx, &platformv1.ExecContainerRequest{Id: "container-1", Command: []string{"ls"}})
		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

	t.Run("GetContainerLogs requires container ID", func(t *testing.T) {
		err := svc.GetContainerLogs(&platformv1.GetContainerLogsRequest{}, nil)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("GetContainerLogs returns unimplemented when orchestrator lacks log capability", func(t *testing.T) {
		err := svc.GetContainerLogs(&platformv1.GetContainerLogsRequest{Id: "container-1"}, nil)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

	t.Run("GetContainerMetrics returns unimplemented when orchestrator lacks capability", func(t *testing.T) {
		resp, err := svc.GetContainerMetrics(ctx, &platformv1.GetContainerMetricsRequest{Id: "container-1"})
		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestComputeGRPCService_InstanceToVMProto(t *testing.T) {
	svc := createTestComputeService(t)

	t.Run("nil instance returns nil", func(t *testing.T) {
		result := svc.instanceToVMProto(nil)
		assert.Nil(t, result)
	})

	t.Run("converts instance with config to VM proto", func(t *testing.T) {
		instance := &compute.Instance{
			ID:        "vm-123",
			Name:      "test-vm",
			Type:      compute.ComputeTypeVM,
			State:     compute.StateRunning,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Config: &compute.InstanceConfig{
				Memory:     4096,
				CPUs:       4,
				SecureBoot: true,
				TPMEnabled: true,
			},
		}

		result := svc.instanceToVMProto(instance)

		assert.NotNil(t, result)
		assert.Equal(t, "vm-123", result.Id)
		assert.Equal(t, platformv1.VMState_VM_STATE_RUNNING, result.State)
		assert.NotNil(t, result.Config)
		assert.Equal(t, "test-vm", result.Config.Name)
		assert.Equal(t, uint64(4096), result.Config.Memory.SizeMb)
		assert.Equal(t, uint32(4), result.Config.Cpu.Cores)
		assert.True(t, result.Config.SecureBoot)
		assert.NotNil(t, result.Config.Tpm)
		assert.True(t, result.Config.Tpm.Enabled)
	})

	t.Run("converts instance without config to VM proto", func(t *testing.T) {
		instance := &compute.Instance{
			ID:        "vm-456",
			Name:      "test-vm-no-config",
			Type:      compute.ComputeTypeVM,
			State:     compute.StateStopped,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		result := svc.instanceToVMProto(instance)

		assert.NotNil(t, result)
		assert.Equal(t, "vm-456", result.Id)
		assert.Equal(t, platformv1.VMState_VM_STATE_STOPPED, result.State)
		assert.NotNil(t, result.Config)
		assert.Equal(t, "test-vm-no-config", result.Config.Name)
	})
}

func TestComputeGRPCService_InstanceStateToVMState(t *testing.T) {
	svc := createTestComputeService(t)

	tests := []struct {
		name     string
		state    compute.InstanceState
		expected platformv1.VMState
	}{
		{"stopped", compute.StateStopped, platformv1.VMState_VM_STATE_STOPPED},
		{"starting", compute.StateStarting, platformv1.VMState_VM_STATE_STARTING},
		{"running", compute.StateRunning, platformv1.VMState_VM_STATE_RUNNING},
		{"stopping", compute.StateStopping, platformv1.VMState_VM_STATE_STOPPING},
		{"error", compute.StateError, platformv1.VMState_VM_STATE_ERROR},
		{"suspended", compute.StateSuspended, platformv1.VMState_VM_STATE_PAUSED},
		{"unknown", compute.StateUnknown, platformv1.VMState_VM_STATE_UNSPECIFIED},
		{"creating", compute.StateCreating, platformv1.VMState_VM_STATE_UNSPECIFIED},
		{"deleting", compute.StateDeleting, platformv1.VMState_VM_STATE_UNSPECIFIED},
		{"unrecognised value", compute.InstanceState("hibernating"), platformv1.VMState_VM_STATE_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.instanceStateToVMState(tc.state)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestComputeGRPCService_InstanceToContainerProto(t *testing.T) {
	svc := createTestComputeService(t)

	t.Run("nil instance returns nil", func(t *testing.T) {
		result := svc.instanceToContainerProto(nil)
		assert.Nil(t, result)
	})

	t.Run("converts instance with name to container proto", func(t *testing.T) {
		instance := &compute.Instance{
			ID:        "container-123",
			Name:      "test-container",
			Type:      compute.ComputeTypeContainer,
			State:     compute.StateRunning,
			CreatedAt: time.Now(),
		}

		result := svc.instanceToContainerProto(instance)

		assert.NotNil(t, result)
		assert.Equal(t, "container-123", result.Id)
		assert.Equal(t, platformv1.ContainerState_CONTAINER_STATE_RUNNING, result.State)
		assert.NotNil(t, result.Config)
		assert.Equal(t, "test-container", result.Config.Name)
	})

	t.Run("converts instance without name to container proto", func(t *testing.T) {
		instance := &compute.Instance{
			ID:        "container-456",
			Name:      "",
			Type:      compute.ComputeTypeContainer,
			State:     compute.StateStopped,
			CreatedAt: time.Now(),
		}

		result := svc.instanceToContainerProto(instance)

		assert.NotNil(t, result)
		assert.Equal(t, "container-456", result.Id)
		assert.Nil(t, result.Config)
	})
}

func TestComputeGRPCService_InstanceStateToContainerState(t *testing.T) {
	svc := createTestComputeService(t)

	tests := []struct {
		name     string
		state    compute.InstanceState
		expected platformv1.ContainerState
	}{
		{"creating", compute.StateCreating, platformv1.ContainerState_CONTAINER_STATE_CREATED},
		{"starting", compute.StateStarting, platformv1.ContainerState_CONTAINER_STATE_STARTING},
		{"running", compute.StateRunning, platformv1.ContainerState_CONTAINER_STATE_RUNNING},
		{"suspended", compute.StateSuspended, platformv1.ContainerState_CONTAINER_STATE_PAUSED},
		{"stopping", compute.StateStopping, platformv1.ContainerState_CONTAINER_STATE_STOPPING},
		{"stopped", compute.StateStopped, platformv1.ContainerState_CONTAINER_STATE_EXITED},
		{"error", compute.StateError, platformv1.ContainerState_CONTAINER_STATE_ERROR},
		// No proto value: these stay UNSPECIFIED rather than claim a state.
		{"unknown", compute.StateUnknown, platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED},
		{"deleting", compute.StateDeleting, platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED},
		{"unrecognised value", compute.InstanceState("hibernating"), platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED},
		{"empty value", compute.InstanceState(""), platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.instanceStateToContainerState(tc.state)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestComputeGRPCService_ContainerProtoReportsSuspendedAsPaused pins the
// #704 parity defect: a suspended workload read through the container view
// was UNSPECIFIED while the VM view said PAUSED.
func TestComputeGRPCService_ContainerProtoReportsSuspendedAsPaused(t *testing.T) {
	svc := createTestComputeService(t)
	instance := &compute.Instance{ID: "c-1", Name: "web", State: compute.StateSuspended}

	assert.Equal(t, platformv1.ContainerState_CONTAINER_STATE_PAUSED, svc.instanceToContainerProto(instance).GetState())
	assert.Equal(t, platformv1.VMState_VM_STATE_PAUSED, svc.instanceToVMProto(instance).GetState())
}
