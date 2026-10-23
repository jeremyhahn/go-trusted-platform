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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// mockOrchestrator implements compute.Orchestrator for testing.
type mockOrchestrator struct {
	createFunc        func(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error)
	startFunc         func(ctx context.Context, instanceID string) error
	stopFunc          func(ctx context.Context, instanceID string) error
	deleteFunc        func(ctx context.Context, instanceID string) error
	listFunc          func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error)
	getFunc           func(ctx context.Context, instanceID string) (*compute.Instance, error)
	attachNetworkFunc func(ctx context.Context, instanceID, portName string) error
	detachNetworkFunc func(ctx context.Context, instanceID, portName string) error
	activateFunc      func(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error
	waitFunc          func(ctx context.Context, instanceID string) error
	getStateFunc      func(ctx context.Context, instanceID string) (compute.InstanceState, error)
	closeFunc         func() error
}

func (m *mockOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, profile)
	}
	return &compute.Instance{
		ID:        "test-id",
		Name:      profile.Name,
		Type:      compute.ComputeTypeContainer,
		State:     compute.StateCreating,
		Profile:   profile,
		CreatedAt: time.Now(),
	}, nil
}

func (m *mockOrchestrator) Start(ctx context.Context, instanceID string) error {
	if m.startFunc != nil {
		return m.startFunc(ctx, instanceID)
	}
	return nil
}

func (m *mockOrchestrator) Stop(ctx context.Context, instanceID string) error {
	if m.stopFunc != nil {
		return m.stopFunc(ctx, instanceID)
	}
	return nil
}

func (m *mockOrchestrator) Delete(ctx context.Context, instanceID string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, instanceID)
	}
	return nil
}

func (m *mockOrchestrator) List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, filter)
	}
	return []*compute.Instance{}, nil
}

func (m *mockOrchestrator) Get(ctx context.Context, instanceID string) (*compute.Instance, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, instanceID)
	}
	return &compute.Instance{
		ID:        instanceID,
		Name:      "test-container",
		Type:      compute.ComputeTypeContainer,
		State:     compute.StateRunning,
		CreatedAt: time.Now(),
	}, nil
}

func (m *mockOrchestrator) AttachNetwork(ctx context.Context, instanceID, portName string) error {
	if m.attachNetworkFunc != nil {
		return m.attachNetworkFunc(ctx, instanceID, portName)
	}
	return nil
}

func (m *mockOrchestrator) DetachNetwork(ctx context.Context, instanceID, portName string) error {
	if m.detachNetworkFunc != nil {
		return m.detachNetworkFunc(ctx, instanceID, portName)
	}
	return nil
}

func (m *mockOrchestrator) ActivateInstance(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error {
	if m.activateFunc != nil {
		return m.activateFunc(ctx, instanceID, portPolicy)
	}
	return nil
}

func (m *mockOrchestrator) Wait(ctx context.Context, instanceID string) error {
	if m.waitFunc != nil {
		return m.waitFunc(ctx, instanceID)
	}
	return nil
}

func (m *mockOrchestrator) GetState(ctx context.Context, instanceID string) (compute.InstanceState, error) {
	if m.getStateFunc != nil {
		return m.getStateFunc(ctx, instanceID)
	}
	return compute.StateRunning, nil
}

func (m *mockOrchestrator) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func TestNewOrchestratorAdapter(t *testing.T) {
	t.Run("success with valid orchestrator", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, err := NewOrchestratorAdapter(mock)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if adapter == nil {
			t.Fatal("expected adapter to not be nil")
		}
		if adapter.orchestrator != mock {
			t.Error("expected adapter to wrap the provided orchestrator")
		}
	})

	t.Run("error with nil orchestrator", func(t *testing.T) {
		adapter, err := NewOrchestratorAdapter(nil)
		if err == nil {
			t.Fatal("expected error for nil orchestrator")
		}
		if adapter != nil {
			t.Error("expected adapter to be nil on error")
		}
		var errNil ErrNilOrchestrator
		if !errors.As(err, &errNil) {
			t.Errorf("expected ErrNilOrchestrator, got: %T", err)
		}
	})
}

func TestOrchestratorAdapter_Create(t *testing.T) {
	t.Run("success with valid spec", func(t *testing.T) {
		mock := &mockOrchestrator{
			createFunc: func(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
				return &compute.Instance{
					ID:        "container-123",
					Name:      profile.Name,
					Type:      compute.ComputeTypeContainer,
					State:     compute.StateCreating,
					Profile:   profile,
					CreatedAt: time.Now(),
					PID:       12345,
					Metadata:  map[string]string{"key": "value"},
				}, nil
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		spec := &container.OrchestratorContainerSpec{
			Name:   "test-container",
			Image:  "nginx:latest",
			Labels: map[string]string{"env": "test"},
		}

		c, err := adapter.Create(context.Background(), spec)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if c == nil {
			t.Fatal("expected container to not be nil")
		}
		if c.ID != "container-123" {
			t.Errorf("expected ID 'container-123', got: %s", c.ID)
		}
		if c.Name != "test-container" {
			t.Errorf("expected Name 'test-container', got: %s", c.Name)
		}
		if c.Image != "nginx:latest" {
			t.Errorf("expected Image 'nginx:latest', got: %s", c.Image)
		}
		if c.Pid != 12345 {
			t.Errorf("expected PID 12345, got: %d", c.Pid)
		}
	})

	t.Run("error with nil spec", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		c, err := adapter.Create(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil spec")
		}
		if c != nil {
			t.Error("expected container to be nil on error")
		}
		if !errors.Is(err, container.ErrInvalidSpec) {
			t.Errorf("expected ErrInvalidSpec, got: %v", err)
		}
	})

	t.Run("error with invalid spec", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		spec := &container.OrchestratorContainerSpec{
			Name:  "", // Invalid: empty name
			Image: "nginx:latest",
		}

		c, err := adapter.Create(context.Background(), spec)
		if err == nil {
			t.Fatal("expected error for invalid spec")
		}
		if c != nil {
			t.Error("expected container to be nil on error")
		}
	})

	t.Run("error from orchestrator", func(t *testing.T) {
		expectedErr := errors.New("orchestrator create failed")
		mock := &mockOrchestrator{
			createFunc: func(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
				return nil, expectedErr
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		spec := &container.OrchestratorContainerSpec{
			Name:  "test-container",
			Image: "nginx:latest",
		}

		c, err := adapter.Create(context.Background(), spec)
		if err == nil {
			t.Fatal("expected error from orchestrator")
		}
		if c != nil {
			t.Error("expected container to be nil on error")
		}
		var opErr *ErrContainerOperationFailed
		if !errors.As(err, &opErr) {
			t.Errorf("expected ErrContainerOperationFailed, got: %T", err)
		}
	})
}

func TestOrchestratorAdapter_Start(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		startCalled := false
		mock := &mockOrchestrator{
			startFunc: func(ctx context.Context, instanceID string) error {
				startCalled = true
				if instanceID != "container-123" {
					t.Errorf("expected instanceID 'container-123', got: %s", instanceID)
				}
				return nil
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.Start(context.Background(), "container-123")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !startCalled {
			t.Error("expected start to be called")
		}
	})

	t.Run("error with empty id", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.Start(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty id")
		}
		if !errors.Is(err, container.ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got: %v", err)
		}
	})

	t.Run("error from orchestrator", func(t *testing.T) {
		expectedErr := errors.New("start failed")
		mock := &mockOrchestrator{
			startFunc: func(ctx context.Context, instanceID string) error {
				return expectedErr
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.Start(context.Background(), "container-123")
		if err == nil {
			t.Fatal("expected error from orchestrator")
		}
		var opErr *ErrContainerOperationFailed
		if !errors.As(err, &opErr) {
			t.Errorf("expected ErrContainerOperationFailed, got: %T", err)
		}
	})
}

func TestOrchestratorAdapter_Stop(t *testing.T) {
	t.Run("success ignoring timeout", func(t *testing.T) {
		stopCalled := false
		mock := &mockOrchestrator{
			stopFunc: func(ctx context.Context, instanceID string) error {
				stopCalled = true
				if instanceID != "container-123" {
					t.Errorf("expected instanceID 'container-123', got: %s", instanceID)
				}
				return nil
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.Stop(context.Background(), "container-123", 30*time.Second)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !stopCalled {
			t.Error("expected stop to be called")
		}
	})

	t.Run("error with empty id", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.Stop(context.Background(), "", 30*time.Second)
		if err == nil {
			t.Fatal("expected error for empty id")
		}
		if !errors.Is(err, container.ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got: %v", err)
		}
	})

	t.Run("error from orchestrator", func(t *testing.T) {
		expectedErr := errors.New("stop failed")
		mock := &mockOrchestrator{
			stopFunc: func(ctx context.Context, instanceID string) error {
				return expectedErr
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.Stop(context.Background(), "container-123", 10*time.Second)
		if err == nil {
			t.Fatal("expected error from orchestrator")
		}
		var opErr *ErrContainerOperationFailed
		if !errors.As(err, &opErr) {
			t.Errorf("expected ErrContainerOperationFailed, got: %T", err)
		}
	})
}

func TestOrchestratorAdapter_Remove(t *testing.T) {
	t.Run("success ignoring force", func(t *testing.T) {
		deleteCalled := false
		mock := &mockOrchestrator{
			deleteFunc: func(ctx context.Context, instanceID string) error {
				deleteCalled = true
				if instanceID != "container-123" {
					t.Errorf("expected instanceID 'container-123', got: %s", instanceID)
				}
				return nil
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.Remove(context.Background(), "container-123", true)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !deleteCalled {
			t.Error("expected delete to be called")
		}
	})

	t.Run("error with empty id", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.Remove(context.Background(), "", false)
		if err == nil {
			t.Fatal("expected error for empty id")
		}
		if !errors.Is(err, container.ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got: %v", err)
		}
	})

	t.Run("error from orchestrator", func(t *testing.T) {
		expectedErr := errors.New("delete failed")
		mock := &mockOrchestrator{
			deleteFunc: func(ctx context.Context, instanceID string) error {
				return expectedErr
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.Remove(context.Background(), "container-123", false)
		if err == nil {
			t.Fatal("expected error from orchestrator")
		}
		var opErr *ErrContainerOperationFailed
		if !errors.As(err, &opErr) {
			t.Errorf("expected ErrContainerOperationFailed, got: %T", err)
		}
	})
}

func TestOrchestratorAdapter_Get(t *testing.T) {
	t.Run("success with network attachments", func(t *testing.T) {
		mock := &mockOrchestrator{
			getFunc: func(ctx context.Context, instanceID string) (*compute.Instance, error) {
				return &compute.Instance{
					ID:        instanceID,
					Name:      "test-container",
					Type:      compute.ComputeTypeContainer,
					State:     compute.StateRunning,
					CreatedAt: time.Now(),
					PID:       9876,
					Profile: &entities.DeviceProfile{
						Name:  "test-container",
						Model: "nginx:latest",
					},
					NetworkAttachments: []compute.NetworkAttachment{
						{
							PortName:   "eth0",
							BridgeName: "br0",
							IPAddress:  "192.168.1.100",
							MACAddress: "00:11:22:33:44:55",
						},
					},
					Metadata: map[string]string{"key": "value"},
				}, nil
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		c, err := adapter.Get(context.Background(), "container-123")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if c == nil {
			t.Fatal("expected container to not be nil")
		}
		if c.ID != "container-123" {
			t.Errorf("expected ID 'container-123', got: %s", c.ID)
		}
		if c.Name != "test-container" {
			t.Errorf("expected Name 'test-container', got: %s", c.Name)
		}
		if c.Image != "nginx:latest" {
			t.Errorf("expected Image 'nginx:latest', got: %s", c.Image)
		}
		if c.State != container.StateRunning {
			t.Errorf("expected State 'running', got: %s", c.State)
		}
		if c.NetworkSettings == nil {
			t.Fatal("expected NetworkSettings to not be nil")
		}
		if c.NetworkSettings.IPAddress != "192.168.1.100" {
			t.Errorf("expected IPAddress '192.168.1.100', got: %s", c.NetworkSettings.IPAddress)
		}
		if c.NetworkSettings.MACAddress != "00:11:22:33:44:55" {
			t.Errorf("expected MACAddress '00:11:22:33:44:55', got: %s", c.NetworkSettings.MACAddress)
		}
	})

	t.Run("error with empty id", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		c, err := adapter.Get(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty id")
		}
		if c != nil {
			t.Error("expected container to be nil on error")
		}
		if !errors.Is(err, container.ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got: %v", err)
		}
	})

	t.Run("error from orchestrator", func(t *testing.T) {
		expectedErr := errors.New("get failed")
		mock := &mockOrchestrator{
			getFunc: func(ctx context.Context, instanceID string) (*compute.Instance, error) {
				return nil, expectedErr
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		c, err := adapter.Get(context.Background(), "container-123")
		if err == nil {
			t.Fatal("expected error from orchestrator")
		}
		if c != nil {
			t.Error("expected container to be nil on error")
		}
		var opErr *ErrContainerOperationFailed
		if !errors.As(err, &opErr) {
			t.Errorf("expected ErrContainerOperationFailed, got: %T", err)
		}
	})
}

func TestOrchestratorAdapter_List(t *testing.T) {
	t.Run("success filtering containers only", func(t *testing.T) {
		mock := &mockOrchestrator{
			listFunc: func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
				return []*compute.Instance{
					{
						ID:    "container-1",
						Name:  "web",
						Type:  compute.ComputeTypeContainer,
						State: compute.StateRunning,
					},
					{
						ID:    "vm-1",
						Name:  "database",
						Type:  compute.ComputeTypeVM, // Should be filtered out
						State: compute.StateRunning,
					},
					{
						ID:    "container-2",
						Name:  "api",
						Type:  compute.ComputeTypeContainer,
						State: compute.StateStopped,
					},
				}, nil
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		containers, err := adapter.List(context.Background(), container.ListOptions{All: true})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(containers) != 2 {
			t.Fatalf("expected 2 containers, got: %d", len(containers))
		}
		if containers[0].ID != "container-1" {
			t.Errorf("expected first container ID 'container-1', got: %s", containers[0].ID)
		}
		if containers[1].ID != "container-2" {
			t.Errorf("expected second container ID 'container-2', got: %s", containers[1].ID)
		}
	})

	t.Run("success with limit", func(t *testing.T) {
		mock := &mockOrchestrator{
			listFunc: func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
				return []*compute.Instance{
					{ID: "c1", Type: compute.ComputeTypeContainer},
					{ID: "c2", Type: compute.ComputeTypeContainer},
					{ID: "c3", Type: compute.ComputeTypeContainer},
					{ID: "c4", Type: compute.ComputeTypeContainer},
				}, nil
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		containers, err := adapter.List(context.Background(), container.ListOptions{All: true, Limit: 2})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(containers) != 2 {
			t.Errorf("expected 2 containers, got: %d", len(containers))
		}
	})

	t.Run("success with name filter", func(t *testing.T) {
		var capturedFilter *compute.InstanceFilter
		mock := &mockOrchestrator{
			listFunc: func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
				capturedFilter = filter
				return []*compute.Instance{}, nil
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		_, err := adapter.List(context.Background(), container.ListOptions{
			Filters: map[string][]string{"name": {"web-server"}},
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if capturedFilter == nil {
			t.Fatal("expected filter to be captured")
		}
		if capturedFilter.Name != "web-server" {
			t.Errorf("expected Name filter 'web-server', got: %s", capturedFilter.Name)
		}
	})

	t.Run("error from orchestrator", func(t *testing.T) {
		expectedErr := errors.New("list failed")
		mock := &mockOrchestrator{
			listFunc: func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
				return nil, expectedErr
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		containers, err := adapter.List(context.Background(), container.ListOptions{})
		if err == nil {
			t.Fatal("expected error from orchestrator")
		}
		if containers != nil {
			t.Error("expected containers to be nil on error")
		}
		var opErr *ErrContainerOperationFailed
		if !errors.As(err, &opErr) {
			t.Errorf("expected ErrContainerOperationFailed, got: %T", err)
		}
	})
}

func TestOrchestratorAdapter_Logs(t *testing.T) {
	t.Run("error not supported", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		reader, err := adapter.Logs(context.Background(), "container-123", container.LogOptions{})
		if err == nil {
			t.Fatal("expected error for unsupported operation")
		}
		if reader != nil {
			t.Error("expected reader to be nil")
		}
		var logsErr ErrLogsNotSupported
		if !errors.As(err, &logsErr) {
			t.Errorf("expected ErrLogsNotSupported, got: %T", err)
		}
	})

	t.Run("error with empty id", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		reader, err := adapter.Logs(context.Background(), "", container.LogOptions{})
		if err == nil {
			t.Fatal("expected error for empty id")
		}
		if reader != nil {
			t.Error("expected reader to be nil")
		}
		if !errors.Is(err, container.ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got: %v", err)
		}
	})
}

func TestOrchestratorAdapter_Attest(t *testing.T) {
	t.Run("error not supported", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		report, err := adapter.Attest(context.Background(), "container-123")
		if err == nil {
			t.Fatal("expected error for unsupported operation")
		}
		if report != nil {
			t.Error("expected report to be nil")
		}
		var attestErr ErrAttestNotSupported
		if !errors.As(err, &attestErr) {
			t.Errorf("expected ErrAttestNotSupported, got: %T", err)
		}
	})

	t.Run("error with empty id", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		report, err := adapter.Attest(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty id")
		}
		if report != nil {
			t.Error("expected report to be nil")
		}
		if !errors.Is(err, container.ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got: %v", err)
		}
	})
}

func TestOrchestratorAdapter_VerifyAttestation(t *testing.T) {
	t.Run("error not supported", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.VerifyAttestation(context.Background(), "container-123", []byte("evidence"))
		if err == nil {
			t.Fatal("expected error for unsupported operation")
		}
		var verifyErr ErrVerifyAttestationNotSupported
		if !errors.As(err, &verifyErr) {
			t.Errorf("expected ErrVerifyAttestationNotSupported, got: %T", err)
		}
	})

	t.Run("error with empty id", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.VerifyAttestation(context.Background(), "", []byte("evidence"))
		if err == nil {
			t.Fatal("expected error for empty id")
		}
		if !errors.Is(err, container.ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got: %v", err)
		}
	})
}

func TestOrchestratorAdapter_EvaluatePolicy(t *testing.T) {
	t.Run("error not supported", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		spec := &container.OrchestratorContainerSpec{
			Name:  "test",
			Image: "nginx:latest",
		}

		decision, err := adapter.EvaluatePolicy(context.Background(), spec)
		if err == nil {
			t.Fatal("expected error for unsupported operation")
		}
		if decision != nil {
			t.Error("expected decision to be nil")
		}
		var policyErr ErrEvaluatePolicyNotSupported
		if !errors.As(err, &policyErr) {
			t.Errorf("expected ErrEvaluatePolicyNotSupported, got: %T", err)
		}
	})

	t.Run("error with nil spec", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		decision, err := adapter.EvaluatePolicy(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil spec")
		}
		if decision != nil {
			t.Error("expected decision to be nil")
		}
		if !errors.Is(err, container.ErrInvalidSpec) {
			t.Errorf("expected ErrInvalidSpec, got: %v", err)
		}
	})
}

func TestOrchestratorAdapter_PullImage(t *testing.T) {
	t.Run("error not supported", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.PullImage(context.Background(), "nginx:latest", container.PullOptions{})
		if err == nil {
			t.Fatal("expected error for unsupported operation")
		}
		var pullErr ErrPullImageNotSupported
		if !errors.As(err, &pullErr) {
			t.Errorf("expected ErrPullImageNotSupported, got: %T", err)
		}
	})

	t.Run("error with empty ref", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.PullImage(context.Background(), "", container.PullOptions{})
		if err == nil {
			t.Fatal("expected error for empty ref")
		}
		if !errors.Is(err, container.ErrInvalidImage) {
			t.Errorf("expected ErrInvalidImage, got: %v", err)
		}
	})
}

func TestOrchestratorAdapter_VerifyImage(t *testing.T) {
	t.Run("error not supported", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		verification, err := adapter.VerifyImage(context.Background(), "nginx:latest")
		if err == nil {
			t.Fatal("expected error for unsupported operation")
		}
		if verification != nil {
			t.Error("expected verification to be nil")
		}
		var verifyErr ErrVerifyImageNotSupported
		if !errors.As(err, &verifyErr) {
			t.Errorf("expected ErrVerifyImageNotSupported, got: %T", err)
		}
	})

	t.Run("error with empty ref", func(t *testing.T) {
		mock := &mockOrchestrator{}
		adapter, _ := NewOrchestratorAdapter(mock)

		verification, err := adapter.VerifyImage(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty ref")
		}
		if verification != nil {
			t.Error("expected verification to be nil")
		}
		if !errors.Is(err, container.ErrInvalidImage) {
			t.Errorf("expected ErrInvalidImage, got: %v", err)
		}
	})
}

func TestOrchestratorAdapter_Close(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		closeCalled := false
		mock := &mockOrchestrator{
			closeFunc: func() error {
				closeCalled = true
				return nil
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.Close()
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !closeCalled {
			t.Error("expected close to be called")
		}
	})

	t.Run("error from orchestrator", func(t *testing.T) {
		expectedErr := errors.New("close failed")
		mock := &mockOrchestrator{
			closeFunc: func() error {
				return expectedErr
			},
		}
		adapter, _ := NewOrchestratorAdapter(mock)

		err := adapter.Close()
		if err == nil {
			t.Fatal("expected error from orchestrator")
		}
		if err != expectedErr {
			t.Errorf("expected error '%v', got: %v", expectedErr, err)
		}
	})
}

func TestInstanceStateToContainerState(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.InstanceState
		expected container.ContainerState
	}{
		{"unknown", compute.StateUnknown, container.StateCreated},
		{"creating", compute.StateCreating, container.StateCreated},
		{"stopped", compute.StateStopped, container.StateStopped},
		{"starting", compute.StateStarting, container.StateRestarting},
		{"running", compute.StateRunning, container.StateRunning},
		{"stopping", compute.StateStopping, container.StateStopped},
		{"error", compute.StateError, container.StateDead},
		{"deleting", compute.StateDeleting, container.StateRemoving},
		{"suspended", compute.StateSuspended, container.StatePaused},
		{"invalid", compute.InstanceState("invalid"), container.StateCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := instanceStateToContainerState(tt.input)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestSpecToDeviceProfile(t *testing.T) {
	spec := &container.OrchestratorContainerSpec{
		Name:  "web-server",
		Image: "nginx:1.25",
	}

	profile := specToDeviceProfile(spec)
	if profile == nil {
		t.Fatal("expected profile to not be nil")
	}
	if profile.Name != "web-server" {
		t.Errorf("expected Name 'web-server', got: %s", profile.Name)
	}
	if profile.Model != "nginx:1.25" {
		t.Errorf("expected Model 'nginx:1.25', got: %s", profile.Model)
	}
	if profile.Role != entities.DeviceRoleServer {
		t.Errorf("expected Role 'server', got: %s", profile.Role)
	}
}

func TestInstanceToContainer(t *testing.T) {
	t.Run("nil instance returns nil", func(t *testing.T) {
		result := instanceToContainer(nil, nil)
		if result != nil {
			t.Error("expected nil for nil instance")
		}
	})

	t.Run("full conversion", func(t *testing.T) {
		now := time.Now()
		instance := &compute.Instance{
			ID:        "inst-123",
			Name:      "my-container",
			Type:      compute.ComputeTypeContainer,
			State:     compute.StateRunning,
			CreatedAt: now,
			PID:       54321,
			Profile: &entities.DeviceProfile{
				Name:  "my-container",
				Model: "redis:7",
			},
			NetworkAttachments: []compute.NetworkAttachment{
				{
					PortName:   "eth0",
					BridgeName: "ovs-br0",
					IPAddress:  "10.0.0.5",
					MACAddress: "aa:bb:cc:dd:ee:ff",
				},
				{
					PortName:   "eth1",
					BridgeName: "ovs-br1",
					IPAddress:  "10.0.1.5",
					MACAddress: "11:22:33:44:55:66",
				},
			},
			Metadata: map[string]string{"env": "prod"},
		}

		spec := &container.OrchestratorContainerSpec{
			Name:  "my-container",
			Image: "redis:7",
		}

		c := instanceToContainer(instance, spec)
		if c == nil {
			t.Fatal("expected container to not be nil")
		}
		if c.ID != "inst-123" {
			t.Errorf("expected ID 'inst-123', got: %s", c.ID)
		}
		if c.Name != "my-container" {
			t.Errorf("expected Name 'my-container', got: %s", c.Name)
		}
		if c.Image != "redis:7" {
			t.Errorf("expected Image 'redis:7', got: %s", c.Image)
		}
		if c.State != container.StateRunning {
			t.Errorf("expected State 'running', got: %s", c.State)
		}
		if c.Pid != 54321 {
			t.Errorf("expected PID 54321, got: %d", c.Pid)
		}
		if !c.CreatedAt.Equal(now) {
			t.Errorf("expected CreatedAt %v, got: %v", now, c.CreatedAt)
		}
		if c.Labels["env"] != "prod" {
			t.Errorf("expected label 'env=prod', got: %s", c.Labels["env"])
		}
		if c.Spec != spec {
			t.Error("expected Spec to be the provided spec")
		}

		// Check network settings
		if c.NetworkSettings == nil {
			t.Fatal("expected NetworkSettings to not be nil")
		}
		if c.NetworkSettings.IPAddress != "10.0.0.5" {
			t.Errorf("expected IPAddress '10.0.0.5', got: %s", c.NetworkSettings.IPAddress)
		}
		if c.NetworkSettings.MACAddress != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("expected MACAddress 'aa:bb:cc:dd:ee:ff', got: %s", c.NetworkSettings.MACAddress)
		}
		if len(c.NetworkSettings.Networks) != 2 {
			t.Errorf("expected 2 networks, got: %d", len(c.NetworkSettings.Networks))
		}
		eth0 := c.NetworkSettings.Networks["eth0"]
		if eth0 == nil {
			t.Fatal("expected eth0 network to exist")
		}
		if eth0.NetworkID != "ovs-br0" {
			t.Errorf("expected NetworkID 'ovs-br0', got: %s", eth0.NetworkID)
		}
	})
}

func TestListOptionsToInstanceFilter(t *testing.T) {
	t.Run("all true", func(t *testing.T) {
		opts := container.ListOptions{All: true}
		filter := listOptionsToInstanceFilter(opts)
		if filter == nil {
			t.Fatal("expected filter to not be nil")
		}
		if filter.Type == nil || *filter.Type != compute.ComputeTypeContainer {
			t.Error("expected Type filter to be container")
		}
		if filter.State != nil {
			t.Error("expected State filter to be nil when All is true")
		}
	})

	t.Run("all false filters running only", func(t *testing.T) {
		opts := container.ListOptions{All: false}
		filter := listOptionsToInstanceFilter(opts)
		if filter == nil {
			t.Fatal("expected filter to not be nil")
		}
		if filter.State == nil || *filter.State != compute.StateRunning {
			t.Error("expected State filter to be running when All is false")
		}
	})

	t.Run("with name filter", func(t *testing.T) {
		opts := container.ListOptions{
			All:     true,
			Filters: map[string][]string{"name": {"my-container", "other"}},
		}
		filter := listOptionsToInstanceFilter(opts)
		if filter.Name != "my-container" {
			t.Errorf("expected Name filter 'my-container', got: %s", filter.Name)
		}
	})

	t.Run("with empty filters map", func(t *testing.T) {
		opts := container.ListOptions{
			All:     true,
			Filters: map[string][]string{},
		}
		filter := listOptionsToInstanceFilter(opts)
		if filter.Name != "" {
			t.Errorf("expected empty Name filter, got: %s", filter.Name)
		}
	})
}

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		err      error
		expected string
	}{
		{ErrNilOrchestrator{}, "orchestrator cannot be nil"},
		{ErrLogsNotSupported{}, "container logs operation not supported by orchestrator adapter"},
		{ErrAttestNotSupported{}, "container attestation operation not supported by orchestrator adapter"},
		{ErrVerifyAttestationNotSupported{}, "verify attestation operation not supported by orchestrator adapter"},
		{ErrEvaluatePolicyNotSupported{}, "evaluate policy operation not supported by orchestrator adapter"},
		{ErrPullImageNotSupported{}, "pull image operation not supported by orchestrator adapter"},
		{ErrVerifyImageNotSupported{}, "verify image operation not supported by orchestrator adapter"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, tt.err.Error())
			}
		})
	}
}
