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
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockComputeOrchestrator is a mock implementation of compute.Orchestrator for testing
type MockComputeOrchestrator struct {
	mock.Mock
}

func (m *MockComputeOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
	args := m.Called(ctx, profile)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*compute.Instance), args.Error(1)
}

func (m *MockComputeOrchestrator) Start(ctx context.Context, instanceID string) error {
	args := m.Called(ctx, instanceID)
	return args.Error(0)
}

func (m *MockComputeOrchestrator) Stop(ctx context.Context, instanceID string) error {
	args := m.Called(ctx, instanceID)
	return args.Error(0)
}

func (m *MockComputeOrchestrator) Delete(ctx context.Context, instanceID string) error {
	args := m.Called(ctx, instanceID)
	return args.Error(0)
}

func (m *MockComputeOrchestrator) List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*compute.Instance), args.Error(1)
}

func (m *MockComputeOrchestrator) Get(ctx context.Context, instanceID string) (*compute.Instance, error) {
	args := m.Called(ctx, instanceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*compute.Instance), args.Error(1)
}

func (m *MockComputeOrchestrator) AttachNetwork(ctx context.Context, instanceID, portName string) error {
	args := m.Called(ctx, instanceID, portName)
	return args.Error(0)
}

func (m *MockComputeOrchestrator) DetachNetwork(ctx context.Context, instanceID, portName string) error {
	args := m.Called(ctx, instanceID, portName)
	return args.Error(0)
}

func (m *MockComputeOrchestrator) ActivateInstance(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error {
	args := m.Called(ctx, instanceID, portPolicy)
	return args.Error(0)
}

func (m *MockComputeOrchestrator) Wait(ctx context.Context, instanceID string) error {
	args := m.Called(ctx, instanceID)
	return args.Error(0)
}

func (m *MockComputeOrchestrator) GetState(ctx context.Context, instanceID string) (compute.InstanceState, error) {
	args := m.Called(ctx, instanceID)
	return args.Get(0).(compute.InstanceState), args.Error(1)
}

func (m *MockComputeOrchestrator) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestMCPContainerCreate_Success(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	expectedInstance := &compute.Instance{
		ID:        "container-123",
		Name:      "test-container",
		Type:      compute.ComputeTypeContainer,
		State:     compute.StateCreating,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockOrchestrator.On("Create", mock.Anything, mock.MatchedBy(func(p *entities.DeviceProfile) bool {
		return p.Name == "test-container" && p.Model == "container:image=nginx:latest"
	})).Return(expectedInstance, nil)

	result, err := provider.ContainerCreate(context.Background(), "test-container", "nginx:latest", nil)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	resultMap, ok := result.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "container-123", resultMap["id"])
	assert.Equal(t, "test-container", resultMap["name"])
	mockOrchestrator.AssertExpectations(t)
}

// attestingMCPOrchestrator is a MockComputeOrchestrator that can also attest,
// the capability attest-on-create asks of the orchestrator.
type attestingMCPOrchestrator struct {
	*MockComputeOrchestrator
	attestErr error
	attested  []string
}

func (m *attestingMCPOrchestrator) Attest(_ context.Context, id string) (*container.AttestationReport, error) {
	m.attested = append(m.attested, id)
	if m.attestErr != nil {
		return nil, m.attestErr
	}
	return &container.AttestationReport{ContainerID: id, Verified: true}, nil
}

func newCreatedContainerInstance() *compute.Instance {
	return &compute.Instance{
		ID:        "container-123",
		Name:      "test-container",
		Type:      compute.ComputeTypeContainer,
		State:     compute.StateStopped,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestMCPContainerCreate_AttestOnCreate(t *testing.T) {
	tests := []struct {
		name         string
		config       map[string]interface{}
		attestErr    error
		wantAttested []string
		wantStatus   map[string]interface{}
	}{
		{
			name:         "attests the created container when asked",
			config:       map[string]interface{}{"attest_on_create": true},
			wantAttested: []string{"container-123"},
			wantStatus:   map[string]interface{}{"success": true, "message": "Container created successfully"},
		},
		{
			name:         "reports a failed attestation as not a success",
			config:       map[string]interface{}{"attest_on_create": true},
			attestErr:    errors.New("quote verification failed"),
			wantAttested: []string{"container-123"},
			wantStatus: map[string]interface{}{
				"success": false,
				"message": "Container created but attestation failed: quote verification failed",
			},
		},
		{
			name:       "does not attest when not asked",
			config:     nil,
			wantStatus: map[string]interface{}{"success": true, "message": "Container created successfully"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orchestrator := &attestingMCPOrchestrator{
				MockComputeOrchestrator: new(MockComputeOrchestrator),
				attestErr:               tt.attestErr,
			}
			orchestrator.On("Create", mock.Anything, mock.Anything).Return(newCreatedContainerInstance(), nil)
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				ComputeOrchestrator: orchestrator,
				Logger:              slog.Default(),
			})

			result, err := provider.ContainerCreate(context.Background(), "test-container", "nginx:latest", tt.config)

			assert.NoError(t, err)
			resultMap, ok := result.(map[string]interface{})
			assert.True(t, ok)
			assert.Equal(t, "container-123", resultMap["id"])
			assert.Equal(t, tt.wantStatus, resultMap["status"])
			assert.Equal(t, tt.wantAttested, orchestrator.attested)
			orchestrator.AssertExpectations(t)
		})
	}
}

func TestMCPContainerCreate_AttestOnCreateUnsupportedCreatesNothing(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	result, err := provider.ContainerCreate(context.Background(), "test-container", "nginx:latest",
		map[string]interface{}{"attest_on_create": true})

	assert.Nil(t, result)
	assert.True(t, errors.As(err, new(ErrContainerAttestNotSupported)))
	mockOrchestrator.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestMCPContainerCreate_NoInstance(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	mockOrchestrator.On("Create", mock.Anything, mock.Anything).Return(nil, nil)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	result, err := provider.ContainerCreate(context.Background(), "test-container", "nginx:latest", nil)

	assert.Nil(t, result)
	assert.True(t, errors.As(err, new(ErrContainerOperationFailed)))
	assert.True(t, errors.As(err, new(ErrContainerCreateNoInstance)))
	mockOrchestrator.AssertExpectations(t)
}

func TestMCPContainerCreate_OrchestratorNotConfigured(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	result, err := provider.ContainerCreate(context.Background(), "test", "nginx:latest", nil)

	assert.Nil(t, result)
	assert.Error(t, err)
	var containerErr ErrContainerServiceNotAvailable
	assert.True(t, errors.As(err, &containerErr))
}

func TestMCPContainerCreate_EmptyName(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	result, err := provider.ContainerCreate(context.Background(), "", "nginx:latest", nil)

	assert.Nil(t, result)
	assert.Error(t, err)
	var paramErr ErrContainerInvalidParameter
	assert.True(t, errors.As(err, &paramErr))
	assert.Equal(t, "name", paramErr.Parameter)
}

func TestMCPContainerCreate_EmptyImage(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	result, err := provider.ContainerCreate(context.Background(), "test", "", nil)

	assert.Nil(t, result)
	assert.Error(t, err)
	var paramErr ErrContainerInvalidParameter
	assert.True(t, errors.As(err, &paramErr))
	assert.Equal(t, "image", paramErr.Parameter)
}

func TestMCPContainerCreate_OrchestratorError(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	mockOrchestrator.On("Create", mock.Anything, mock.Anything).Return(nil, errors.New("orchestrator error"))

	result, err := provider.ContainerCreate(context.Background(), "test", "nginx:latest", nil)

	assert.Nil(t, result)
	assert.Error(t, err)
	var opErr ErrContainerOperationFailed
	assert.True(t, errors.As(err, &opErr))
	assert.Equal(t, "create", opErr.Operation)
	mockOrchestrator.AssertExpectations(t)
}

func TestMCPContainerStart_Success(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	mockOrchestrator.On("Start", mock.Anything, "container-123").Return(nil)

	err := provider.ContainerStart(context.Background(), "container-123")

	assert.NoError(t, err)
	mockOrchestrator.AssertExpectations(t)
}

func TestMCPContainerStart_OrchestratorNotConfigured(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.ContainerStart(context.Background(), "container-123")

	assert.Error(t, err)
	var containerErr ErrContainerServiceNotAvailable
	assert.True(t, errors.As(err, &containerErr))
}

func TestMCPContainerStart_EmptyID(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	err := provider.ContainerStart(context.Background(), "")

	assert.Error(t, err)
	var paramErr ErrContainerInvalidParameter
	assert.True(t, errors.As(err, &paramErr))
	assert.Equal(t, "id", paramErr.Parameter)
}

func TestMCPContainerStart_OrchestratorError(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	mockOrchestrator.On("Start", mock.Anything, "container-123").Return(errors.New("start error"))

	err := provider.ContainerStart(context.Background(), "container-123")

	assert.Error(t, err)
	var opErr ErrContainerOperationFailed
	assert.True(t, errors.As(err, &opErr))
	assert.Equal(t, "start", opErr.Operation)
	mockOrchestrator.AssertExpectations(t)
}

func TestMCPContainerStop_Success(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	mockOrchestrator.On("Stop", mock.Anything, "container-123").Return(nil)

	err := provider.ContainerStop(context.Background(), "container-123", 30)

	assert.NoError(t, err)
	mockOrchestrator.AssertExpectations(t)
}

func TestMCPContainerStop_OrchestratorNotConfigured(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.ContainerStop(context.Background(), "container-123", 30)

	assert.Error(t, err)
	var containerErr ErrContainerServiceNotAvailable
	assert.True(t, errors.As(err, &containerErr))
}

func TestMCPContainerStop_EmptyID(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	err := provider.ContainerStop(context.Background(), "", 30)

	assert.Error(t, err)
	var paramErr ErrContainerInvalidParameter
	assert.True(t, errors.As(err, &paramErr))
	assert.Equal(t, "id", paramErr.Parameter)
}

func TestMCPContainerRemove_Success(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	mockOrchestrator.On("Delete", mock.Anything, "container-123").Return(nil)

	err := provider.ContainerRemove(context.Background(), "container-123", false)

	assert.NoError(t, err)
	mockOrchestrator.AssertExpectations(t)
}

func TestMCPContainerRemove_OrchestratorNotConfigured(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.ContainerRemove(context.Background(), "container-123", false)

	assert.Error(t, err)
	var containerErr ErrContainerServiceNotAvailable
	assert.True(t, errors.As(err, &containerErr))
}

func TestMCPContainerRemove_EmptyID(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	err := provider.ContainerRemove(context.Background(), "", false)

	assert.Error(t, err)
	var paramErr ErrContainerInvalidParameter
	assert.True(t, errors.As(err, &paramErr))
	assert.Equal(t, "id", paramErr.Parameter)
}

func TestMCPContainerGet_Success(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	expectedInstance := &compute.Instance{
		ID:        "container-123",
		Name:      "test-container",
		Type:      compute.ComputeTypeContainer,
		State:     compute.StateRunning,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockOrchestrator.On("Get", mock.Anything, "container-123").Return(expectedInstance, nil)

	result, err := provider.ContainerGet(context.Background(), "container-123")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	resultMap, ok := result.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "container-123", resultMap["id"])
	assert.Equal(t, "test-container", resultMap["name"])
	mockOrchestrator.AssertExpectations(t)
}

func TestMCPContainerGet_OrchestratorNotConfigured(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	result, err := provider.ContainerGet(context.Background(), "container-123")

	assert.Nil(t, result)
	assert.Error(t, err)
	var containerErr ErrContainerServiceNotAvailable
	assert.True(t, errors.As(err, &containerErr))
}

func TestMCPContainerGet_EmptyID(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	result, err := provider.ContainerGet(context.Background(), "")

	assert.Nil(t, result)
	assert.Error(t, err)
	var paramErr ErrContainerInvalidParameter
	assert.True(t, errors.As(err, &paramErr))
	assert.Equal(t, "id", paramErr.Parameter)
}

func TestMCPContainerGet_NotFound(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	mockOrchestrator.On("Get", mock.Anything, "container-123").Return(nil, errors.New("not found"))

	result, err := provider.ContainerGet(context.Background(), "container-123")

	assert.Nil(t, result)
	assert.Error(t, err)
	var notFoundErr ErrContainerNotFound
	assert.True(t, errors.As(err, &notFoundErr))
	assert.Equal(t, "container-123", notFoundErr.ContainerID)
	mockOrchestrator.AssertExpectations(t)
}

func TestMCPContainerList_Success(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	expectedInstances := []*compute.Instance{
		{
			ID:        "container-1",
			Name:      "container-one",
			Type:      compute.ComputeTypeContainer,
			State:     compute.StateRunning,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:        "container-2",
			Name:      "container-two",
			Type:      compute.ComputeTypeContainer,
			State:     compute.StateRunning,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	mockOrchestrator.On("List", mock.Anything, mock.MatchedBy(func(f *compute.InstanceFilter) bool {
		return f.Type != nil && *f.Type == compute.ComputeTypeContainer
	})).Return(expectedInstances, nil)

	result, err := provider.ContainerList(context.Background(), true, nil, 0)

	assert.NoError(t, err)
	assert.Len(t, result, 2)
	mockOrchestrator.AssertExpectations(t)
}

func TestMCPContainerList_WithLimit(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	expectedInstances := []*compute.Instance{
		{
			ID:        "container-1",
			Name:      "container-one",
			Type:      compute.ComputeTypeContainer,
			State:     compute.StateRunning,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:        "container-2",
			Name:      "container-two",
			Type:      compute.ComputeTypeContainer,
			State:     compute.StateRunning,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:        "container-3",
			Name:      "container-three",
			Type:      compute.ComputeTypeContainer,
			State:     compute.StateRunning,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	mockOrchestrator.On("List", mock.Anything, mock.Anything).Return(expectedInstances, nil)

	result, err := provider.ContainerList(context.Background(), true, nil, 2)

	assert.NoError(t, err)
	assert.Len(t, result, 2)
	mockOrchestrator.AssertExpectations(t)
}

func TestMCPContainerList_OrchestratorNotConfigured(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	result, err := provider.ContainerList(context.Background(), true, nil, 0)

	assert.Nil(t, result)
	assert.Error(t, err)
	var containerErr ErrContainerServiceNotAvailable
	assert.True(t, errors.As(err, &containerErr))
}

func TestMCPContainerList_OrchestratorError(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	mockOrchestrator.On("List", mock.Anything, mock.Anything).Return(nil, errors.New("list error"))

	result, err := provider.ContainerList(context.Background(), true, nil, 0)

	assert.Nil(t, result)
	assert.Error(t, err)
	var opErr ErrContainerOperationFailed
	assert.True(t, errors.As(err, &opErr))
	assert.Equal(t, "list", opErr.Operation)
	mockOrchestrator.AssertExpectations(t)
}

func TestMCPContainerLogs_NotSupported(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	result, err := provider.ContainerLogs(context.Background(), "container-123", false, true, true, "100", false)

	assert.Empty(t, result)
	assert.Error(t, err)
	var logsErr ErrContainerLogsNotSupported
	assert.True(t, errors.As(err, &logsErr))
}

func TestMCPContainerAttest_NotSupported(t *testing.T) {
	mockOrchestrator := new(MockComputeOrchestrator)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		ComputeOrchestrator: mockOrchestrator,
		Logger:              slog.Default(),
	})

	result, err := provider.ContainerAttest(context.Background(), "container-123")

	assert.Nil(t, result)
	assert.Error(t, err)
	var attestErr ErrContainerAttestNotSupported
	assert.True(t, errors.As(err, &attestErr))
}

func TestMCPSetComputeOrchestrator(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Initially no orchestrator
	err := provider.ContainerStart(context.Background(), "container-123")
	assert.Error(t, err)
	var containerErr ErrContainerServiceNotAvailable
	assert.True(t, errors.As(err, &containerErr))

	// Set orchestrator dynamically
	mockOrchestrator := new(MockComputeOrchestrator)
	provider.SetComputeOrchestrator(mockOrchestrator)

	mockOrchestrator.On("Start", mock.Anything, "container-123").Return(nil)

	err = provider.ContainerStart(context.Background(), "container-123")
	assert.NoError(t, err)
	mockOrchestrator.AssertExpectations(t)
}

func TestInstanceToContainerResponse_NilInstance(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	result := provider.instanceToContainerResponse(nil)
	assert.Nil(t, result)
}

func TestInstanceToContainerResponse_WithConfig(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	instance := &compute.Instance{
		ID:        "container-123",
		Name:      "test-container",
		Type:      compute.ComputeTypeContainer,
		State:     compute.StateRunning,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Config: &compute.InstanceConfig{
			Memory: 512,
			CPUs:   2,
		},
	}

	result := provider.instanceToContainerResponse(instance)
	assert.NotNil(t, result)
	assert.Equal(t, 512, result["memory"])
	assert.Equal(t, 2, result["cpus"])
}

func TestInstanceToContainerResponse_WithMetadata(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	instance := &compute.Instance{
		ID:        "container-123",
		Name:      "test-container",
		Type:      compute.ComputeTypeContainer,
		State:     compute.StateRunning,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}

	result := provider.instanceToContainerResponse(instance)
	assert.NotNil(t, result)
	metadata, ok := result["metadata"].(map[string]string)
	assert.True(t, ok)
	assert.Equal(t, "value1", metadata["key1"])
	assert.Equal(t, "value2", metadata["key2"])
}
