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

package podman

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPodmanManager(t *testing.T) {
	tests := []struct {
		name      string
		config    *ManagerConfig
		opts      []ManagerOption
		expectErr bool
	}{
		{
			name:      "valid config",
			config:    DefaultManagerConfig(),
			expectErr: false,
		},
		{
			name:      "valid config with logger option",
			config:    DefaultManagerConfig(),
			opts:      []ManagerOption{WithManagerLogger(slog.Default())},
			expectErr: false,
		},
		{
			name:      "nil config uses defaults",
			config:    nil,
			expectErr: false,
		},
		{
			name: "invalid config - nil runtime",
			config: &ManagerConfig{
				Runtime:            nil,
				MaxContainers:      100,
				DefaultStopTimeout: DefaultStopTimeout,
			},
			expectErr: true,
		},
		{
			name: "invalid config - zero max containers",
			config: &ManagerConfig{
				Runtime:            DefaultRuntimeConfig(),
				MaxContainers:      0,
				DefaultStopTimeout: DefaultStopTimeout,
			},
			expectErr: true,
		},
		{
			name: "invalid config - negative stop timeout",
			config: &ManagerConfig{
				Runtime:            DefaultRuntimeConfig(),
				MaxContainers:      100,
				DefaultStopTimeout: -1,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewPodmanManager(tt.config, tt.opts...)
			if tt.expectErr {
				require.Error(t, err)
				assert.Nil(t, manager)
			} else {
				require.NoError(t, err)
				require.NotNil(t, manager)
			}
		})
	}
}

func TestPodmanManager_Close(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)

	// Close should succeed
	err = manager.Close()
	assert.NoError(t, err)

	// Double close should also succeed
	err = manager.Close()
	assert.NoError(t, err)
}

func TestPodmanManager_NotInitialized(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	ctx := context.Background()

	// All operations should fail when not initialized
	t.Run("PullImage", func(t *testing.T) {
		err := manager.PullImage(ctx, "alpine:latest")
		assert.ErrorIs(t, err, ErrClientNotConnected)
	})

	t.Run("ListImages", func(t *testing.T) {
		_, err := manager.ListImages(ctx)
		assert.ErrorIs(t, err, ErrClientNotConnected)
	})

	t.Run("InspectImage", func(t *testing.T) {
		_, err := manager.InspectImage(ctx, "alpine:latest")
		assert.ErrorIs(t, err, ErrClientNotConnected)
	})

	t.Run("RemoveImage", func(t *testing.T) {
		err := manager.RemoveImage(ctx, "alpine:latest", false)
		assert.ErrorIs(t, err, ErrClientNotConnected)
	})

	t.Run("CreateContainer", func(t *testing.T) {
		_, err := manager.CreateContainer(ctx, &ContainerConfig{
			Name:  "test",
			Image: "alpine",
		})
		assert.ErrorIs(t, err, ErrClientNotConnected)
	})

	t.Run("StartContainer", func(t *testing.T) {
		err := manager.StartContainer(ctx, "abc123")
		assert.ErrorIs(t, err, ErrClientNotConnected)
	})

	t.Run("StopContainer", func(t *testing.T) {
		err := manager.StopContainer(ctx, "abc123", nil)
		assert.ErrorIs(t, err, ErrClientNotConnected)
	})

	t.Run("RemoveContainer", func(t *testing.T) {
		err := manager.RemoveContainer(ctx, "abc123", false)
		assert.ErrorIs(t, err, ErrClientNotConnected)
	})

	t.Run("InspectContainer", func(t *testing.T) {
		_, err := manager.InspectContainer(ctx, "abc123")
		assert.ErrorIs(t, err, ErrClientNotConnected)
	})

	t.Run("ListContainers", func(t *testing.T) {
		_, err := manager.ListContainers(ctx, false)
		assert.ErrorIs(t, err, ErrClientNotConnected)
	})

	t.Run("WaitContainer", func(t *testing.T) {
		_, err := manager.WaitContainer(ctx, "abc123")
		assert.ErrorIs(t, err, ErrClientNotConnected)
	})

	t.Run("GetContainerLogs", func(t *testing.T) {
		_, err := manager.GetContainerLogs(ctx, "abc123", false, nil)
		assert.ErrorIs(t, err, ErrClientNotConnected)
	})
}

func TestPodmanManager_EmptyIDs(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	// Cast to internal type to set initialized state
	pm := manager.(*podmanManager)
	pm.initialized.Store(true)

	ctx := context.Background()

	t.Run("PullImage empty", func(t *testing.T) {
		err := manager.PullImage(ctx, "")
		assert.Error(t, err)
	})

	t.Run("InspectImage empty", func(t *testing.T) {
		_, err := manager.InspectImage(ctx, "")
		assert.Error(t, err)
	})

	t.Run("StartContainer empty", func(t *testing.T) {
		err := manager.StartContainer(ctx, "")
		assert.Error(t, err)
	})

	t.Run("StopContainer empty", func(t *testing.T) {
		err := manager.StopContainer(ctx, "", nil)
		assert.Error(t, err)
	})

	t.Run("RemoveContainer empty", func(t *testing.T) {
		err := manager.RemoveContainer(ctx, "", false)
		assert.Error(t, err)
	})

	t.Run("InspectContainer empty", func(t *testing.T) {
		_, err := manager.InspectContainer(ctx, "")
		assert.Error(t, err)
	})

	t.Run("WaitContainer empty", func(t *testing.T) {
		_, err := manager.WaitContainer(ctx, "")
		assert.Error(t, err)
	})

	t.Run("GetContainerLogs empty", func(t *testing.T) {
		_, err := manager.GetContainerLogs(ctx, "", false, nil)
		assert.Error(t, err)
	})
}

func TestPodmanManager_CreateContainer_NilConfig(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	pm := manager.(*podmanManager)
	pm.initialized.Store(true)

	ctx := context.Background()
	_, err = manager.CreateContainer(ctx, nil)
	assert.ErrorIs(t, err, ErrInvalidContainerConfig)
}

func TestPodmanManager_CreateContainer_InvalidConfig(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("cleanup: failed to close manager: %v", err)
		}
	})

	pm := manager.(*podmanManager)
	pm.initialized.Store(true)

	ctx := context.Background()

	// Missing name
	_, err = manager.CreateContainer(ctx, &ContainerConfig{
		Image: "alpine",
	})
	assert.Error(t, err)

	// Missing image
	_, err = manager.CreateContainer(ctx, &ContainerConfig{
		Name: "test",
	})
	assert.Error(t, err)
}

func TestPodmanManager_ConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    *ManagerConfig
		expectErr bool
	}{
		{
			name:      "valid config",
			config:    DefaultManagerConfig(),
			expectErr: false,
		},
		{
			name: "invalid - nil runtime",
			config: &ManagerConfig{
				Runtime:            nil,
				MaxContainers:      100,
				DefaultStopTimeout: DefaultStopTimeout,
			},
			expectErr: true,
		},
		{
			name: "invalid - zero max containers",
			config: &ManagerConfig{
				Runtime:            DefaultRuntimeConfig(),
				MaxContainers:      0,
				DefaultStopTimeout: DefaultStopTimeout,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPodmanManager(tt.config)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPodmanManagerInterface(t *testing.T) {
	// Verify podmanManager implements PodmanManager interface
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)

	var _ = manager
}

func TestPodmanManager_ContainerCount(t *testing.T) {
	config := DefaultManagerConfig()
	config.MaxContainers = 2 // Set low limit for testing

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("cleanup: failed to close manager: %v", err)
		}
	})

	pm := manager.(*podmanManager)

	// Initial count should be 0
	assert.Equal(t, int64(0), pm.containerCount.Load())
}

func TestPodmanManager_CloseClearsContainers(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)

	pm := manager.(*podmanManager)

	// Add some items to containers map
	pm.containers.Store("test1", &Container{ID: "test1"})
	pm.containers.Store("test2", &Container{ID: "test2"})
	pm.containerCount.Store(2)

	// Close should clear everything
	err = manager.Close()
	assert.NoError(t, err)

	// Verify containers are cleared
	assert.Equal(t, int64(0), pm.containerCount.Load())

	count := 0
	pm.containers.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	assert.Equal(t, 0, count)
}

func TestManagerOption_WithManagerLogger(t *testing.T) {
	config := DefaultManagerConfig()
	logger := slog.Default()

	manager, err := NewPodmanManager(config, WithManagerLogger(logger))
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("cleanup: failed to close manager: %v", err)
		}
	})

	pm := manager.(*podmanManager)
	assert.Equal(t, logger, pm.logger)
}

func TestManagerOption_WithAttestor(t *testing.T) {
	config := DefaultManagerConfig()
	attestor := &testAttestor{}

	manager, err := NewPodmanManager(config, WithAttestor(attestor))
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("cleanup: failed to close manager: %v", err)
		}
	})

	assert.Equal(t, attestor, manager.GetAttestor())
}

func TestPodmanManager_SetAttestor(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("cleanup: failed to close manager: %v", err)
		}
	})

	// Initially no attestor
	assert.Nil(t, manager.GetAttestor())

	// Set attestor
	attestor := &testAttestor{}
	manager.SetAttestor(attestor)

	assert.Equal(t, attestor, manager.GetAttestor())
}

func TestPodmanManager_IsInitialized(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("cleanup: failed to close manager: %v", err)
		}
	})

	// Initially not initialized
	assert.False(t, manager.IsInitialized())

	// Manually set initialized
	pm := manager.(*podmanManager)
	pm.initialized.Store(true)

	assert.True(t, manager.IsInitialized())
}

func TestPodmanManager_StopContainer_WithTimeout(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("cleanup: failed to close manager: %v", err)
		}
	})

	ctx := context.Background()
	timeout := 30

	// Not initialized - should return error
	err = manager.StopContainer(ctx, "nonexistent", &timeout)
	assert.ErrorIs(t, err, ErrClientNotConnected)
}

func TestPodmanManager_GetContainerLogs_WithSince(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("cleanup: failed to close manager: %v", err)
		}
	})

	ctx := context.Background()
	since := time.Now().Add(-1 * time.Hour)

	// Not initialized - should return error
	_, err = manager.GetContainerLogs(ctx, "testcontainer", false, &since)
	assert.ErrorIs(t, err, ErrClientNotConnected)
}

func TestPodmanManager_CreateContainer_MaxContainersReached(t *testing.T) {
	config := DefaultManagerConfig()
	config.MaxContainers = 1

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("cleanup: failed to close manager: %v", err)
		}
	})

	pm := manager.(*podmanManager)
	pm.initialized.Store(true)
	pm.containerCount.Store(1) // Already at max

	ctx := context.Background()
	_, err = manager.CreateContainer(ctx, &ContainerConfig{
		Name:  "test",
		Image: "alpine",
	})
	assert.Error(t, err)
}

func TestDefaultManagerConfig(t *testing.T) {
	config := DefaultManagerConfig()

	require.NotNil(t, config)
	require.NotNil(t, config.Runtime)
	assert.Equal(t, 100, config.MaxContainers)
	assert.Equal(t, DefaultStopTimeout, config.DefaultStopTimeout)
	assert.False(t, config.EnableTPMAccess)
	assert.False(t, config.Debug)
}

func TestManagerConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    *ManagerConfig
		expectErr bool
		errField  string
	}{
		{
			name:      "valid config",
			config:    DefaultManagerConfig(),
			expectErr: false,
		},
		{
			name: "nil runtime",
			config: &ManagerConfig{
				Runtime:            nil,
				MaxContainers:      100,
				DefaultStopTimeout: DefaultStopTimeout,
			},
			expectErr: true,
			errField:  "runtime",
		},
		{
			name: "zero max containers",
			config: &ManagerConfig{
				Runtime:            DefaultRuntimeConfig(),
				MaxContainers:      0,
				DefaultStopTimeout: DefaultStopTimeout,
			},
			expectErr: true,
			errField:  "max_containers",
		},
		{
			name: "negative stop timeout",
			config: &ManagerConfig{
				Runtime:            DefaultRuntimeConfig(),
				MaxContainers:      100,
				DefaultStopTimeout: -1,
			},
			expectErr: true,
			errField:  "stop_timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectErr {
				require.Error(t, err)
				if tt.errField != "" {
					assert.Contains(t, err.Error(), tt.errField)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMapContainerState(t *testing.T) {
	now := time.Now()
	started := now.Add(-1 * time.Hour)
	finished := now

	config := &ContainerConfig{
		Name:        "test-container",
		Image:       "alpine:latest",
		Command:     []string{"sleep", "infinity"},
		Environment: map[string]string{"FOO": "bar"},
		Labels:      map[string]string{"app": "test"},
		NetworkMode: "bridge",
		Mounts: []Mount{
			{Source: "/host", Target: "/container", Type: "bind"},
		},
		Ports: []PortMapping{
			{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		},
	}

	state := &containerState{
		ID:         "abc123",
		Name:       "test-container",
		Image:      "alpine:latest",
		State:      ContainerStateRunning,
		CreatedAt:  now,
		StartedAt:  &started,
		FinishedAt: &finished,
		PID:        12345,
		ExitCode:   0,
		Config:     config,
	}

	container := mapContainerState(state)

	assert.Equal(t, "abc123", container.ID)
	assert.Equal(t, "test-container", container.Name)
	assert.Equal(t, "alpine:latest", container.Image)
	assert.Equal(t, ContainerStateRunning, container.State)
	assert.Equal(t, 12345, container.PID)
	assert.Equal(t, 0, container.ExitCode)
	assert.NotNil(t, container.StartedAt)
	assert.NotNil(t, container.FinishedAt)
	assert.Equal(t, "bar", container.Environment["FOO"])
	assert.Equal(t, "test", container.Labels["app"])
	assert.Len(t, container.Command, 2)
	assert.Len(t, container.Mounts, 1)
	assert.Len(t, container.Ports, 1)
	assert.Equal(t, "bridge", container.NetworkMode)
}

func TestMapContainerState_NilOptionalFields(t *testing.T) {
	state := &containerState{
		ID:        "abc123",
		Name:      "test",
		Image:     "alpine",
		State:     ContainerStateCreated,
		CreatedAt: time.Now(),
		// StartedAt and FinishedAt are nil
		// Config is nil
	}

	container := mapContainerState(state)

	assert.Equal(t, "abc123", container.ID)
	assert.Nil(t, container.StartedAt)
	assert.Nil(t, container.FinishedAt)
	assert.Nil(t, container.Labels)
	assert.Nil(t, container.Mounts)
	assert.Nil(t, container.Ports)
	assert.Nil(t, container.Environment)
	assert.Nil(t, container.Command)
}

func TestPodmanManager_Connect_Alias(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("cleanup: failed to close manager: %v", err)
		}
	})

	pm := manager.(*podmanManager)

	// Connect is an alias for Initialize
	// It should fail because runtime initialization requires system resources
	ctx := context.Background()
	err = pm.Connect(ctx)
	// Error is expected because we don't have the OCI runtime installed in test
	assert.Error(t, err)
}

func TestPodmanManager_ListImages_NotInitialized(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("cleanup: failed to close manager: %v", err)
		}
	})

	ctx := context.Background()

	// Not initialized - should return error
	_, err = manager.ListImages(ctx)
	assert.ErrorIs(t, err, ErrClientNotConnected)
}

func TestPodmanManager_InspectImage_NotInitialized(t *testing.T) {
	config := DefaultManagerConfig()

	manager, err := NewPodmanManager(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("cleanup: failed to close manager: %v", err)
		}
	})

	ctx := context.Background()

	// Not initialized - should return error
	_, err = manager.InspectImage(ctx, "alpine:latest")
	assert.ErrorIs(t, err, ErrClientNotConnected)
}

// testAttestor is a mock attestor for testing
type testAttestor struct {
	startCalled bool
	stopCalled  bool
}

func (a *testAttestor) OnContainerStart(ctx context.Context, container *Container) error {
	a.startCalled = true
	return nil
}

func (a *testAttestor) OnContainerStop(ctx context.Context, container *Container) error {
	a.stopCalled = true
	return nil
}

func (a *testAttestor) GetContainerQuote(ctx context.Context, containerID string, nonce []byte) (*ContainerQuote, error) {
	return &ContainerQuote{
		ContainerID: containerID,
		Nonce:       nonce,
	}, nil
}

func (a *testAttestor) GetMeasurementLog(ctx context.Context, containerID string) ([]*ContainerMeasurement, error) {
	return []*ContainerMeasurement{}, nil
}

func (a *testAttestor) VerifyQuote(ctx context.Context, quote *ContainerQuote, expectedPCR []byte) error {
	return nil
}
