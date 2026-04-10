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

package container

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/podman"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPodmanManager implements podman.PodmanManager for testing
type mockPodmanManager struct {
	initializeErr      error
	pullImageErr       error
	listImagesResult   []*podman.Image
	listImagesErr      error
	inspectImageResult *podman.Image
	inspectImageErr    error
	createResult       *podman.Container
	createErr          error
	startErr           error
	stopErr            error
	removeErr          error
	inspectResult      *podman.Container
	inspectErr         error
	listResult         []*podman.Container
	listErr            error
	logsResult         *podman.ContainerLogs
	logsErr            error
	closeErr           error
	initialized        bool
}

func (m *mockPodmanManager) Initialize(ctx context.Context) error {
	if m.initializeErr != nil {
		return m.initializeErr
	}
	m.initialized = true
	return nil
}

func (m *mockPodmanManager) PullImage(ctx context.Context, imageRef string) error {
	return m.pullImageErr
}

func (m *mockPodmanManager) ListImages(ctx context.Context) ([]*podman.Image, error) {
	return m.listImagesResult, m.listImagesErr
}

func (m *mockPodmanManager) InspectImage(ctx context.Context, imageRef string) (*podman.Image, error) {
	return m.inspectImageResult, m.inspectImageErr
}

func (m *mockPodmanManager) RemoveImage(ctx context.Context, imageRef string, force bool) error {
	return nil
}

func (m *mockPodmanManager) CreateContainer(ctx context.Context, config *podman.ContainerConfig) (*podman.Container, error) {
	return m.createResult, m.createErr
}

func (m *mockPodmanManager) StartContainer(ctx context.Context, id string) error {
	return m.startErr
}

func (m *mockPodmanManager) StopContainer(ctx context.Context, id string, timeout *int) error {
	return m.stopErr
}

func (m *mockPodmanManager) RemoveContainer(ctx context.Context, id string, force bool) error {
	return m.removeErr
}

func (m *mockPodmanManager) InspectContainer(ctx context.Context, id string) (*podman.Container, error) {
	return m.inspectResult, m.inspectErr
}

func (m *mockPodmanManager) ListContainers(ctx context.Context, all bool) ([]*podman.Container, error) {
	return m.listResult, m.listErr
}

func (m *mockPodmanManager) WaitContainer(ctx context.Context, id string) (int, error) {
	return 0, nil
}

func (m *mockPodmanManager) GetContainerLogs(ctx context.Context, id string, follow bool, since *time.Time) (*podman.ContainerLogs, error) {
	return m.logsResult, m.logsErr
}

func (m *mockPodmanManager) SetAttestor(attestor podman.ContainerAttestor) {}

func (m *mockPodmanManager) GetAttestor() podman.ContainerAttestor { return nil }

func (m *mockPodmanManager) Close() error {
	return m.closeErr
}

func (m *mockPodmanManager) IsInitialized() bool {
	return m.initialized
}

func TestNewEmbeddedPodmanAdapter(t *testing.T) {
	mock := &mockPodmanManager{}
	adapter := NewEmbeddedPodmanAdapter(mock)

	assert.NotNil(t, adapter)
	assert.Equal(t, mock, adapter.manager)
}

func TestEmbeddedPodmanAdapter_Connect(t *testing.T) {
	tests := []struct {
		name    string
		mock    *mockPodmanManager
		wantErr bool
	}{
		{
			name: "success",
			mock: &mockPodmanManager{},
		},
		{
			name: "error",
			mock: &mockPodmanManager{
				initializeErr: errors.New("init failed"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewEmbeddedPodmanAdapter(tt.mock)
			err := adapter.Connect(context.Background())

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEmbeddedPodmanAdapter_PullImage(t *testing.T) {
	tests := []struct {
		name    string
		mock    *mockPodmanManager
		wantErr bool
	}{
		{
			name: "success",
			mock: &mockPodmanManager{},
		},
		{
			name: "error",
			mock: &mockPodmanManager{
				pullImageErr: errors.New("pull failed"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewEmbeddedPodmanAdapter(tt.mock)
			err := adapter.PullImage(context.Background(), "alpine:latest")

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEmbeddedPodmanAdapter_ListImages(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		mock       *mockPodmanManager
		wantResult []*PodmanImage
		wantErr    bool
	}{
		{
			name: "success with images",
			mock: &mockPodmanManager{
				listImagesResult: []*podman.Image{
					{ID: "img1", Names: []string{"alpine:latest"}, Created: now},
					{ID: "img2", Names: []string{"nginx:latest"}, Created: now},
				},
			},
			wantResult: []*PodmanImage{
				{ID: "img1", Names: []string{"alpine:latest"}, Created: now},
				{ID: "img2", Names: []string{"nginx:latest"}, Created: now},
			},
		},
		{
			name: "success empty",
			mock: &mockPodmanManager{
				listImagesResult: []*podman.Image{},
			},
			wantResult: []*PodmanImage{},
		},
		{
			name: "error",
			mock: &mockPodmanManager{
				listImagesErr: errors.New("list failed"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewEmbeddedPodmanAdapter(tt.mock)
			result, err := adapter.ListImages(context.Background())

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Len(t, result, len(tt.wantResult))
			}
		})
	}
}

func TestEmbeddedPodmanAdapter_InspectImage(t *testing.T) {
	tests := []struct {
		name    string
		mock    *mockPodmanManager
		wantErr bool
	}{
		{
			name: "success",
			mock: &mockPodmanManager{
				inspectImageResult: &podman.Image{ID: "img1", Names: []string{"alpine:latest"}},
			},
		},
		{
			name: "error",
			mock: &mockPodmanManager{
				inspectImageErr: errors.New("inspect failed"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewEmbeddedPodmanAdapter(tt.mock)
			result, err := adapter.InspectImage(context.Background(), "alpine:latest")

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestEmbeddedPodmanAdapter_CreateContainer(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		mock    *mockPodmanManager
		config  *PodmanContainerConfig
		wantErr bool
	}{
		{
			name: "success",
			mock: &mockPodmanManager{
				createResult: &podman.Container{
					ID:        "ctr1",
					Name:      "test-container",
					Image:     "alpine:latest",
					State:     podman.ContainerStateCreated,
					CreatedAt: now,
				},
			},
			config: &PodmanContainerConfig{
				Name:  "test-container",
				Image: "alpine:latest",
			},
		},
		{
			name: "success with all options",
			mock: &mockPodmanManager{
				createResult: &podman.Container{
					ID:    "ctr1",
					Name:  "full-container",
					Image: "alpine:latest",
					State: podman.ContainerStateCreated,
				},
			},
			config: &PodmanContainerConfig{
				Name:        "full-container",
				Image:       "alpine:latest",
				Command:     []string{"/bin/sh"},
				Environment: map[string]string{"FOO": "bar"},
				Labels:      map[string]string{"app": "test"},
				Privileged:  true,
				ReadOnly:    true,
				TPMAccess:   true,
				Mounts: []PodmanMount{
					{Source: "/host", Target: "/container", Type: "bind"},
				},
				Ports: []PodmanPort{
					{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
				},
			},
		},
		{
			name: "error",
			mock: &mockPodmanManager{
				createErr: errors.New("create failed"),
			},
			config: &PodmanContainerConfig{
				Name:  "test-container",
				Image: "alpine:latest",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewEmbeddedPodmanAdapter(tt.mock)
			result, err := adapter.CreateContainer(context.Background(), tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestEmbeddedPodmanAdapter_StartContainer(t *testing.T) {
	tests := []struct {
		name    string
		mock    *mockPodmanManager
		wantErr bool
	}{
		{
			name: "success",
			mock: &mockPodmanManager{},
		},
		{
			name: "error",
			mock: &mockPodmanManager{
				startErr: errors.New("start failed"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewEmbeddedPodmanAdapter(tt.mock)
			err := adapter.StartContainer(context.Background(), "ctr1")

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEmbeddedPodmanAdapter_StopContainer(t *testing.T) {
	timeout := 10
	tests := []struct {
		name    string
		mock    *mockPodmanManager
		timeout *int
		wantErr bool
	}{
		{
			name:    "success with timeout",
			mock:    &mockPodmanManager{},
			timeout: &timeout,
		},
		{
			name: "success without timeout",
			mock: &mockPodmanManager{},
		},
		{
			name: "error",
			mock: &mockPodmanManager{
				stopErr: errors.New("stop failed"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewEmbeddedPodmanAdapter(tt.mock)
			err := adapter.StopContainer(context.Background(), "ctr1", tt.timeout)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEmbeddedPodmanAdapter_RemoveContainer(t *testing.T) {
	tests := []struct {
		name    string
		mock    *mockPodmanManager
		force   bool
		wantErr bool
	}{
		{
			name:  "success",
			mock:  &mockPodmanManager{},
			force: false,
		},
		{
			name:  "success with force",
			mock:  &mockPodmanManager{},
			force: true,
		},
		{
			name: "error",
			mock: &mockPodmanManager{
				removeErr: errors.New("remove failed"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewEmbeddedPodmanAdapter(tt.mock)
			err := adapter.RemoveContainer(context.Background(), "ctr1", tt.force)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEmbeddedPodmanAdapter_InspectContainer(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		mock    *mockPodmanManager
		wantErr bool
	}{
		{
			name: "success",
			mock: &mockPodmanManager{
				inspectResult: &podman.Container{
					ID:        "ctr1",
					Name:      "test-container",
					Image:     "alpine:latest",
					State:     podman.ContainerStateRunning,
					CreatedAt: now,
					StartedAt: &now,
				},
			},
		},
		{
			name: "error",
			mock: &mockPodmanManager{
				inspectErr: errors.New("inspect failed"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewEmbeddedPodmanAdapter(tt.mock)
			result, err := adapter.InspectContainer(context.Background(), "ctr1")

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestEmbeddedPodmanAdapter_ListContainers(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		mock    *mockPodmanManager
		all     bool
		wantLen int
		wantErr bool
	}{
		{
			name: "success with containers",
			mock: &mockPodmanManager{
				listResult: []*podman.Container{
					{ID: "ctr1", Name: "c1", State: podman.ContainerStateRunning, CreatedAt: now},
					{ID: "ctr2", Name: "c2", State: podman.ContainerStateStopped, CreatedAt: now},
				},
			},
			all:     true,
			wantLen: 2,
		},
		{
			name: "success empty",
			mock: &mockPodmanManager{
				listResult: []*podman.Container{},
			},
			wantLen: 0,
		},
		{
			name: "error",
			mock: &mockPodmanManager{
				listErr: errors.New("list failed"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewEmbeddedPodmanAdapter(tt.mock)
			result, err := adapter.ListContainers(context.Background(), tt.all)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Len(t, result, tt.wantLen)
			}
		})
	}
}

func TestEmbeddedPodmanAdapter_GetContainerLogs(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		mock    *mockPodmanManager
		wantErr bool
	}{
		{
			name: "success",
			mock: &mockPodmanManager{
				logsResult: &podman.ContainerLogs{
					ContainerID: "ctr1",
					Stdout:      []byte("stdout logs"),
					Stderr:      []byte("stderr logs"),
					Since:       now,
					Until:       now,
				},
			},
		},
		{
			name: "error",
			mock: &mockPodmanManager{
				logsErr: errors.New("logs failed"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewEmbeddedPodmanAdapter(tt.mock)
			result, err := adapter.GetContainerLogs(context.Background(), "ctr1", false, nil)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestEmbeddedPodmanAdapter_Close(t *testing.T) {
	tests := []struct {
		name    string
		mock    *mockPodmanManager
		wantErr bool
	}{
		{
			name: "success",
			mock: &mockPodmanManager{},
		},
		{
			name: "error",
			mock: &mockPodmanManager{
				closeErr: errors.New("close failed"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewEmbeddedPodmanAdapter(tt.mock)
			err := adapter.Close()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConvertToPodmanImage(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := convertToPodmanImage(nil)
		assert.Nil(t, result)
	})

	t.Run("valid input", func(t *testing.T) {
		now := time.Now()
		img := &podman.Image{
			ID:           "img123",
			Names:        []string{"alpine:latest", "alpine:3.18"},
			Digest:       "sha256:abc123",
			Size:         1024,
			Created:      now,
			Labels:       map[string]string{"foo": "bar"},
			Architecture: "amd64",
			OS:           "linux",
		}

		result := convertToPodmanImage(img)
		require.NotNil(t, result)
		assert.Equal(t, img.ID, result.ID)
		assert.Equal(t, img.Names, result.Names)
		assert.Equal(t, img.Digest, result.Digest)
		assert.Equal(t, img.Size, result.Size)
		assert.Equal(t, img.Created, result.Created)
		assert.Equal(t, img.Labels, result.Labels)
		assert.Equal(t, img.Architecture, result.Architecture)
		assert.Equal(t, img.OS, result.OS)
	})
}

func TestConvertToPodmanContainer(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := convertToPodmanContainer(nil)
		assert.Nil(t, result)
	})

	t.Run("valid input with all fields", func(t *testing.T) {
		now := time.Now()
		c := &podman.Container{
			ID:          "ctr123",
			Name:        "test-container",
			Image:       "alpine:latest",
			ImageDigest: "sha256:xyz",
			State:       podman.ContainerStateRunning,
			CreatedAt:   now,
			StartedAt:   &now,
			FinishedAt:  nil,
			ExitCode:    0,
			Labels:      map[string]string{"app": "test"},
			PID:         1234,
			Command:     []string{"/bin/sh"},
			NetworkMode: "bridge",
		}

		result := convertToPodmanContainer(c)
		require.NotNil(t, result)
		assert.Equal(t, c.ID, result.ID)
		assert.Equal(t, c.Name, result.Name)
		assert.Equal(t, c.Image, result.Image)
		assert.Equal(t, c.ImageDigest, result.ImageDigest)
		assert.Equal(t, string(c.State), result.State)
		assert.Equal(t, c.CreatedAt, result.CreatedAt)
		assert.Equal(t, c.StartedAt, result.StartedAt)
		assert.Nil(t, result.FinishedAt)
		assert.Equal(t, c.ExitCode, result.ExitCode)
		assert.Equal(t, c.Labels, result.Labels)
		assert.Equal(t, c.PID, result.PID)
		assert.Equal(t, c.Command, result.Command)
		assert.Equal(t, c.NetworkMode, result.NetworkMode)
	})
}

func TestConvertFromPodmanContainerConfig(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := convertFromPodmanContainerConfig(nil)
		assert.Nil(t, result)
	})

	t.Run("minimal config", func(t *testing.T) {
		config := &PodmanContainerConfig{
			Name:  "test",
			Image: "alpine:latest",
		}

		result := convertFromPodmanContainerConfig(config)
		require.NotNil(t, result)
		assert.Equal(t, config.Name, result.Name)
		assert.Equal(t, config.Image, result.Image)
		assert.NotNil(t, result.StopTimeout)
		assert.Equal(t, 10, *result.StopTimeout)
	})

	t.Run("full config", func(t *testing.T) {
		timeout := 30
		config := &PodmanContainerConfig{
			Name:        "full-test",
			Image:       "nginx:latest",
			Command:     []string{"/bin/sh", "-c", "echo hello"},
			Environment: map[string]string{"ENV": "test"},
			Labels:      map[string]string{"app": "nginx"},
			NetworkMode: "host",
			User:        "1000:1000",
			WorkDir:     "/app",
			Hostname:    "myhost",
			Privileged:  true,
			ReadOnly:    true,
			StopTimeout: &timeout,
			CapAdd:      []string{"NET_ADMIN"},
			CapDrop:     []string{"MKNOD"},
			TPMAccess:   true,
			Mounts: []PodmanMount{
				{Source: "/src", Target: "/dest", Type: "bind", ReadOnly: true, Options: []string{"ro"}},
			},
			Ports: []PodmanPort{
				{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
			},
		}

		result := convertFromPodmanContainerConfig(config)
		require.NotNil(t, result)
		assert.Equal(t, config.Name, result.Name)
		assert.Equal(t, config.Image, result.Image)
		assert.Equal(t, config.Command, result.Command)
		assert.Equal(t, config.Environment, result.Environment)
		assert.Equal(t, config.Labels, result.Labels)
		assert.Equal(t, config.NetworkMode, result.NetworkMode)
		assert.Equal(t, config.User, result.User)
		assert.Equal(t, config.WorkDir, result.WorkDir)
		assert.Equal(t, config.Hostname, result.Hostname)
		assert.Equal(t, config.Privileged, result.Privileged)
		assert.Equal(t, config.ReadOnly, result.ReadOnly)
		assert.Equal(t, timeout, *result.StopTimeout)
		assert.Equal(t, config.CapAdd, result.CapAdd)
		assert.Equal(t, config.CapDrop, result.CapDrop)
		assert.Equal(t, config.TPMAccess, result.TPMAccess)
		require.Len(t, result.Mounts, 1)
		assert.Equal(t, "/src", result.Mounts[0].Source)
		require.Len(t, result.Ports, 1)
		assert.Equal(t, uint16(8080), result.Ports[0].HostPort)
	})
}

func TestConvertToPodmanContainerLogs(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := convertToPodmanContainerLogs(nil)
		assert.Nil(t, result)
	})

	t.Run("valid input", func(t *testing.T) {
		now := time.Now()
		logs := &podman.ContainerLogs{
			ContainerID: "ctr123",
			Stdout:      []byte("stdout content"),
			Stderr:      []byte("stderr content"),
			Since:       now.Add(-time.Hour),
			Until:       now,
		}

		result := convertToPodmanContainerLogs(logs)
		require.NotNil(t, result)
		assert.Equal(t, logs.ContainerID, result.ContainerID)
		assert.Equal(t, logs.Stdout, result.Stdout)
		assert.Equal(t, logs.Stderr, result.Stderr)
		assert.Equal(t, logs.Since, result.Since)
		assert.Equal(t, logs.Until, result.Until)
	})
}

func TestEmbeddedPodmanAdapter_ImplementsInterface(t *testing.T) {
	// Compile-time check that EmbeddedPodmanAdapter implements PodmanBackend
	var _ PodmanBackend = (*EmbeddedPodmanAdapter)(nil)
}
